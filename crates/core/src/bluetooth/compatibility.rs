// ==============================================================================
// crates/core/src/bluetooth/compatibility.rs
// ==============================================================================

//! Compatibility layer for connecting Rust devices to existing iOS/Android mesh
//! 
//! This module implements connection arbitration logic that prevents dual role conflicts
//! by ensuring deterministic connection behavior compatible with iOS/Android implementations.

use crate::bluetooth::constants::peer_id;
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, warn};

/// Compatibility manager that makes Rust devices work with existing iOS/Android implementations
#[derive(Clone)]
pub struct CompatibilityManager {
    my_peer_id: String, // 8-character hex string (iOS/Android format)
    connections_in_progress: Arc<RwLock<HashSet<String>>>,
    connection_attempts: Arc<RwLock<HashMap<String, ConnectionAttempt>>>,
    discovered_devices: Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
}

#[derive(Clone)]
struct ConnectionAttempt {
    started_at: Instant,
    retry_count: u32,
}

#[derive(Clone)]
struct DiscoveredDevice {
    peer_id: String,
    device_id: String,
    rssi: i8,
    last_seen: Instant,
}

impl CompatibilityManager {
    /// Create new compatibility manager with iOS/Android compatible peer ID
    pub fn new(my_peer_id: String) -> Self {
        // Ensure peer ID is in correct format
        let formatted_peer_id = if peer_id::is_valid_peer_id_string(&my_peer_id) {
            my_peer_id.to_uppercase()
        } else {
            warn!("Invalid peer ID format '{}', generating new one", my_peer_id);
            peer_id::generate_random_peer_id()
        };
        
        info!("Initializing iOS/Android compatibility manager with peer ID: {}", formatted_peer_id);
        
        Self {
            my_peer_id: formatted_peer_id,
            connections_in_progress: Arc::new(RwLock::new(HashSet::new())),
            connection_attempts: Arc::new(RwLock::new(HashMap::new())),
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Create compatibility manager from device info (deterministic)
    pub fn from_device_info(device_info: &str) -> Self {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        device_info.hash(&mut hasher);
        let hash = hasher.finish();
        
        let mut peer_bytes = [0u8; 8];
        peer_bytes.copy_from_slice(&hash.to_be_bytes());
        let peer_id = peer_id::bytes_to_string(&peer_bytes);
        
        Self::new(peer_id)
    }
    
    /// Determine if we should connect to this peer based on peer ID comparison
    /// This is the key to avoiding dual role conflicts with iOS/Android
    pub fn should_initiate_connection(&self, remote_peer_id: &str) -> bool {
        let should_connect = self.my_peer_id.as_str() < remote_peer_id;
        debug!("Connection decision: {} {} {} = {}", 
               self.my_peer_id, 
               if should_connect { "<" } else { ">=" },
               remote_peer_id,
               should_connect);
        should_connect
    }
    
    /// Process discovered device and decide whether to connect
    pub async fn handle_discovered_device(
        &self,
        device_id: String,
        device_name: Option<String>,
        rssi: i8,
        current_connections: usize,
        max_connections: usize,
    ) -> Option<String> {
        // Extract peer ID from device name (8-character format used by iOS/Android)
        let peer_id = match device_name.as_ref().and_then(|name| {
            extract_peer_id_from_device_name(name)
        }) {
            Some(id) => id,
            None => {
                debug!("No valid peer ID found in device name: {:?}", device_name);
                return None;
            }
        };
        
        info!("Discovered peer: {}, RSSI: {}, Device: {}", peer_id, rssi, device_id);
        
        // Don't connect to ourselves
        if peer_id == self.my_peer_id {
            debug!("Ignoring our own advertisement: {}", peer_id);
            return None;
        }
        
        // Store discovered device info
        {
            let mut discovered = self.discovered_devices.write().await;
            discovered.insert(device_id.clone(), DiscoveredDevice {
                peer_id: peer_id.clone(),
                device_id: device_id.clone(),
                rssi,
                last_seen: Instant::now(),
            });
        }
        
        // Check if we should initiate connection based on peer ID comparison
        if !self.should_initiate_connection(&peer_id) {
            info!("Not my role to connect to {} - they should connect to me", peer_id);
            return None;
        }
        
        // Check connection limiting
        if current_connections >= max_connections {
            info!("Connection limit reached ({}/{})", current_connections, max_connections);
            return None;
        }
        
        // Check signal strength (same threshold as iOS/Android implementation)
        if rssi < -85 {
            info!("Signal too weak for {}: {} dBm", peer_id, rssi);
            return None;
        }
        
        // Check if connection is already in progress
        if self.is_connection_in_progress(&peer_id).await {
            info!("Connection to {} already in progress", peer_id);
            return None;
        }
        
        // Check retry limits
        if !self.should_retry_connection(&peer_id).await {
            debug!("Retry limit reached for {}", peer_id);
            return None;
        }
        
        // Mark connection attempt
        self.mark_connection_in_progress(&peer_id).await;
        
        Some(peer_id)
    }
    
    /// Check if connection attempt is in progress
    async fn is_connection_in_progress(&self, peer_id: &str) -> bool {
        let connections = self.connections_in_progress.read().await;
        let attempts = self.connection_attempts.read().await;
        
        if !connections.contains(peer_id) {
            return false;
        }
        
        // Check if attempt has timed out (10 second timeout)
        if let Some(attempt) = attempts.get(peer_id) {
            if attempt.started_at.elapsed() > Duration::from_secs(10) {
                // Clean up expired attempt
                drop(connections);
                drop(attempts);
                self.cleanup_expired_connection(peer_id).await;
                return false;
            }
        }
        
        true
    }
    
    /// Mark connection as in progress
    async fn mark_connection_in_progress(&self, peer_id: &str) {
        let mut connections = self.connections_in_progress.write().await;
        let mut attempts = self.connection_attempts.write().await;
        
        connections.insert(peer_id.to_string());
        
        let attempt = ConnectionAttempt {
            started_at: Instant::now(),
            retry_count: attempts.get(peer_id)
                .map(|a| a.retry_count + 1)
                .unwrap_or(1),
        };
        
        attempts.insert(peer_id.to_string(), attempt.clone());
        info!("Marked connection to {} as in progress (attempt {})", peer_id, attempt.retry_count);
    }
    
    /// Mark connection as complete (success or failure)
    pub async fn mark_connection_complete(&self, peer_id: &str) {
        let mut connections = self.connections_in_progress.write().await;
        connections.remove(peer_id);
        info!("Marked connection to {} as complete", peer_id);
        // Keep attempt record for retry logic
    }
    
    /// Clean up expired connection attempt
    async fn cleanup_expired_connection(&self, peer_id: &str) {
        let mut connections = self.connections_in_progress.write().await;
        connections.remove(peer_id);
        warn!("Cleaned up expired connection attempt to {}", peer_id);
    }
    
    /// Create advertisement name compatible with iOS/Android
    pub fn create_advertisement_name(&self) -> String {
        format!("BC_{}", self.my_peer_id)
    }
    
    /// Determine if we should retry connection
    pub async fn should_retry_connection(&self, peer_id: &str) -> bool {
        let attempts = self.connection_attempts.read().await;
        
        if let Some(attempt) = attempts.get(peer_id) {
            // Max 3 retries, exponential backoff
            let max_retries = 3;
            let backoff_duration = Duration::from_secs(2_u64.pow(attempt.retry_count.saturating_sub(1)));
            
            attempt.retry_count <= max_retries && 
            attempt.started_at.elapsed() > backoff_duration
        } else {
            true
        }
    }
    
    /// Get retry delay for a peer
    pub async fn get_retry_delay(&self, peer_id: &str) -> Duration {
        let attempts = self.connection_attempts.read().await;
        
        if let Some(attempt) = attempts.get(peer_id) {
            Duration::from_secs(2_u64.pow(attempt.retry_count.saturating_sub(1)))
        } else {
            Duration::from_secs(1)
        }
    }
    
    /// Clean up old discovered devices (30 second timeout)
    pub async fn cleanup_old_discoveries(&self) {
        let mut discovered = self.discovered_devices.write().await;
        let cutoff = Instant::now() - Duration::from_secs(30);
        
        let before_count = discovered.len();
        discovered.retain(|_, device| device.last_seen > cutoff);
        let after_count = discovered.len();
        
        if before_count != after_count {
            debug!("Cleaned up {} old discovered devices", before_count - after_count);
        }
    }
    
    /// Get connection debug info
    pub async fn get_debug_info(&self) -> String {
        let connections = self.connections_in_progress.read().await;
        let attempts = self.connection_attempts.read().await;
        let discovered = self.discovered_devices.read().await;
        
        let mut info = format!(
            "iOS/Android Compatibility Manager:\n\
             ===================================\n\
             My Peer ID: {} (8-char hex format)\n\
             Connections in Progress: {}\n\
             Total Attempts: {}\n\
             Discovered Devices: {}\n\
             Connection Rule: Lower peer ID connects to higher\n\
             Advertisement Name: {}\n\n",
            self.my_peer_id,
            connections.len(),
            attempts.len(),
            discovered.len(),
            self.create_advertisement_name()
        );
        
        if !connections.is_empty() {
            info.push_str("Connections in Progress:\n");
            for peer_id in connections.iter() {
                if let Some(attempt) = attempts.get(peer_id) {
                    info.push_str(&format!("  - {}: attempt {}, {}s ago\n", 
                                         peer_id, 
                                         attempt.retry_count,
                                         attempt.started_at.elapsed().as_secs()));
                }
            }
            info.push('\n');
        }
        
        if !discovered.is_empty() {
            info.push_str("Recently Discovered:\n");
            for (device_id, device) in discovered.iter() {
                let will_connect = self.should_initiate_connection(&device.peer_id);
                info.push_str(&format!("  - {}: {} (RSSI: {} dBm, {}s ago) {}\n",
                                     device.peer_id,
                                     device_id,
                                     device.rssi,
                                     device.last_seen.elapsed().as_secs(),
                                     if will_connect { "[WILL CONNECT]" } else { "[WAIT FOR THEM]" }));
            }
        }
        
        info
    }
    
    /// Get the peer ID
    pub fn get_peer_id(&self) -> &str {
        &self.my_peer_id
    }
    
    /// Get discovered peers list
    pub async fn get_discovered_peers(&self) -> Vec<(String, i8, Duration)> {
        let discovered = self.discovered_devices.read().await;
        discovered.values()
            .map(|device| (device.peer_id.clone(), device.rssi, device.last_seen.elapsed()))
            .collect()
    }
}

/// Extract peer ID from device name
fn extract_peer_id_from_device_name(device_name: &str) -> Option<String> {
    // Check for BitChat format: "BC_ABCD1234" 
    if device_name.starts_with("BC_") && device_name.len() == 19 { // BC_ + 16 hex chars
        let peer_id = &device_name[3..];
        if peer_id::is_valid_peer_id_string(peer_id) {
            return Some(peer_id.to_uppercase());
        }
    }
    None
}