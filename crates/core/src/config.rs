// crates/core/src/config.rs

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub data_dir: PathBuf,
    pub device_name: String, // Now stores the 16-character hex peer ID
    pub auto_accept_channels: bool,
    pub max_peers: usize,
    pub scan_interval_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| {
                // Windows fallback to AppData\Roaming
                std::env::var("APPDATA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."))
            })
            .join("BitChat");
            
        Self {
            data_dir,
            // Generate compatible 16-character hex peer ID
            device_name: generate_compatible_peer_id(),
            auto_accept_channels: false,
            max_peers: 10,
            scan_interval_ms: 5000,
        }
    }
}

impl Config {
    /// Create config with deterministic peer ID from system info
    pub fn with_deterministic_peer_id() -> Self {
        let mut config = Self::default();
        
        // Generate deterministic peer ID from system-specific info
        let system_info = format!(
            "{}|{}|{}",
            std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "unknown".to_string()),
            std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "user".to_string()),
            config.data_dir.to_string_lossy()
        );
        
        config.device_name = peer_id_from_device_info(&system_info);
        config
    }
    
    /// Get peer ID as bytes for internal use
    pub fn get_peer_id_bytes(&self) -> [u8; 8] {
        peer_id_string_to_bytes(&self.device_name)
            .unwrap_or_else(|_| {
                tracing::warn!("Invalid peer ID in config: {}, generating new one", self.device_name);
                peer_id_string_to_bytes(&generate_compatible_peer_id()).unwrap()
            })
    }
    
    /// Get peer ID as string for compatibility
    pub fn get_peer_id_string(&self) -> &str {
        &self.device_name
    }
    
    /// Update peer ID (useful for testing or manual override)
    pub fn set_peer_id(&mut self, peer_id: &str) -> Result<(), String> {
        if is_valid_peer_id_string(peer_id) {
            self.device_name = peer_id.to_uppercase();
            Ok(())
        } else {
            Err(format!("Invalid peer ID format: {}", peer_id))
        }
    }
}

// Helper functions for peer ID management
fn generate_compatible_peer_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes).to_uppercase()
}

fn peer_id_from_device_info(device_info: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    device_info.hash(&mut hasher);
    let hash = hasher.finish();
    
    let mut peer_bytes = [0u8; 8];
    peer_bytes.copy_from_slice(&hash.to_be_bytes());
    hex::encode(peer_bytes).to_uppercase()
}

fn is_valid_peer_id_string(peer_id: &str) -> bool {
    peer_id.len() == 16 && 
    peer_id.chars().all(|c| c.is_ascii_hexdigit())
}

fn peer_id_string_to_bytes(peer_id: &str) -> Result<[u8; 8], String> {
    if !is_valid_peer_id_string(peer_id) {
        return Err(format!("Invalid peer ID format: {}", peer_id));
    }
    
    let decoded = hex::decode(peer_id)
        .map_err(|e| format!("Failed to decode peer ID: {}", e))?;
    
    if decoded.len() != 8 {
        return Err(format!("Peer ID must be 8 bytes, got {}", decoded.len()));
    }
    
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&decoded);
    Ok(bytes)
}