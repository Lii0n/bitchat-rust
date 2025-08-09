// ==============================================================================
// crates/core/src/network/udp.rs - UDP Broadcast Bridge Implementation
// ==============================================================================

//! UDP broadcast bridge for BitChat local network discovery
//! 
//! This module implements local network peer discovery using UDP broadcasts,
//! providing a fallback when BLE and Nostr are unavailable.

use anyhow::Result;
use async_trait::async_trait;
use base64::prelude::*;
use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket as StdUdpSocket};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::network::bridge::{NetworkBridge, BridgeConfig, BridgeStats};
use crate::network::discovery::{DiscoveryMethod, PeerAnnouncement};

/// UDP broadcast bridge for local network discovery
pub struct UdpBridge {
    peer_id: String,
    port: u16,
    config: BridgeConfig,
    socket: Option<Arc<UdpSocket>>,
    is_active: Arc<RwLock<bool>>,
    stats: Arc<RwLock<BridgeStats>>,
}

impl UdpBridge {
    /// Create new UDP broadcast bridge
    pub fn new(peer_id: String, port: u16, config: BridgeConfig) -> Self {
        let mut stats = BridgeStats::default();
        stats.name = format!("udp-bridge-{}", port);
        
        Self {
            peer_id,
            port,
            config,
            socket: None,
            is_active: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(stats)),
        }
    }
    
    /// Start UDP broadcast listener and announcer
    async fn start_udp_tasks(&mut self) -> Result<()> {
        let bind_addr = format!("0.0.0.0:{}", self.port);
        let socket = UdpSocket::bind(&bind_addr).await?;
        socket.set_broadcast(true)?;
        
        info!("📡 UDP socket bound to: {}", bind_addr);
        
        let socket = Arc::new(socket);
        self.socket = Some(socket.clone());
        
        // Task 1: Broadcast announcements
        let peer_id = self.peer_id.clone();
        let port = self.port;
        let broadcast_socket = socket.clone();
        let is_active = Arc::clone(&self.is_active);
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            let mut announce_interval = interval(Duration::from_secs(15));
            let broadcast_addr: SocketAddr = format!("255.255.255.255:{}", port).parse().unwrap();
            
            loop {
                announce_interval.tick().await;
                
                if !*is_active.read().await {
                    break;
                }
                
                let announcement = PeerAnnouncement::new(
                    peer_id.clone(),
                    format!("BitChat-{}", &peer_id[..8]),
                    format!("udp://{}:{}", local_ip().unwrap_or("127.0.0.1".to_string()), port),
                );
                
                match announcement.to_json() {
                    Ok(json) => {
                        let message = format!("BITCHAT_ANNOUNCE:{}", json);
                        
                        if let Err(e) = broadcast_socket.send_to(message.as_bytes(), broadcast_addr).await {
                            warn!("Failed to send UDP broadcast: {}", e);
                        } else {
                            debug!("📡 Sent UDP announcement for peer: {}", peer_id);
                            let mut stats_guard = stats.write().await;
                            stats_guard.messages_sent += 1;
                            stats_guard.last_activity = Some(chrono::Utc::now());
                        }
                    }
                    Err(e) => {
                        warn!("Failed to serialize announcement: {}", e);
                    }
                }
            }
        });
        
        // Task 2: Listen for announcements
        let listen_socket = socket.clone();
        let our_peer_id = self.peer_id.clone();
        let is_active = Arc::clone(&self.is_active);
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            
            loop {
                if !*is_active.read().await {
                    break;
                }
                
                match listen_socket.recv_from(&mut buffer).await {
                    Ok((size, sender)) => {
                        let message = String::from_utf8_lossy(&buffer[..size]);
                        
                        if let Some(announcement_json) = message.strip_prefix("BITCHAT_ANNOUNCE:") {
                            match PeerAnnouncement::from_json(announcement_json) {
                                Ok(announcement) => {
                                    if announcement.peer_id != our_peer_id && announcement.is_recent(10) {
                                        info!("📥 Discovered UDP peer: {} from {}", announcement.peer_id, sender);
                                        
                                        let mut stats_guard = stats.write().await;
                                        stats_guard.messages_received += 1;
                                        stats_guard.last_activity = Some(chrono::Utc::now());
                                        
                                        // Would notify discovery system here
                                    }
                                }
                                Err(e) => {
                                    debug!("Invalid announcement JSON: {}", e);
                                }
                            }
                        } else if message.starts_with("BITCHAT_MESSAGE:") {
                            debug!("📨 Received UDP message from: {}", sender);
                            let mut stats_guard = stats.write().await;
                            stats_guard.messages_received += 1;
                        }
                    }
                    Err(e) => {
                        if *is_active.read().await {
                            warn!("UDP receive error: {}", e);
                        }
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Send direct message via UDP
    async fn send_udp_message(&self, peer_endpoint: &str, message: &[u8]) -> Result<()> {
        if let Some(socket) = &self.socket {
            // Parse peer endpoint (format: udp://ip:port)
            let endpoint_str = peer_endpoint.strip_prefix("udp://")
                .ok_or_else(|| anyhow::anyhow!("Invalid UDP endpoint format"))?;
            
            let target_addr: SocketAddr = endpoint_str.parse()?;
            
            let message_wrapper = format!("BITCHAT_MESSAGE:{}", base64::prelude::BASE64_STANDARD.encode(message));
            socket.send_to(message_wrapper.as_bytes(), target_addr).await?;
            
            debug!("📤 Sent UDP message to: {}", target_addr);
            
            let mut stats = self.stats.write().await;
            stats.messages_sent += 1;
            stats.last_activity = Some(chrono::Utc::now());
            
            Ok(())
        } else {
            Err(anyhow::anyhow!("UDP socket not initialized"))
        }
    }
}

#[async_trait]
impl NetworkBridge for UdpBridge {
    fn name(&self) -> String {
        format!("udp-bridge-{}", self.port)
    }
    
    async fn start(&mut self) -> Result<()> {
        info!("🚀 Starting UDP broadcast bridge on port: {}", self.port);
        
        self.start_udp_tasks().await?;
        *self.is_active.write().await = true;
        
        let mut stats = self.stats.write().await;
        stats.is_active = true;
        stats.connections_established += 1;
        stats.last_activity = Some(chrono::Utc::now());
        
        info!("✅ UDP bridge started successfully");
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        info!("⏹️  Stopping UDP bridge...");
        
        *self.is_active.write().await = false;
        self.socket = None;
        
        let mut stats = self.stats.write().await;
        stats.is_active = false;
        
        Ok(())
    }
    
    fn supports_method(&self, method: &DiscoveryMethod) -> bool {
        matches!(method, DiscoveryMethod::UdpBroadcast { .. })
    }
    
    async fn send_message(&self, _peer_id: &str, message: &[u8]) -> Result<()> {
        // For UDP, we need to resolve peer ID to endpoint
        // This would typically come from discovered peer information
        let peer_endpoint = format!("udp://127.0.0.1:{}", self.port); // Simplified
        
        self.send_udp_message(&peer_endpoint, message).await
    }
    
    async fn announce_presence(&self, peer_id: &str, _metadata: &HashMap<String, String>) -> Result<()> {
        // Announcements are handled automatically in the background task
        debug!("📢 Announcing presence for peer: {}", peer_id);
        Ok(())
    }
    
    async fn is_active(&self) -> bool {
        *self.is_active.read().await
    }
    
    async fn get_stats(&self) -> BridgeStats {
        let mut stats = self.stats.read().await.clone();
        stats.is_active = *self.is_active.read().await;
        stats
    }
}

/// Get local IP address for UDP announcements
fn local_ip() -> Option<String> {
    // Try to get local IP by connecting to a remote address
    let socket = StdUdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    let local_addr = socket.local_addr().ok()?;
    Some(local_addr.ip().to_string())
}

/// Create UDP bridge with default configuration
pub fn create_udp_bridge(peer_id: String, port: u16) -> UdpBridge {
    let mut config = BridgeConfig::default();
    config.name = format!("udp-bridge-{}", port);
    config.params.insert("broadcast".to_string(), "true".to_string());
    
    UdpBridge::new(peer_id, port, config)
}