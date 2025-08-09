// ==============================================================================
// crates/core/src/network/mod.rs - Network-based Discovery Module
// ==============================================================================

//! Network-based peer discovery and messaging bridge for BitChat
//! 
//! This module implements network fallbacks when Bluetooth LE advertising fails,
//! inspired by BitChat 1.2.0's Nostr bridge approach. It provides cross-platform
//! discovery and messaging capabilities through multiple network protocols.

pub mod discovery;
pub mod nostr;
pub mod bridge;
pub mod udp;
pub mod tcp;

pub use discovery::{NetworkDiscovery, DiscoveryMethod, NetworkPeer};
pub use bridge::{NetworkBridge, BridgeConfig};
pub use nostr::{NostrClient, NostrRelay};

use anyhow::Result;
use std::collections::HashMap;
use std::time::Instant;
use tokio::sync::RwLock;
use std::sync::Arc;
use tracing::{info, warn};

/// Network-based discovery modes
#[derive(Debug, Clone, PartialEq)]
pub enum NetworkMode {
    /// Nostr protocol for cross-platform discovery
    Nostr,
    /// UDP broadcast for local network discovery
    UdpBroadcast,
    /// TCP direct connections
    TcpDirect,
    /// Hybrid mode using multiple protocols
    Hybrid,
}

/// Network discovery result
#[derive(Debug, Clone)]
pub struct NetworkDiscoveryResult {
    pub peer_id: String,
    pub discovery_method: DiscoveryMethod,
    pub endpoint: String,
    pub timestamp: Instant,
    pub metadata: HashMap<String, String>,
}

/// Network bridge manager for BitChat fallback discovery
pub struct NetworkManager {
    pub peer_id: String,
    pub mode: NetworkMode,
    pub bridges: Vec<Box<dyn NetworkBridge + Send + Sync>>,
    pub discovered_peers: Arc<RwLock<HashMap<String, NetworkDiscoveryResult>>>,
    pub is_active: Arc<RwLock<bool>>,
}

impl NetworkManager {
    /// Create new network manager for BitChat network discovery
    pub fn new(peer_id: String, mode: NetworkMode) -> Self {
        info!("🌐 Initializing Network Manager for BitChat discovery");
        info!("   Peer ID: {}", peer_id);
        info!("   Mode: {:?}", mode);
        
        Self {
            peer_id,
            mode,
            bridges: Vec::new(),
            discovered_peers: Arc::new(RwLock::new(HashMap::new())),
            is_active: Arc::new(RwLock::new(false)),
        }
    }
    
    /// Start network-based discovery (fallback when BLE fails)
    pub async fn start_discovery(&mut self) -> Result<()> {
        info!("🚀 Starting network-based BitChat discovery...");
        
        // Initialize bridges based on mode
        self.initialize_bridges().await?;
        
        // Start all bridges
        for bridge in &mut self.bridges {
            if let Err(e) = bridge.start().await {
                warn!("Failed to start bridge {}: {}", bridge.name(), e);
            } else {
                info!("✅ Started bridge: {}", bridge.name());
            }
        }
        
        *self.is_active.write().await = true;
        info!("🎯 Network discovery active with {} bridges", self.bridges.len());
        
        Ok(())
    }
    
    /// Initialize network bridges based on mode
    async fn initialize_bridges(&mut self) -> Result<()> {
        use crate::network::bridge::BridgeFactory;
        use crate::network::bridge::BridgeConfig;
        
        match self.mode {
            NetworkMode::Nostr => {
                info!("🔗 Initializing Nostr bridge for cross-platform discovery");
                let config = BridgeConfig {
                    name: "nostr-bridge".to_string(),
                    ..Default::default()
                };
                
                let bridge = BridgeFactory::create_nostr_bridge(
                    self.peer_id.clone(),
                    crate::network::nostr::DEFAULT_BITCHAT_RELAYS.iter()
                        .map(|&s| s.to_string())
                        .collect(),
                    config
                );
                self.bridges.push(bridge);
            }
            NetworkMode::UdpBroadcast => {
                info!("📡 Initializing UDP broadcast for local network discovery");
                let config = BridgeConfig {
                    name: "udp-bridge".to_string(),
                    ..Default::default()
                };
                
                let bridge = BridgeFactory::create_udp_bridge(
                    self.peer_id.clone(),
                    3737, // BitChat UDP port
                    config
                );
                self.bridges.push(bridge);
            }
            NetworkMode::TcpDirect => {
                info!("🔌 Initializing TCP direct connections");
                let config = BridgeConfig {
                    name: "tcp-bridge".to_string(),
                    ..Default::default()
                };
                
                let bridge = BridgeFactory::create_tcp_bridge(
                    self.peer_id.clone(),
                    3738, // BitChat TCP port
                    config
                );
                self.bridges.push(bridge);
            }
            NetworkMode::Hybrid => {
                info!("🌈 Initializing hybrid multi-protocol discovery");
                
                // Add Nostr bridge for iOS compatibility
                let nostr_config = BridgeConfig {
                    name: "nostr-bridge".to_string(),
                    ..Default::default()
                };
                let nostr_bridge = BridgeFactory::create_nostr_bridge(
                    self.peer_id.clone(),
                    crate::network::nostr::DEFAULT_BITCHAT_RELAYS.iter()
                        .map(|&s| s.to_string())
                        .collect(),
                    nostr_config
                );
                self.bridges.push(nostr_bridge);
                
                // Add UDP bridge for local network
                let udp_config = BridgeConfig {
                    name: "udp-bridge".to_string(),
                    ..Default::default()
                };
                let udp_bridge = BridgeFactory::create_udp_bridge(
                    self.peer_id.clone(),
                    3737,
                    udp_config
                );
                self.bridges.push(udp_bridge);
                
                // Add TCP bridge for direct connections
                let tcp_config = BridgeConfig {
                    name: "tcp-bridge".to_string(),
                    ..Default::default()
                };
                let tcp_bridge = BridgeFactory::create_tcp_bridge(
                    self.peer_id.clone(),
                    3738,
                    tcp_config
                );
                self.bridges.push(tcp_bridge);
                
                info!("✅ Hybrid mode: {} bridges initialized", self.bridges.len());
            }
        }
        
        Ok(())
    }
    
    /// Get discovered network peers
    pub async fn get_discovered_peers(&self) -> HashMap<String, NetworkDiscoveryResult> {
        self.discovered_peers.read().await.clone()
    }
    
    /// Stop network discovery
    pub async fn stop_discovery(&mut self) -> Result<()> {
        info!("⏹️  Stopping network discovery...");
        
        for bridge in &mut self.bridges {
            if let Err(e) = bridge.stop().await {
                warn!("Error stopping bridge {}: {}", bridge.name(), e);
            }
        }
        
        self.bridges.clear();
        *self.is_active.write().await = false;
        
        info!("✅ Network discovery stopped");
        Ok(())
    }
    
    /// Check if network discovery is active
    pub async fn is_active(&self) -> bool {
        *self.is_active.read().await
    }
    
    /// Send message to peer via network bridge
    pub async fn send_message(&self, peer_id: &str, message: &[u8]) -> Result<()> {
        info!("📤 Sending message to peer {} via network bridge", peer_id);
        
        // Find the bridge that discovered this peer
        let peers = self.discovered_peers.read().await;
        if let Some(peer) = peers.get(peer_id) {
            // Try to find appropriate bridge for this peer
            for bridge in &self.bridges {
                if bridge.supports_method(&peer.discovery_method) {
                    return bridge.send_message(peer_id, message).await;
                }
            }
            return Err(anyhow::anyhow!("No bridge supports peer {}", peer_id));
        }
        
        Err(anyhow::anyhow!("Peer {} not found in network discovery", peer_id))
    }
    
    /// Handle discovered peer callback
    pub async fn handle_peer_discovered(&self, result: NetworkDiscoveryResult) {
        info!("🎯 Network peer discovered: {} via {:?}", 
              result.peer_id, result.discovery_method);
        
        let mut peers = self.discovered_peers.write().await;
        peers.insert(result.peer_id.clone(), result);
    }
    
    /// Get network discovery statistics
    pub async fn get_stats(&self) -> NetworkStats {
        let peers = self.discovered_peers.read().await;
        let is_active = *self.is_active.read().await;
        
        NetworkStats {
            is_active,
            bridge_count: self.bridges.len(),
            discovered_peer_count: peers.len(),
            discovery_methods: peers.values()
                .map(|p| p.discovery_method.clone())
                .collect::<std::collections::HashSet<_>>()
                .into_iter()
                .collect(),
        }
    }
}

/// Network discovery statistics
#[derive(Debug, Clone)]
pub struct NetworkStats {
    pub is_active: bool,
    pub bridge_count: usize,
    pub discovered_peer_count: usize,
    pub discovery_methods: Vec<DiscoveryMethod>,
}