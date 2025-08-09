// ==============================================================================
// crates/core/src/network/bridge.rs - Network Bridge Trait and Implementation
// ==============================================================================

//! Network bridge abstraction for BitChat cross-platform discovery and messaging

use anyhow::Result;
use async_trait::async_trait;
use crate::network::discovery::DiscoveryMethod;
use std::collections::HashMap;

/// Configuration for network bridges
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// Bridge name for identification
    pub name: String,
    /// Connection timeout in seconds
    pub connection_timeout_seconds: u64,
    /// Message retry attempts
    pub retry_attempts: u32,
    /// Whether to enable encryption
    pub enable_encryption: bool,
    /// Custom configuration parameters
    pub params: HashMap<String, String>,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            name: "default-bridge".to_string(),
            connection_timeout_seconds: 30,
            retry_attempts: 3,
            enable_encryption: true,
            params: HashMap::new(),
        }
    }
}

/// Network bridge trait for different transport protocols
#[async_trait]
pub trait NetworkBridge: Send + Sync {
    /// Get bridge name
    fn name(&self) -> String;
    
    /// Start the bridge service
    async fn start(&mut self) -> Result<()>;
    
    /// Stop the bridge service
    async fn stop(&mut self) -> Result<()>;
    
    /// Check if this bridge supports a discovery method
    fn supports_method(&self, method: &DiscoveryMethod) -> bool;
    
    /// Send message to peer via this bridge
    async fn send_message(&self, peer_id: &str, message: &[u8]) -> Result<()>;
    
    /// Broadcast presence announcement
    async fn announce_presence(&self, peer_id: &str, metadata: &HashMap<String, String>) -> Result<()>;
    
    /// Check if bridge is active
    async fn is_active(&self) -> bool;
    
    /// Get bridge statistics
    async fn get_stats(&self) -> BridgeStats;
}

/// Bridge statistics and metrics
#[derive(Debug, Clone)]
pub struct BridgeStats {
    pub name: String,
    pub is_active: bool,
    pub messages_sent: u64,
    pub messages_received: u64,
    pub connections_established: u64,
    pub connection_failures: u64,
    pub last_activity: Option<chrono::DateTime<chrono::Utc>>,
}

impl Default for BridgeStats {
    fn default() -> Self {
        Self {
            name: "unknown".to_string(),
            is_active: false,
            messages_sent: 0,
            messages_received: 0,
            connections_established: 0,
            connection_failures: 0,
            last_activity: None,
        }
    }
}

/// Bridge factory for creating different bridge types
pub struct BridgeFactory;

impl BridgeFactory {
    /// Create a Nostr bridge for cross-platform discovery
    pub fn create_nostr_bridge(
        peer_id: String, 
        relay_urls: Vec<String>, 
        config: BridgeConfig
    ) -> Box<dyn NetworkBridge + Send + Sync> {
        Box::new(crate::network::nostr::NostrBridge::new(peer_id, relay_urls, config))
    }
    
    /// Create a UDP broadcast bridge for local network discovery
    pub fn create_udp_bridge(
        peer_id: String, 
        port: u16, 
        config: BridgeConfig
    ) -> Box<dyn NetworkBridge + Send + Sync> {
        Box::new(crate::network::udp::UdpBridge::new(peer_id, port, config))
    }
    
    /// Create a TCP direct connection bridge
    pub fn create_tcp_bridge(
        peer_id: String, 
        bind_port: u16, 
        config: BridgeConfig
    ) -> Box<dyn NetworkBridge + Send + Sync> {
        Box::new(crate::network::tcp::TcpBridge::new(peer_id, bind_port, config))
    }
    
    /// Create bridges based on discovery method
    pub fn create_for_method(
        method: &DiscoveryMethod,
        peer_id: String,
        config: BridgeConfig,
    ) -> Result<Box<dyn NetworkBridge + Send + Sync>> {
        match method {
            DiscoveryMethod::Nostr { relay_url } => {
                Ok(Self::create_nostr_bridge(peer_id, vec![relay_url.clone()], config))
            }
            DiscoveryMethod::UdpBroadcast { port } => {
                Ok(Self::create_udp_bridge(peer_id, *port, config))
            }
            DiscoveryMethod::TcpDirect { host: _, port } => {
                Ok(Self::create_tcp_bridge(peer_id, *port, config))
            }
            _ => Err(anyhow::anyhow!("Unsupported discovery method: {:?}", method)),
        }
    }
}

/// Network fallback coordinator - manages multiple bridges for redundancy
pub struct NetworkFallbackCoordinator {
    bridges: Vec<Box<dyn NetworkBridge + Send + Sync>>,
    active_bridges: Vec<String>,
    fallback_order: Vec<String>,
}

impl NetworkFallbackCoordinator {
    /// Create new fallback coordinator
    pub fn new() -> Self {
        Self {
            bridges: Vec::new(),
            active_bridges: Vec::new(),
            fallback_order: Vec::new(),
        }
    }
    
    /// Add bridge with priority
    pub fn add_bridge(&mut self, bridge: Box<dyn NetworkBridge + Send + Sync>, _priority: u8) {
        let name = bridge.name();
        
        // Insert bridge in priority order (lower number = higher priority)
        let insert_pos = self.fallback_order.iter()
            .position(|_| true) // Simplified - would need priority tracking
            .unwrap_or(self.fallback_order.len());
        
        self.bridges.push(bridge);
        self.fallback_order.insert(insert_pos, name);
    }
    
    /// Start all bridges in priority order
    pub async fn start_all(&mut self) -> Result<()> {
        for bridge in &mut self.bridges {
            match bridge.start().await {
                Ok(()) => {
                    self.active_bridges.push(bridge.name());
                    tracing::info!("✅ Started bridge: {}", bridge.name());
                }
                Err(e) => {
                    tracing::warn!("❌ Failed to start bridge {}: {}", bridge.name(), e);
                }
            }
        }
        
        if self.active_bridges.is_empty() {
            return Err(anyhow::anyhow!("No network bridges started successfully"));
        }
        
        Ok(())
    }
    
    /// Send message with fallback (try bridges in priority order)
    pub async fn send_message_with_fallback(&self, peer_id: &str, message: &[u8]) -> Result<()> {
        let mut last_error = None;
        
        for bridge_name in &self.fallback_order {
            if let Some(bridge) = self.bridges.iter().find(|b| &b.name() == bridge_name) {
                if bridge.is_active().await {
                    match bridge.send_message(peer_id, message).await {
                        Ok(()) => return Ok(()),
                        Err(e) => {
                            tracing::warn!("Bridge {} failed to send message: {}", bridge_name, e);
                            last_error = Some(e);
                            continue;
                        }
                    }
                }
            }
        }
        
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("No active bridges available")))
    }
    
    /// Get coordinator statistics
    pub async fn get_stats(&self) -> CoordinatorStats {
        let mut bridge_stats = Vec::new();
        
        for bridge in &self.bridges {
            bridge_stats.push(bridge.get_stats().await);
        }
        
        CoordinatorStats {
            total_bridges: self.bridges.len(),
            active_bridges: self.active_bridges.len(),
            fallback_order: self.fallback_order.clone(),
            bridge_stats,
        }
    }
}

/// Coordinator statistics
#[derive(Debug)]
pub struct CoordinatorStats {
    pub total_bridges: usize,
    pub active_bridges: usize,
    pub fallback_order: Vec<String>,
    pub bridge_stats: Vec<BridgeStats>,
}