// ==============================================================================
// crates/core/src/network/tcp.rs - TCP Direct Connection Bridge Implementation
// ==============================================================================

//! TCP direct connection bridge for BitChat peer-to-peer messaging
//! 
//! This module provides direct TCP connections between BitChat peers,
//! useful for local network communication and as a BLE fallback.

use anyhow::Result;
use async_trait::async_trait;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::network::bridge::{NetworkBridge, BridgeConfig, BridgeStats};
use crate::network::discovery::DiscoveryMethod;

/// TCP connection bridge for direct peer communication
pub struct TcpBridge {
    peer_id: String,
    bind_port: u16,
    config: BridgeConfig,
    listener: Option<TcpListener>,
    connections: Arc<RwLock<HashMap<String, TcpStream>>>,
    is_active: Arc<RwLock<bool>>,
    stats: Arc<RwLock<BridgeStats>>,
}

impl TcpBridge {
    /// Create new TCP bridge
    pub fn new(peer_id: String, bind_port: u16, config: BridgeConfig) -> Self {
        let mut stats = BridgeStats::default();
        stats.name = format!("tcp-bridge-{}", bind_port);
        
        Self {
            peer_id,
            bind_port,
            config,
            listener: None,
            connections: Arc::new(RwLock::new(HashMap::new())),
            is_active: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(stats)),
        }
    }
    
    /// Start TCP listener for incoming connections
    async fn start_tcp_listener(&mut self) -> Result<()> {
        let bind_addr = format!("0.0.0.0:{}", self.bind_port);
        let listener = TcpListener::bind(&bind_addr).await?;
        
        info!("🔌 TCP listener bound to: {}", bind_addr);
        
        let listener = Arc::new(listener);
        
        // Start accepting connections
        let accept_listener = listener.clone();
        let peer_id = self.peer_id.clone();
        let connections = Arc::clone(&self.connections);
        let is_active = Arc::clone(&self.is_active);
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            loop {
                if !*is_active.read().await {
                    break;
                }
                
                match accept_listener.accept().await {
                    Ok((stream, addr)) => {
                        info!("📞 Incoming TCP connection from: {}", addr);
                        
                        let mut stats_guard = stats.write().await;
                        stats_guard.connections_established += 1;
                        stats_guard.last_activity = Some(chrono::Utc::now());
                        drop(stats_guard);
                        
                        // Handle connection in separate task
                        let peer_id = peer_id.clone();
                        let connections = Arc::clone(&connections);
                        let stats = Arc::clone(&stats);
                        
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(stream, addr, peer_id, connections, stats).await {
                                warn!("Error handling TCP connection from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        if *is_active.read().await {
                            warn!("TCP accept error: {}", e);
                        }
                    }
                }
            }
        });
        
        Ok(())
    }
    
    /// Handle incoming TCP connection
    async fn handle_connection(
        mut stream: TcpStream,
        addr: SocketAddr,
        our_peer_id: String,
        connections: Arc<RwLock<HashMap<String, TcpStream>>>,
        stats: Arc<RwLock<BridgeStats>>,
    ) -> Result<()> {
        debug!("🤝 Handling TCP connection from: {}", addr);
        
        // Read handshake message
        let mut buffer = [0u8; 1024];
        let timeout_duration = Duration::from_secs(10);
        
        match timeout(timeout_duration, stream.read(&mut buffer)).await {
            Ok(Ok(size)) => {
                let handshake = String::from_utf8_lossy(&buffer[..size]);
                
                if let Some(peer_id) = parse_bitchat_handshake(&handshake) {
                    if peer_id != our_peer_id {
                        info!("✅ BitChat peer connected: {} from {}", peer_id, addr);
                        
                        // Send our handshake response
                        let response = format!("BITCHAT_HANDSHAKE:{}", our_peer_id);
                        stream.write_all(response.as_bytes()).await?;
                        
                        // Store connection
                        connections.write().await.insert(peer_id.clone(), stream);
                        
                        // Start message handler for this connection
                        Self::handle_peer_messages(peer_id, connections, stats).await;
                    } else {
                        debug!("Ignoring connection from ourselves");
                    }
                } else {
                    warn!("Invalid handshake from: {}", addr);
                }
            }
            Ok(Err(e)) => {
                warn!("Error reading handshake from {}: {}", addr, e);
            }
            Err(_) => {
                warn!("Handshake timeout from: {}", addr);
            }
        }
        
        Ok(())
    }
    
    /// Handle messages from a connected peer
    async fn handle_peer_messages(
        peer_id: String,
        _connections: Arc<RwLock<HashMap<String, TcpStream>>>,
        stats: Arc<RwLock<BridgeStats>>,
    ) {
        debug!("📨 Starting message handler for peer: {}", peer_id);
        
        // This would implement the message loop for the peer
        // For now, just simulate receiving messages
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        let mut stats_guard = stats.write().await;
        stats_guard.messages_received += 1;
        stats_guard.last_activity = Some(chrono::Utc::now());
    }
    
    /// Connect to a peer via TCP
    async fn connect_to_peer(&self, peer_endpoint: &str) -> Result<TcpStream> {
        // Parse peer endpoint (format: tcp://ip:port)
        let endpoint_str = peer_endpoint.strip_prefix("tcp://")
            .ok_or_else(|| anyhow::anyhow!("Invalid TCP endpoint format"))?;
        
        let target_addr: SocketAddr = endpoint_str.parse()?;
        
        info!("🔗 Connecting to peer at: {}", target_addr);
        
        let timeout_duration = Duration::from_secs(self.config.connection_timeout_seconds);
        let mut stream = timeout(timeout_duration, TcpStream::connect(target_addr)).await??;
        
        // Send handshake
        let handshake = format!("BITCHAT_HANDSHAKE:{}", self.peer_id);
        stream.write_all(handshake.as_bytes()).await?;
        
        // Wait for response
        let mut buffer = [0u8; 256];
        let response_size = timeout(timeout_duration, stream.read(&mut buffer)).await??;
        let response = String::from_utf8_lossy(&buffer[..response_size]);
        
        if response.starts_with("BITCHAT_HANDSHAKE:") {
            info!("✅ TCP handshake successful with: {}", target_addr);
            
            let mut stats = self.stats.write().await;
            stats.connections_established += 1;
            stats.last_activity = Some(chrono::Utc::now());
            
            Ok(stream)
        } else {
            Err(anyhow::anyhow!("Invalid handshake response from peer"))
        }
    }
    
    /// Send message to peer via TCP
    async fn send_tcp_message(&self, peer_id: &str, _message: &[u8]) -> Result<()> {
        // Try to find existing connection
        let connections = self.connections.read().await;
        
        if let Some(_stream) = connections.get(peer_id) {
            // Would send message via existing connection
            debug!("📤 Sending TCP message to peer: {}", peer_id);
            
            let mut stats = self.stats.write().await;
            stats.messages_sent += 1;
            stats.last_activity = Some(chrono::Utc::now());
            
            Ok(())
        } else {
            // No existing connection - would need to establish one
            Err(anyhow::anyhow!("No TCP connection to peer: {}", peer_id))
        }
    }
}

#[async_trait]
impl NetworkBridge for TcpBridge {
    fn name(&self) -> String {
        format!("tcp-bridge-{}", self.bind_port)
    }
    
    async fn start(&mut self) -> Result<()> {
        info!("🚀 Starting TCP bridge on port: {}", self.bind_port);
        
        self.start_tcp_listener().await?;
        *self.is_active.write().await = true;
        
        let mut stats = self.stats.write().await;
        stats.is_active = true;
        stats.last_activity = Some(chrono::Utc::now());
        
        info!("✅ TCP bridge started successfully");
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        info!("⏹️  Stopping TCP bridge...");
        
        *self.is_active.write().await = false;
        self.listener = None;
        self.connections.write().await.clear();
        
        let mut stats = self.stats.write().await;
        stats.is_active = false;
        
        Ok(())
    }
    
    fn supports_method(&self, method: &DiscoveryMethod) -> bool {
        matches!(method, DiscoveryMethod::TcpDirect { .. })
    }
    
    async fn send_message(&self, peer_id: &str, message: &[u8]) -> Result<()> {
        self.send_tcp_message(peer_id, message).await
    }
    
    async fn announce_presence(&self, peer_id: &str, _metadata: &HashMap<String, String>) -> Result<()> {
        // TCP doesn't do broadcasts - presence is announced through connections
        debug!("📢 TCP presence for peer: {}", peer_id);
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

/// Parse BitChat handshake message to extract peer ID
fn parse_bitchat_handshake(handshake: &str) -> Option<String> {
    handshake.strip_prefix("BITCHAT_HANDSHAKE:")
        .map(|peer_id| peer_id.trim().to_string())
        .filter(|peer_id| {
            // Validate peer ID format (16 hex chars)
            peer_id.len() == 16 && peer_id.chars().all(|c| c.is_ascii_hexdigit())
        })
}

/// Create TCP bridge with default configuration
pub fn create_tcp_bridge(peer_id: String, port: u16) -> TcpBridge {
    let mut config = BridgeConfig::default();
    config.name = format!("tcp-bridge-{}", port);
    config.connection_timeout_seconds = 10;
    
    TcpBridge::new(peer_id, port, config)
}