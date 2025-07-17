// ==============================================================================
// crates/core/src/lib.rs - BitChat Compatible Version
// ==============================================================================

//! BitChat Core Library
//! 
//! Main entry point for the BitChat mesh networking library with enhanced
//! Bluetooth support for Windows-macOS interoperability.

// Core modules
pub mod config;
pub mod crypto;
pub mod storage;
pub mod protocol;
pub mod commands;
pub mod encryption;
pub mod constants;
pub mod message;
pub mod peer;
pub mod channel;
pub mod messaging;

// Bluetooth module (conditional compilation)
#[cfg(feature = "bluetooth")]
pub mod bluetooth;

// Re-export main types from each module
pub use config::Config;
pub use crypto::CryptoManager;
pub use storage::Storage;

// Protocol re-exports
pub use protocol::{BitchatPacket, MessageType, BinaryProtocol};

// Encryption re-exports
pub use encryption::{BitChatEncryption, BitChatIdentity, EncryptionStats};

// Bluetooth re-exports (only when feature is enabled)
#[cfg(feature = "bluetooth")]
pub use bluetooth::{BluetoothManager, BluetoothConfig, BluetoothEvent, ConnectedPeer, DiscoveredDevice};

// Standard library imports
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use tokio::sync::{Mutex, RwLock};
use anyhow::Result;

/// Channel management for BitChat
#[derive(Debug)]
pub struct ChannelManager {
    channels: HashMap<String, Channel>,
}

/// Channel information
#[derive(Debug, Clone)]
pub struct Channel {
    pub name: String,
    pub password: Option<String>,
    pub members: HashSet<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {
            channels: HashMap::new(),
        }
    }
    
    pub fn create_channel(&mut self, name: String, password: Option<String>) -> Result<()> {
        let channel = Channel {
            name: name.clone(),
            password,
            members: HashSet::new(),
            created_at: chrono::Utc::now(),
        };
        self.channels.insert(name, channel);
        Ok(())
    }
    
    pub fn join_channel(&mut self, channel_name: &str, peer_id: String) -> Result<()> {
        if let Some(channel) = self.channels.get_mut(channel_name) {
            channel.members.insert(peer_id);
        }
        Ok(())
    }
    
    pub fn leave_channel(&mut self, channel_name: &str, peer_id: &str) -> Result<()> {
        if let Some(channel) = self.channels.get_mut(channel_name) {
            channel.members.remove(peer_id);
        }
        Ok(())
    }
    
    pub fn list_channels(&self) -> Vec<&Channel> {
        self.channels.values().collect()
    }
}

/// Peer management for BitChat
#[derive(Debug)]
pub struct PeerManager {
    peers: HashMap<String, PeerInfo>,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub id: String,
    pub nickname: Option<String>,
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub connection_count: u32,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }
    
    pub fn add_peer(&mut self, peer_id: String) -> Result<()> {
        let peer = PeerInfo {
            id: peer_id.clone(),
            nickname: None,
            last_seen: chrono::Utc::now(),
            connection_count: 0,
        };
        self.peers.insert(peer_id, peer);
        Ok(())
    }
    
    pub fn list_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().collect()
    }
    
    pub fn update_peer_seen(&mut self, peer_id: &str) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.last_seen = chrono::Utc::now();
        }
    }
}

/// Packet routing for BitChat mesh
#[derive(Debug)]
pub struct PacketRouter {
    my_peer_id: [u8; 8],
    routing_table: HashMap<[u8; 8], [u8; 8]>,
}

impl PacketRouter {
    pub fn new(my_peer_id: [u8; 8]) -> Self {
        Self {
            my_peer_id,
            routing_table: HashMap::new(),
        }
    }
    
    pub fn add_route(&mut self, dest: [u8; 8], next_hop: [u8; 8]) {
        self.routing_table.insert(dest, next_hop);
    }
    
    pub fn get_next_hop(&self, dest: &[u8; 8]) -> Option<[u8; 8]> {
        self.routing_table.get(dest).copied()
    }
    
    pub fn my_peer_id(&self) -> [u8; 8] {
        self.my_peer_id
    }
}

/// Main BitChat core structure
pub struct BitchatCore {
    // Bluetooth manager (only when feature is enabled)
    #[cfg(feature = "bluetooth")]
    pub bluetooth: Arc<Mutex<BluetoothManager>>,
    
    // Core components
    pub crypto: CryptoManager,
    pub peer_manager: PeerManager,
    pub storage: Storage,
    pub config: Config,
    pub packet_router: Arc<RwLock<PacketRouter>>,
    pub channel_manager: Arc<Mutex<ChannelManager>>,
    pub my_peer_id: [u8; 8],
}

// Manual Debug implementation to handle conditional bluetooth field
impl std::fmt::Debug for BitchatCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("BitchatCore");
        
        #[cfg(feature = "bluetooth")]
        debug_struct.field("bluetooth", &"Arc<Mutex<BluetoothManager>>");
        
        debug_struct
            .field("crypto", &"CryptoManager")
            .field("peer_manager", &self.peer_manager)
            .field("storage", &self.storage)
            .field("config", &self.config)
            .field("packet_router", &"Arc<RwLock<PacketRouter>>")
            .field("channel_manager", &"Arc<Mutex<ChannelManager>>")
            .field("my_peer_id", &hex::encode(self.my_peer_id))
            .finish()
    }
}

impl BitchatCore {
    /// Create new BitChat core instance
    pub async fn new(config: Config) -> Result<Self> {
        let storage = Storage::new(&config.data_dir.to_string_lossy())?;
        let crypto = CryptoManager::new()?;
        let peer_manager = PeerManager::new();
        
        // Generate our peer ID from device name
        let my_peer_id = crate::peer::peer_id_from_device_name(&config.device_name);
        
        // Create packet router and channel manager
        let packet_router = Arc::new(RwLock::new(PacketRouter::new(my_peer_id)));
        let channel_manager = Arc::new(Mutex::new(ChannelManager::new()));
        
        // Create bluetooth manager (only when feature is enabled)
        #[cfg(feature = "bluetooth")]
        let bluetooth = {
            // Create bluetooth manager with the device name in config
            let mut bluetooth_config = BluetoothConfig::default();
            bluetooth_config.device_name = config.device_name.clone();
            
            let bluetooth_manager = BluetoothManager::with_config(bluetooth_config).await?;
            Arc::new(Mutex::new(bluetooth_manager))
        };
        
        Ok(Self {
            #[cfg(feature = "bluetooth")]
            bluetooth,
            crypto,
            peer_manager,
            storage,
            config,
            packet_router,
            channel_manager,
            my_peer_id,
        })
    }
    
    /// Get our peer ID
    pub fn get_peer_id(&self) -> [u8; 8] {
        self.my_peer_id
    }
    
    /// Send a message to a channel
    pub async fn send_channel_message(&self, channel: &str, message: &str) -> Result<()> {
        tracing::info!("Sending message to {}: {}", channel, message);
        
        #[cfg(feature = "bluetooth")]
        {
            let bluetooth = self.bluetooth.lock().await;
            bluetooth.broadcast_message(message).await?;
        }
        
        #[cfg(not(feature = "bluetooth"))]
        {
            tracing::warn!("Bluetooth feature not enabled, message not sent");
        }
        
        Ok(())
    }
    
    /// Join a channel
    pub async fn join_channel(&self, channel: &str, password: Option<&str>) -> Result<()> {
        let mut channel_manager = self.channel_manager.lock().await;
        channel_manager.create_channel(channel.to_string(), password.map(|s| s.to_string()))?;
        let peer_id = hex::encode(self.my_peer_id);
        channel_manager.join_channel(channel, peer_id)?;
        tracing::info!("Joined channel: {}", channel);
        Ok(())
    }
    
    /// Leave a channel
    pub async fn leave_channel(&self, channel: &str) -> Result<()> {
        let mut channel_manager = self.channel_manager.lock().await;
        let peer_id = hex::encode(self.my_peer_id);
        channel_manager.leave_channel(channel, &peer_id)?;
        tracing::info!("Left channel: {}", channel);
        Ok(())
    }
    
    /// List joined channels
    pub async fn list_channels(&self) -> Result<Vec<String>> {
        let channel_manager = self.channel_manager.lock().await;
        let channels = channel_manager.list_channels()
            .into_iter()
            .map(|c| c.name.clone())
            .collect();
        Ok(channels)
    }
    
    /// Get list of connected peers
    pub fn list_peers(&self) -> Vec<String> {
        self.peer_manager.list_peers()
            .into_iter()
            .map(|p| p.id.clone())
            .collect()
    }
    
    /// Start Bluetooth with enhanced delegate support
    #[cfg(feature = "bluetooth")]
    pub async fn start_bluetooth_with_delegate(&self, delegate: Arc<dyn BitchatBluetoothDelegate + Send + Sync>) -> Result<()> {
        let bluetooth = self.bluetooth.clone();
        let delegate_clone = delegate.clone();
        
        tokio::spawn(async move {
            let mut bluetooth_manager = bluetooth.lock().await;
            
            // Set up event callback
            bluetooth_manager.set_event_callback(move |event| {
                match &event {
                    BluetoothEvent::DeviceDiscovered { device_id, device_name, rssi } => {
                        delegate_clone.on_device_discovered(device_id, device_name.as_deref(), *rssi);
                    }
                    BluetoothEvent::PeerConnected { peer_id } => {
                        delegate_clone.on_device_connected("unknown_device", peer_id);
                    }
                    BluetoothEvent::PeerDisconnected { peer_id } => {
                        delegate_clone.on_device_disconnected("unknown_device", peer_id);
                    }
                    BluetoothEvent::PacketReceived { peer_id, packet_size, .. } => {
                        // For now, just send empty data - in a real implementation,
                        // you'd extract the actual message data
                        delegate_clone.on_message_received(peer_id, &[]);
                    }
                    BluetoothEvent::Error { error, context } => {
                        let error_msg = match context {
                            Some(ctx) => format!("{}: {}", ctx, error),
                            None => error.clone(),
                        };
                        delegate_clone.on_error(&error_msg);
                    }
                    _ => {} // Ignore other events
                }
            });
            
            // Start the bluetooth manager
            if let Err(e) = bluetooth_manager.start().await {
                delegate.on_error(&format!("Bluetooth manager failed: {}", e));
            }
        });
        
        tracing::info!("Bluetooth manager started with delegate");
        Ok(())
    }
    
    /// Start Bluetooth without delegate (simplified)
    #[cfg(feature = "bluetooth")]
    pub async fn start_bluetooth(&self) -> Result<()> {
        let mut bluetooth = self.bluetooth.lock().await;
        bluetooth.start().await?;
        tracing::info!("Bluetooth manager started");
        Ok(())
    }
    
    /// Stop Bluetooth
    #[cfg(feature = "bluetooth")]
    pub async fn stop_bluetooth(&self) -> Result<()> {
        let mut bluetooth = self.bluetooth.lock().await;
        bluetooth.stop().await?;
        tracing::info!("Bluetooth manager stopped");
        Ok(())
    }
    
    /// Get Bluetooth status
    #[cfg(feature = "bluetooth")]
    pub async fn bluetooth_status(&self) -> String {
        let bluetooth = self.bluetooth.lock().await;
        bluetooth.get_status().await
    }
    
    /// Get connected Bluetooth peers
    #[cfg(feature = "bluetooth")]
    pub async fn bluetooth_peers(&self) -> Vec<String> {
        let bluetooth = self.bluetooth.lock().await;
        bluetooth.get_connected_peers().await
    }
}

/// Delegate trait for handling Bluetooth events  
pub trait BitchatBluetoothDelegate: Send + Sync {
    fn on_device_discovered(&self, device_id: &str, device_name: Option<&str>, rssi: i8);
    fn on_device_connected(&self, device_id: &str, peer_id: &str);
    fn on_device_disconnected(&self, device_id: &str, peer_id: &str);
    fn on_message_received(&self, from_peer: &str, data: &[u8]);
    fn on_error(&self, message: &str);
}