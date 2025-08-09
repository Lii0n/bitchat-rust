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
pub mod encryption;
pub mod message;  
pub mod peer;
pub mod messaging;
pub mod commands;

// Bluetooth module (conditional compilation)
#[cfg(feature = "bluetooth")]
pub mod bluetooth;

// Network module for fallback discovery and messaging
pub mod network;

// Test modules removed - were incomplete stubs

// Re-export main types from each module
pub use config::Config;
pub use storage::Storage;

// Protocol re-exports
pub use protocol::{BitchatPacket, MessageType, BinaryProtocol};

// Encryption re-exports (UNIFIED SYSTEM)
pub use encryption::{
    UnifiedEncryptionManager, 
    EncryptionManager,
    EncryptionStrategy,
    EncryptionContext,
    UnifiedEncryptionStats,
};

// Bluetooth re-exports (only when feature is enabled)
#[cfg(feature = "bluetooth")]
pub use bluetooth::{BluetoothManager, BluetoothConfig, BluetoothEvent, ConnectedPeer, DiscoveredDevice};

// Network re-exports
pub use network::{NetworkManager, NetworkMode, NetworkDiscoveryResult, NetworkStats};


// Standard library imports
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::{Mutex, RwLock};
use anyhow::{Result, anyhow};

// Channel management is in messaging::channel::ChannelManager
// Duplicate channel implementations have been removed

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
    
    // Network manager for fallback discovery (when BLE fails)
    pub network: Arc<Mutex<NetworkManager>>,
    
    // Core components (UNIFIED ENCRYPTION)
    pub encryption: EncryptionManager,
    pub peer_manager: PeerManager,
    pub storage: Storage,
    pub config: Config,
    pub packet_router: Arc<RwLock<PacketRouter>>,
    pub channel_manager: Arc<Mutex<crate::messaging::channel::ChannelManager>>,
    pub message_manager: Arc<Mutex<crate::messaging::MessageManager>>,
    pub my_peer_id: [u8; 8],
}

// Manual Debug implementation to handle conditional bluetooth field
impl std::fmt::Debug for BitchatCore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug_struct = f.debug_struct("BitchatCore");
        
        #[cfg(feature = "bluetooth")]
        debug_struct.field("bluetooth", &"Arc<Mutex<BluetoothManager>>");
        
        debug_struct
            .field("network", &"Arc<Mutex<NetworkManager>>")
            .field("encryption", &"UnifiedEncryptionManager")
            .field("peer_manager", &self.peer_manager)
            .field("storage", &self.storage)
            .field("config", &self.config)
            .field("packet_router", &"Arc<RwLock<PacketRouter>>")
            .field("channel_manager", &"Arc<Mutex<ChannelManager>>")
            .field("message_manager", &"Arc<Mutex<MessageManager>>")
            .field("my_peer_id", &hex::encode(self.my_peer_id))
            .finish()
    }
}

impl BitchatCore {
    /// Create new BitChat core instance
    pub async fn new(config: Config) -> Result<Self> {
        let storage = Storage::new(&config.data_dir.to_string_lossy())?;
        let encryption = EncryptionManager::new()?;
        let peer_manager = PeerManager::new();
        
        // Generate our peer ID from device name
        let my_peer_id = crate::peer::peer_id_from_device_name(&config.device_name);
        let peer_id_hex = hex::encode(my_peer_id);
        
        // Create network manager for fallback discovery (when BLE fails)
        let network_manager = NetworkManager::new(peer_id_hex.clone(), NetworkMode::Hybrid);
        let network = Arc::new(Mutex::new(network_manager));
        
        // Create packet router, channel manager, and message manager
        let packet_router = Arc::new(RwLock::new(PacketRouter::new(my_peer_id)));
        let channel_manager = Arc::new(Mutex::new(crate::messaging::channel::ChannelManager::new()));
        
        // Create message manager with database in the data directory
        let message_db_path = config.data_dir.join("messages.db");
        let message_manager = Arc::new(Mutex::new(
            crate::messaging::MessageManager::new(message_db_path)?
        ));
        
        
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
            network,
            encryption,
            peer_manager,
            storage,
            config,
            packet_router,
            channel_manager,
            message_manager,
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
        
        // Store message in database
        let stored_message = crate::messaging::StoredMessage {
            id: 0, // Will be assigned by database
            message_type: crate::messaging::MessageType::Channel,
            sender_id: hex::encode(self.my_peer_id),
            recipient_id: None,
            channel: Some(channel.to_string()),
            content: message.to_string(),
            timestamp: chrono::Utc::now(),
            encrypted: false, // TODO: Set based on encryption status
            delivery_status: crate::messaging::DeliveryStatus::Pending,
            protocol_version: 1,
            protocol_message_id: Some(rand::random::<u32>()),
        };
        
        let message_manager = self.message_manager.lock().await;
        let message_id = message_manager.store_message(stored_message)?;
        drop(message_manager);
        
        #[cfg(feature = "bluetooth")]
        {
            let bluetooth = self.bluetooth.lock().await;
            match bluetooth.broadcast_message(message).await {
                Ok(_) => {
                    // Update message status to sent
                    let message_manager = self.message_manager.lock().await;
                    message_manager.update_delivery_status(message_id, crate::messaging::DeliveryStatus::Sent)?;
                }
                Err(e) => {
                    // Update message status to failed
                    let message_manager = self.message_manager.lock().await;
                    message_manager.update_delivery_status(message_id, crate::messaging::DeliveryStatus::Failed)?;
                    return Err(e);
                }
            }
        }
        
        #[cfg(not(feature = "bluetooth"))]
        {
            tracing::warn!("Bluetooth feature not enabled, message not sent");
            // Update message status to failed since we can't send
            let message_manager = self.message_manager.lock().await;
            message_manager.update_delivery_status(message_id, crate::messaging::DeliveryStatus::Failed)?;
        }
        
        Ok(())
    }
    
    /// Send a direct message to a specific peer
    pub async fn send_direct_message(&self, peer_id: &str, message: &str) -> Result<()> {
        tracing::info!("Sending direct message to {}: {}", peer_id, message);
        
        // Validate peer ID format (16 hex chars)
        if peer_id.len() != 16 || !peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow!("Invalid peer ID format. Expected 16 hex characters, got: {}", peer_id));
        }
        
        // Store message in database
        let stored_message = crate::messaging::StoredMessage {
            id: 0, // Will be assigned by database
            message_type: crate::messaging::MessageType::Direct,
            sender_id: hex::encode(self.my_peer_id),
            recipient_id: Some(peer_id.to_string()),
            channel: None,
            content: message.to_string(),
            timestamp: chrono::Utc::now(),
            encrypted: false, // TODO: Use unified encryption system
            delivery_status: crate::messaging::DeliveryStatus::Pending,
            protocol_version: 1,
            protocol_message_id: Some(rand::random::<u32>()),
        };
        
        let message_manager = self.message_manager.lock().await;
        let message_id = message_manager.store_message(stored_message)?;
        drop(message_manager);
        
        #[cfg(feature = "bluetooth")]
        {
            let bluetooth = self.bluetooth.lock().await;
            
            // Check if peer is discovered
            let discovered = bluetooth.get_discovered_devices().await;
            if !discovered.contains_key(peer_id) {
                let message_manager = self.message_manager.lock().await;
                message_manager.update_delivery_status(message_id, crate::messaging::DeliveryStatus::Failed)?;
                return Err(anyhow!("Peer {} not found. Use '/scan' to discover peers first.", peer_id));
            }
            
            // Try to connect if not already connected
            let mut bluetooth = self.bluetooth.lock().await;
            match bluetooth.connect_to_device(peer_id).await {
                Ok(_) => {
                    // Create direct message packet
                    let message_timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    
                    let recipient_id_bytes = hex::decode(peer_id)
                        .map_err(|_| anyhow!("Invalid peer ID hex format"))?;
                    let recipient_id: [u8; 8] = recipient_id_bytes.try_into()
                        .map_err(|_| anyhow!("Peer ID must be exactly 8 bytes"))?;
                    
                    // Create BitChat message packet
                    let message_packet = BitchatPacket {
                        version: 1,
                        message_type: MessageType::DirectMessage,
                        ttl: 3,
                        timestamp: message_timestamp,
                        flags: 0x01, // HAS_RECIPIENT flag for direct message
                        message_id: rand::random::<u32>(),
                        sender_id: self.my_peer_id,
                        recipient_id: Some(recipient_id),
                        fragment_index: None,
                        total_fragments: None,
                        payload: message.as_bytes().to_vec(),
                        signature: None,
                    };
                    
                    // Send message packet
                    match bluetooth.send_packet_to_peer(peer_id, &message_packet).await {
                        Ok(()) => {
                            let message_manager = self.message_manager.lock().await;
                            message_manager.update_delivery_status(message_id, crate::messaging::DeliveryStatus::Sent)?;
                            tracing::info!("Direct message sent to {}", peer_id);
                        }
                        Err(e) => {
                            let message_manager = self.message_manager.lock().await;
                            message_manager.update_delivery_status(message_id, crate::messaging::DeliveryStatus::Failed)?;
                            return Err(anyhow!("Failed to send message to {}: {}", peer_id, e));
                        }
                    }
                }
                Err(e) => {
                    let message_manager = self.message_manager.lock().await;
                    message_manager.update_delivery_status(message_id, crate::messaging::DeliveryStatus::Failed)?;
                    return Err(anyhow!("Failed to connect to {}: {}", peer_id, e));
                }
            }
        }
        
        #[cfg(not(feature = "bluetooth"))]
        {
            tracing::warn!("Bluetooth feature not enabled, direct message not sent");
            let message_manager = self.message_manager.lock().await;
            message_manager.update_delivery_status(message_id, crate::messaging::DeliveryStatus::Failed)?;
            return Err(anyhow!("Bluetooth feature not enabled"));
        }
        
        Ok(())
    }
    
    /// Join a channel
    pub async fn join_channel(&self, channel: &str, _password: Option<&str>) -> Result<()> {
        let mut channel_manager = self.channel_manager.lock().await;
        channel_manager.join_channel(channel)?;
        tracing::info!("Joined channel: {}", channel);
        Ok(())
    }
    
    /// Leave a channel
    pub async fn leave_channel(&self, channel: &str) -> Result<()> {
        let mut channel_manager = self.channel_manager.lock().await;
        channel_manager.leave_channel(channel)?;
        tracing::info!("Left channel: {}", channel);
        Ok(())
    }
    
    /// List joined channels
    pub async fn list_channels(&self) -> Result<Vec<String>> {
        let channel_manager = self.channel_manager.lock().await;
        Ok(channel_manager.get_joined_channels())
    }
    
    /// Get list of connected peers
    pub fn list_peers(&self) -> Vec<String> {
        self.peer_manager.list_peers()
            .into_iter()
            .map(|p| p.id.clone())
            .collect()
    }
    
    /// Get recent messages (latest first)
    pub async fn get_recent_messages(&self, limit: Option<usize>) -> Result<Vec<crate::messaging::StoredMessage>> {
        let message_manager = self.message_manager.lock().await;
        message_manager.get_messages_with_limit(limit)
    }
    
    /// Get messages for a specific channel
    pub async fn get_channel_messages(&self, channel: &str, limit: Option<usize>) -> Result<Vec<crate::messaging::StoredMessage>> {
        let message_manager = self.message_manager.lock().await;
        message_manager.get_channel_messages(channel, limit)
    }
    
    /// Get direct messages between this device and another peer
    pub async fn get_direct_messages(&self, peer_id: &str, limit: Option<usize>) -> Result<Vec<crate::messaging::StoredMessage>> {
        let message_manager = self.message_manager.lock().await;
        let my_peer_id_str = hex::encode(self.my_peer_id);
        message_manager.get_direct_messages(&my_peer_id_str, peer_id, limit)
    }
    
    /// Search messages by content
    pub async fn search_messages(&self, query: &str, limit: Option<usize>) -> Result<Vec<crate::messaging::StoredMessage>> {
        let message_manager = self.message_manager.lock().await;
        message_manager.search_messages(query, limit)
    }
    
    /// Get message statistics
    pub async fn get_message_stats(&self) -> Result<crate::messaging::MessageStats> {
        let message_manager = self.message_manager.lock().await;
        message_manager.get_message_stats()
    }
    
    /// Store an incoming message (called when receiving messages from peers)
    pub async fn store_incoming_message(&self, sender_id: &str, content: &str, message_type: crate::messaging::MessageType, channel: Option<&str>) -> Result<i64> {
        let stored_message = crate::messaging::StoredMessage {
            id: 0, // Will be assigned by database
            message_type,
            sender_id: sender_id.to_string(),
            recipient_id: Some(hex::encode(self.my_peer_id)),
            channel: channel.map(|c| c.to_string()),
            content: content.to_string(),
            timestamp: chrono::Utc::now(),
            encrypted: false, // TODO: Detect encryption status
            delivery_status: crate::messaging::DeliveryStatus::Delivered,
            protocol_version: 1,
            protocol_message_id: None, // Incoming messages might not have this
        };
        
        let message_manager = self.message_manager.lock().await;
        message_manager.store_message(stored_message)
    }
    
    /// Announce presence to the network with optional nickname
    pub async fn announce_presence(&self, nickname: Option<&str>) -> Result<()> {
        tracing::info!("📢 Announcing presence to network");
        
        // Create announcement payload with device name and optional nickname
        let mut announcement_data = serde_json::json!({
            "device_name": self.config.device_name,
            "peer_id": hex::encode(self.my_peer_id),
            "timestamp": chrono::Utc::now().timestamp(),
            "protocol_version": 1
        });
        
        if let Some(nick) = nickname {
            announcement_data["nickname"] = serde_json::Value::String(nick.to_string());
        }
        
        let announcement_payload = announcement_data.to_string().into_bytes();
        
        #[cfg(feature = "bluetooth")]
        {
            let bluetooth = self.bluetooth.lock().await;
            
            // Create announcement packet
            let announcement_packet = BitchatPacket {
                version: 1,
                message_type: MessageType::Announce,
                ttl: 3, // Allow forwarding through mesh
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_millis() as u64,
                flags: 0x00, // No special flags for announcements
                message_id: rand::random::<u32>(),
                sender_id: self.my_peer_id,
                recipient_id: None, // Broadcast to all
                fragment_index: None,
                total_fragments: None,
                payload: announcement_payload,
                signature: None,
            };
            
            // Broadcast announcement to all connected peers and discovered devices
            let discovered = bluetooth.get_discovered_devices().await;
            let mut announcement_count = 0;
            
            for device_id in discovered.keys() {
                match bluetooth.send_packet_to_peer(device_id, &announcement_packet).await {
                    Ok(()) => {
                        announcement_count += 1;
                        tracing::debug!("📢 Announced to peer: {}", device_id);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to announce to {}: {}", device_id, e);
                    }
                }
            }
            
            if announcement_count > 0 {
                tracing::info!("📢 Presence announced to {} peers", announcement_count);
            } else {
                tracing::info!("📢 No peers to announce to. Use '/scan' to discover peers first.");
            }
        }
        
        #[cfg(not(feature = "bluetooth"))]
        {
            tracing::warn!("Bluetooth feature not enabled, presence announcement not sent");
            return Err(anyhow!("Bluetooth feature not enabled"));
        }
        
        Ok(())
    }
    
    /// Handle incoming BitChat packet from Bluetooth
    pub async fn handle_incoming_packet(&self, peer_id: String, packet: BitchatPacket) -> Result<()> {
        tracing::info!("📥 Processing incoming packet from {}: type={:?}", peer_id, packet.message_type);
        
        match packet.message_type {
            MessageType::DirectMessage => {
                // Extract message content
                if let Ok(message_content) = String::from_utf8(packet.payload.clone()) {
                    tracing::info!("📨 Direct message from {}: {}", peer_id, message_content);
                    
                    // Store incoming direct message in database
                    self.store_incoming_message(
                        &peer_id,
                        &message_content,
                        crate::messaging::MessageType::Direct,
                        None
                    ).await?;
                    
                    tracing::info!("✅ Direct message from {} stored in database", peer_id);
                } else {
                    tracing::warn!("Failed to decode direct message payload from {}", peer_id);
                }
            }
            MessageType::Message => {
                // Extract message content (assuming channel info is in a header or we default to general)
                if let Ok(message_content) = String::from_utf8(packet.payload.clone()) {
                    tracing::info!("📢 Channel message from {}: {}", peer_id, message_content);
                    
                    // For now, store channel messages to a default channel
                    // TODO: Extract actual channel from packet metadata
                    self.store_incoming_message(
                        &peer_id,
                        &message_content,
                        crate::messaging::MessageType::Channel,
                        Some("general")
                    ).await?;
                    
                    tracing::info!("✅ Channel message from {} stored in database", peer_id);
                } else {
                    tracing::warn!("Failed to decode channel message payload from {}", peer_id);
                }
            }
            MessageType::Announce => {
                tracing::info!("📢 Received announcement from {}", peer_id);
                if let Ok(announcement_json) = String::from_utf8(packet.payload.clone()) {
                    if let Ok(announcement_data) = serde_json::from_str::<serde_json::Value>(&announcement_json) {
                        let device_name = announcement_data["device_name"].as_str().unwrap_or("Unknown");
                        let nickname = announcement_data["nickname"].as_str();
                        
                        tracing::info!("📢 Announcement from {}: device='{}'{}", 
                              peer_id, device_name,
                              nickname.map(|n| format!(", nickname='{}'", n)).unwrap_or_default());
                        
                        // Update peer information in peer manager
                        // (This could be expanded to track nicknames and device names)
                    }
                }
            }
            MessageType::Ping => {
                tracing::info!("🏓 Received ping from {}", peer_id);
                // TODO: Send pong response
            }
            MessageType::Pong => {
                tracing::info!("🏓 Received pong from {}", peer_id);
                // TODO: Update ping statistics
            }
            _ => {
                tracing::debug!("📦 Received unhandled message type {:?} from {}", packet.message_type, peer_id);
            }
        }
        
        Ok(())
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
                    BluetoothEvent::PacketReceived { peer_id, .. } => {
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
    
    /// Start discovery system with BLE and network fallback
    pub async fn start_discovery(&self) -> Result<()> {
        tracing::info!("🚀 Starting BitChat discovery system (BLE + Network fallback)");
        
        // First, try to start Bluetooth LE discovery
        #[cfg(feature = "bluetooth")]
        {
            match self.try_start_bluetooth().await {
                Ok(()) => {
                    tracing::info!("✅ Bluetooth LE discovery started successfully");
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("❌ Bluetooth LE discovery failed: {}", e);
                    tracing::info!("🔄 Activating network-based discovery fallback...");
                    
                    // Activate network fallback
                    return self.start_network_discovery().await;
                }
            }
        }
        
        #[cfg(not(feature = "bluetooth"))]
        {
            tracing::info!("📱 Bluetooth not available, using network discovery");
            self.start_network_discovery().await
        }
    }
    
    /// Start network-based discovery as fallback
    pub async fn start_network_discovery(&self) -> Result<()> {
        tracing::info!("🌐 Starting network-based peer discovery...");
        
        let mut network = self.network.lock().await;
        network.start_discovery().await?;
        
        tracing::info!("✅ Network discovery active (Nostr + UDP + TCP)");
        tracing::info!("🍎 This provides iOS BitChat compatibility via network protocols");
        
        Ok(())
    }
    
    /// Try to start Bluetooth LE (may fail on hardware limitations)
    #[cfg(feature = "bluetooth")]
    async fn try_start_bluetooth(&self) -> Result<()> {
        self.start_bluetooth().await
    }
    
    /// Start Bluetooth without delegate (simplified)
    #[cfg(feature = "bluetooth")]
    pub async fn start_bluetooth(&self) -> Result<()> {
        let mut bluetooth = self.bluetooth.lock().await;
        
        // Create shared references for the packet handler
        let message_manager = self.message_manager.clone();
        let my_peer_id = self.my_peer_id;
        
        // Set up packet handler to process packets directly
        bluetooth.set_packet_handler(move |peer_id: String, packet: BitchatPacket| {
            let message_manager = message_manager.clone();
            tokio::spawn(async move {
                tracing::info!("📥 Processing incoming packet from {}: type={:?}", peer_id, packet.message_type);
                
                match packet.message_type {
                    MessageType::DirectMessage => {
                        // Extract message content
                        if let Ok(message_content) = String::from_utf8(packet.payload.clone()) {
                            tracing::info!("📨 Direct message from {}: {}", peer_id, message_content);
                            
                            // Store incoming direct message in database
                            let stored_message = crate::messaging::StoredMessage {
                                id: 0, // Will be assigned by database
                                message_type: crate::messaging::MessageType::Direct,
                                sender_id: peer_id.clone(),
                                recipient_id: Some(hex::encode(my_peer_id)),
                                channel: None,
                                content: message_content,
                                timestamp: chrono::Utc::now(),
                                encrypted: false, // TODO: Detect encryption status
                                delivery_status: crate::messaging::DeliveryStatus::Delivered,
                                protocol_version: 1,
                                protocol_message_id: Some(packet.message_id),
                            };
                            
                            let message_manager = message_manager.lock().await;
                            if let Err(e) = message_manager.store_message(stored_message) {
                                tracing::error!("Failed to store direct message: {}", e);
                            } else {
                                tracing::info!("✅ Direct message from {} stored in database", peer_id);
                            }
                        } else {
                            tracing::warn!("Failed to decode direct message payload from {}", peer_id);
                        }
                    }
                    MessageType::Message => {
                        // Extract message content (channel message)
                        if let Ok(message_content) = String::from_utf8(packet.payload.clone()) {
                            tracing::info!("📢 Channel message from {}: {}", peer_id, message_content);
                            
                            // Store channel message in database (default to "general" channel)
                            let stored_message = crate::messaging::StoredMessage {
                                id: 0, // Will be assigned by database
                                message_type: crate::messaging::MessageType::Channel,
                                sender_id: peer_id.clone(),
                                recipient_id: Some(hex::encode(my_peer_id)),
                                channel: Some("general".to_string()),
                                content: message_content,
                                timestamp: chrono::Utc::now(),
                                encrypted: false, // TODO: Detect encryption status
                                delivery_status: crate::messaging::DeliveryStatus::Delivered,
                                protocol_version: 1,
                                protocol_message_id: Some(packet.message_id),
                            };
                            
                            let message_manager = message_manager.lock().await;
                            if let Err(e) = message_manager.store_message(stored_message) {
                                tracing::error!("Failed to store channel message: {}", e);
                            } else {
                                tracing::info!("✅ Channel message from {} stored in database", peer_id);
                            }
                        } else {
                            tracing::warn!("Failed to decode channel message payload from {}", peer_id);
                        }
                    }
                    MessageType::Announce => {
                        tracing::info!("📢 Received announcement from {}", peer_id);
                        if let Ok(announcement_json) = String::from_utf8(packet.payload.clone()) {
                            if let Ok(announcement_data) = serde_json::from_str::<serde_json::Value>(&announcement_json) {
                                let device_name = announcement_data["device_name"].as_str().unwrap_or("Unknown");
                                let nickname = announcement_data["nickname"].as_str();
                                
                                tracing::info!("📢 Announcement from {}: device='{}'{}", 
                                      peer_id, device_name,
                                      nickname.map(|n| format!(", nickname='{}'", n)).unwrap_or_default());
                            }
                        }
                    }
                    MessageType::Ping => {
                        tracing::info!("🏓 Received ping from {}", peer_id);
                        // TODO: Send pong response
                    }
                    MessageType::Pong => {
                        tracing::info!("🏓 Received pong from {}", peer_id);
                        // TODO: Update ping statistics
                    }
                    _ => {
                        tracing::debug!("📦 Received unhandled message type {:?} from {}", packet.message_type, peer_id);
                    }
                }
            });
        });
        
        // Start Bluetooth
        bluetooth.start().await?;
        
        tracing::info!("Bluetooth manager started with packet routing");
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
    
    /// Stop discovery system (both BLE and network)
    pub async fn stop_discovery(&self) -> Result<()> {
        tracing::info!("⏹️ Stopping BitChat discovery system...");
        
        // Stop Bluetooth if enabled
        #[cfg(feature = "bluetooth")]
        if let Err(e) = self.stop_bluetooth().await {
            tracing::warn!("Error stopping Bluetooth: {}", e);
        }
        
        // Stop network discovery
        let mut network = self.network.lock().await;
        network.stop_discovery().await?;
        
        tracing::info!("✅ Discovery system stopped");
        Ok(())
    }
    
    /// Get network discovery status
    pub async fn get_network_status(&self) -> NetworkStats {
        let network = self.network.lock().await;
        network.get_stats().await
    }
    
    /// Get discovered network peers
    pub async fn get_network_peers(&self) -> HashMap<String, NetworkDiscoveryResult> {
        let network = self.network.lock().await;
        network.get_discovered_peers().await
    }
    
    /// Send message via network bridge (fallback when BLE unavailable)
    pub async fn send_network_message(&self, peer_id: &str, message: &[u8]) -> Result<()> {
        let network = self.network.lock().await;
        network.send_message(peer_id, message).await
    }
    
    /// Get discovery mode status (BLE vs Network)
    pub async fn get_discovery_mode(&self) -> String {
        #[cfg(feature = "bluetooth")]
        {
            let bluetooth = self.bluetooth.lock().await;
            if bluetooth.is_running().await {
                return "Bluetooth LE".to_string();
            }
        }
        
        let network = self.network.lock().await;
        if network.is_active().await {
            "Network Fallback (Nostr + UDP + TCP)".to_string()
        } else {
            "Discovery Inactive".to_string()
        }
    }
}

/// Enhanced discovery system result
#[derive(Debug, Clone)]
pub struct DiscoverySystemStatus {
    pub mode: String,
    pub bluetooth_active: bool,
    pub network_active: bool,
    pub discovered_peers_count: usize,
    pub network_stats: Option<NetworkStats>,
}

/// Delegate trait for handling Bluetooth events  
pub trait BitchatBluetoothDelegate: Send + Sync {
    fn on_device_discovered(&self, device_id: &str, device_name: Option<&str>, rssi: i8);
    fn on_device_connected(&self, device_id: &str, peer_id: &str);
    fn on_device_disconnected(&self, device_id: &str, peer_id: &str);
    fn on_message_received(&self, from_peer: &str, data: &[u8]);
    fn on_error(&self, message: &str);
}