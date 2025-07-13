//! BitChat Core Library
//! 
//! This library contains the core functionality for BitChat:
//! - Bluetooth mesh networking
//! - Cryptographic operations
//! - Message handling and routing
//! - Protocol definitions

pub mod bluetooth;  // Now points to bluetooth/ module
pub mod crypto;
pub mod message;
pub mod peer;
pub mod protocol;   // NEW: Binary protocol implementation
pub mod storage;
pub mod config;
pub mod channel;

// Re-export main types
pub use bluetooth::BluetoothManager;
pub use crypto::{CryptoManager, KeyPair};
pub use message::{Message, MessageType, Channel};
pub use peer::{Peer, PeerManager};
pub use protocol::{BitchatPacket, BinaryProtocolManager, PacketRouter, MessageType as ProtocolMessageType};
pub use storage::Storage;
pub use config::Config;
pub use channel::ChannelManager;

// Re-export Bluetooth types for easy access
pub use bluetooth::{BluetoothEvent, BluetoothConnectionDelegate, ConnectedPeer, BluetoothConfig};

use anyhow::Result;
use protocol::{peer_utils, PacketAction, process_packet_content};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};

/// Initialize the BitChat core with configuration
pub async fn init(config: Config) -> Result<BitchatCore> {
    Ok(BitchatCore::new(config).await?)
}

/// Main BitChat core structure
pub struct BitchatCore {
    pub bluetooth: Arc<Mutex<BluetoothManager>>,
    pub crypto: CryptoManager,
    pub peer_manager: PeerManager,
    pub storage: Storage,
    pub config: Config,
    /// NEW: Binary protocol router for packet processing
    pub packet_router: Arc<RwLock<PacketRouter>>,
    /// NEW: Channel manager for handling channels
    pub channel_manager: Arc<Mutex<ChannelManager>>,
    /// NEW: Our peer ID for the protocol
    pub my_peer_id: [u8; 8],
}

impl BitchatCore {
    pub async fn new(config: Config) -> Result<Self> {
        let storage = Storage::new(&config.data_dir)?;
        let crypto = CryptoManager::new()?;
        let peer_manager = PeerManager::new();
        
        // Generate our peer ID from device name
        let my_peer_id = peer_utils::peer_id_from_device_name(&config.device_name);
        
        // Create packet router and channel manager
        let packet_router = Arc::new(RwLock::new(PacketRouter::new(my_peer_id)));
        let channel_manager = Arc::new(Mutex::new(ChannelManager::new()));
        
        // Create Bluetooth manager with custom config
        let bluetooth_config = BluetoothConfig::default()
            .with_device_name(config.device_name.clone())
            .with_verbose_logging();
        let bluetooth = BluetoothManager::with_config(bluetooth_config).await?;
        let bluetooth = Arc::new(Mutex::new(bluetooth));

        Ok(Self {
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

    pub async fn start(&self) -> Result<()> {
        tracing::info!("Starting BitChat core with peer ID: {}", 
                      peer_utils::short_peer_id(&self.my_peer_id));
        
        {
            let mut bluetooth = self.bluetooth.lock().await;
            bluetooth.start_scanning().await?;
            bluetooth.start_advertising().await?;
        }
        
        // Send initial ANNOUNCE packet
        self.announce_presence().await?;
        
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        tracing::info!("Stopping BitChat core");
        
        // Send LEAVE packet before stopping
        self.announce_leave().await?;
        
        {
            let mut bluetooth = self.bluetooth.lock().await;
            bluetooth.stop().await?;
        }
        Ok(())
    }

    /// Send an ANNOUNCE packet to discover ourselves to other peers
    pub async fn announce_presence(&self) -> Result<()> {
        let packet = BinaryProtocolManager::create_announce_packet(
            self.my_peer_id,
            &self.config.device_name,
        )?;
        
        let data = BinaryProtocolManager::encode(&packet)?;
        {
            let bluetooth = self.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
        }
        
        tracing::info!("Announced presence as '{}'", self.config.device_name);
        Ok(())
    }

    /// Send a LEAVE packet when shutting down
    pub async fn announce_leave(&self) -> Result<()> {
        let packet = BinaryProtocolManager::create_leave_packet(self.my_peer_id)?;
        let data = BinaryProtocolManager::encode(&packet)?;
        {
            let bluetooth = self.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
        }
        
        tracing::info!("Announced departure");
        Ok(())
    }

    /// Send a message using the BitChat protocol
    pub async fn send_protocol_message(&self, content: &str, recipient_id: Option<[u8; 8]>) -> Result<()> {
        let packet = BinaryProtocolManager::create_message_packet(
            self.my_peer_id,
            recipient_id,
            content,
        )?;
        
        let data = BinaryProtocolManager::encode(&packet)?;
        
        {
            let bluetooth = self.bluetooth.lock().await;
            match recipient_id {
                Some(recipient) => {
                    // Try to send directly to specific peer
                    let _recipient_str = peer_utils::short_peer_id(&recipient);
                    // Note: This is simplified - in reality we'd need to map peer IDs to Bluetooth addresses
                    bluetooth.broadcast_message(&data).await?;
                    tracing::info!("Sent direct message to {}", peer_utils::short_peer_id(&recipient));
                }
                None => {
                    // Broadcast message
                    bluetooth.broadcast_message(&data).await?;
                    tracing::info!("Broadcast message sent");
                }
            }
        }
        
        Ok(())
    }

    /// Join a channel and announce it
    pub async fn join_channel(&self, channel: &str) -> Result<String> {
        let joined = {
            let mut cm = self.channel_manager.lock().await;
            cm.join_channel(channel)?
        };
        
        if joined {
            // Send channel join packet
            let packet = BinaryProtocolManager::create_channel_join_packet(
                self.my_peer_id,
                channel,
            )?;
            
            let data = BinaryProtocolManager::encode(&packet)?;
            let bluetooth = self.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
            
            Ok(format!("Joined channel {}", channel))
        } else {
            Ok(format!("Already in channel {}", channel))
        }
    }

    /// Leave a channel and announce it
    pub async fn leave_channel(&self, channel: &str) -> Result<String> {
        let left = {
            let mut cm = self.channel_manager.lock().await;
            cm.leave_channel(channel)?
        };
        
        if left {
            // Send channel leave packet
            let packet = BinaryProtocolManager::create_channel_leave_packet(
                self.my_peer_id,
                channel,
            )?;
            
            let data = BinaryProtocolManager::encode(&packet)?;
            let bluetooth = self.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
            
            Ok(format!("Left channel {}", channel))
        } else {
            Ok(format!("Not in channel {}", channel))
        }
    }

    /// List joined channels
    pub async fn list_channels(&self) -> Result<String> {
        let cm = self.channel_manager.lock().await;
        let channels = cm.get_joined_channels();
        let current = cm.get_current_channel();
        
        if channels.is_empty() {
            Ok("No channels joined".to_string())
        } else {
            let mut result = String::from("Joined channels:\n");
            for channel in channels {
                let marker = if current == Some(&channel) { " (current)" } else { "" };
                result.push_str(&format!("  {}{}\n", channel, marker));
            }
            Ok(result)
        }
    }

    /// Send a channel message
    pub async fn send_channel_message(&self, channel: &str, content: &str) -> Result<()> {
        // Check if we're joined to this channel
        let is_joined = {
            let cm = self.channel_manager.lock().await;
            cm.is_joined(channel)
        };
        
        if !is_joined {
            return Err(anyhow::anyhow!("Not joined to channel: {}", channel));
        }

        // Create message with channel info in payload
        let payload = format!("{}|{}", channel, content);
        let packet = BinaryProtocolManager::create_message_packet(
            self.my_peer_id,
            None, // Broadcast to channel
            &payload,
        )?;

        let data = BinaryProtocolManager::encode(&packet)?;
        let bluetooth = self.bluetooth.lock().await;
        bluetooth.broadcast_message(&data).await?;
        
        tracing::info!("Sent channel message to {}: {}", channel, content);
        Ok(())
    }

    /// Process incoming packet data
    pub async fn process_packet(&self, data: &[u8]) -> Result<()> {
        let packet = BinaryProtocolManager::decode(data)?;
        
        // Update router and get action
        let action = {
            let mut router = self.packet_router.write().await;
            router.process_packet(&packet)
        };
        
        // Process the packet content
        let processor = BitchatMessageProcessor { core: self };
        process_packet_content(&packet, &processor);
        
        // Handle routing action
        match action {
            PacketAction::Relay => {
                self.relay_packet(&packet).await?;
            }
            PacketAction::Drop => {
                // Packet was duplicate or expired, ignore
            }
            PacketAction::Process => {
                // Already processed above
            }
        }
        
        Ok(())
    }

    /// Relay a packet to other peers
    async fn relay_packet(&self, packet: &BitchatPacket) -> Result<()> {
        let router = self.packet_router.read().await;
        if let Some(relay_packet) = router.create_relay_packet(packet) {
            let data = BinaryProtocolManager::encode(&relay_packet)?;
            let bluetooth = self.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
            
            tracing::debug!("Relayed packet: {}", 
                          BinaryProtocolManager::packet_summary(&relay_packet));
        }
        Ok(())
    }

    /// Legacy methods for backward compatibility
    
    /// Send a message to a specific peer (legacy)
    pub async fn send_message_to_peer(&self, _peer_id: &str, message: &str) -> Result<()> {
        // For now, broadcast (we'd need peer ID mapping for direct messages)
        self.send_protocol_message(message, None).await
    }

    /// Broadcast a message (legacy)
    pub async fn broadcast_message(&self, message: &str) -> Result<()> {
        self.send_protocol_message(message, None).await
    }

    /// Get list of connected peers
    pub async fn get_connected_peers(&self) -> Vec<String> {
        let bluetooth = self.bluetooth.lock().await;
        bluetooth.get_connected_peers().await
    }

    /// Get detailed peer information
    pub async fn get_peer_info(&self, peer_id: &str) -> Option<ConnectedPeer> {
        let bluetooth = self.bluetooth.lock().await;
        bluetooth.get_peer_info(peer_id).await
    }

    /// Get Bluetooth event receiver (call once during initialization)
    pub async fn take_bluetooth_events(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<BluetoothEvent>> {
        let bluetooth = self.bluetooth.lock().await;
        bluetooth.take_event_receiver().await
    }

    /// Get our peer ID as a hex string
    pub fn get_my_peer_id(&self) -> String {
        peer_utils::short_peer_id(&self.my_peer_id)
    }

    /// Get short peer ID for display
    pub fn get_my_short_peer_id(&self) -> String {
        peer_utils::short_peer_id(&self.my_peer_id)
    }
}

/// Custom message processor for BitChat core
struct BitchatMessageProcessor<'a> {
    core: &'a BitchatCore,
}

impl<'a> protocol::MessageProcessor for BitchatMessageProcessor<'a> {
    fn handle_announce(&self, packet: &BitchatPacket, nickname: &str) {
        let sender = peer_utils::short_peer_id(&packet.sender_id);
        tracing::info!("📢 {} announced as '{}'", sender, nickname);
        
        // TODO: Update peer manager with new peer info
    }
    
    fn handle_message(&self, packet: &BitchatPacket, content: &str) {
        let sender = peer_utils::short_peer_id(&packet.sender_id);
        
        // Check if this is a channel message (format: channel|content)
        if let Some((channel, message_content)) = content.split_once('|') {
            if channel.starts_with('#') {
                // This is a channel message
                tracing::info!("📨 Channel message in {}: {} from {}", channel, message_content, sender);
                return;
            }
        }
        
        // Regular broadcast message
        if packet.is_broadcast() {
            tracing::info!("💬 Broadcast from {}: {}", sender, content);
        } else {
            tracing::info!("💬 Direct from {}: {}", sender, content);
        }
    }
    
    fn handle_leave(&self, packet: &BitchatPacket) {
        let sender = peer_utils::short_peer_id(&packet.sender_id);
        tracing::info!("👋 {} left the network", sender);
        
        // TODO: Remove peer from peer manager
    }

    fn handle_channel_join(&self, packet: &BitchatPacket) {
        if let Ok(channel) = String::from_utf8(packet.payload.clone()) {
            let sender = peer_utils::short_peer_id(&packet.sender_id);
            tracing::info!("📢 {} joined channel: {}", sender, channel);
        }
    }

    fn handle_channel_leave(&self, packet: &BitchatPacket) {
        if let Ok(channel) = String::from_utf8(packet.payload.clone()) {
            let sender = peer_utils::short_peer_id(&packet.sender_id);
            tracing::info!("📤 {} left channel: {}", sender, channel);
        }
    }
}