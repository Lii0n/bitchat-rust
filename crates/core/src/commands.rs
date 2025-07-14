// crates/core/src/commands.rs
// Command processing for BitChat

use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

// Import core types
use crate::{
    Config,
    Storage,
    CryptoManager,
    PacketRouter,
    ChannelManager,
};

// Import protocol types
use crate::protocol::{
    BinaryProtocolManager,
    BitchatPacket,
    MessageType,
};

// Import bluetooth types (conditional)
#[cfg(feature = "bluetooth")]
use crate::bluetooth::{
    BluetoothManager,
    BluetoothEvent,
    events::BluetoothConnectionDelegate as BitchatBluetoothDelegate,
};

/// Command types that can be processed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BitchatCommand {
    /// Join a channel
    Join { channel: String, password: Option<String> },
    /// Leave a channel
    Leave { channel: String },
    /// Send a message
    Message { content: String, channel: Option<String>, recipient: Option<String> },
    /// List peers
    ListPeers,
    /// List channels
    ListChannels,
    /// Set nickname
    SetNickname { nickname: String },
    /// Quit the application
    Quit,
}

/// Result of command processing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandResult {
    Success { message: String },
    Error { error: String },
    PeerList { peers: Vec<String> },
    ChannelList { channels: Vec<String> },
    Quit,
}

/// Command processor for BitChat
#[derive(Clone)]
pub struct CommandProcessor {
    #[cfg(feature = "bluetooth")]
    bluetooth: Arc<Mutex<BluetoothManager>>,
    crypto: Arc<Mutex<CryptoManager>>,
    storage: Arc<Storage>,
    config: Arc<Config>,
    packet_router: Arc<RwLock<PacketRouter>>,
    channel_manager: Arc<Mutex<ChannelManager>>,
    my_peer_id: [u8; 8],
}

impl CommandProcessor {
    /// Create new command processor
    pub fn new(
        #[cfg(feature = "bluetooth")]
        bluetooth: Arc<Mutex<BluetoothManager>>,
        crypto: Arc<Mutex<CryptoManager>>,
        storage: Arc<Storage>,
        config: Arc<Config>,
        packet_router: Arc<RwLock<PacketRouter>>,
        channel_manager: Arc<Mutex<ChannelManager>>,
        my_peer_id: [u8; 8],
    ) -> Self {
        Self {
            #[cfg(feature = "bluetooth")]
            bluetooth,
            crypto,
            storage,
            config,
            packet_router,
            channel_manager,
            my_peer_id,
        }
    }

    /// Process a command
    pub async fn process_command(&self, command: BitchatCommand) -> Result<CommandResult> {
        match command {
            BitchatCommand::Join { channel, password } => {
                self.join_channel(&channel, password.as_deref()).await
            },
            BitchatCommand::Leave { channel } => {
                self.leave_channel(&channel).await
            },
            BitchatCommand::Message { content, channel, recipient } => {
                if let Some(channel) = channel {
                    self.send_channel_message(&channel, &content).await?;
                } else if let Some(recipient) = recipient {
                    self.send_private_message(&recipient, &content).await?;
                } else {
                    self.send_public_message(&content).await?;
                }
                Ok(CommandResult::Success { 
                    message: "Message sent".to_string() 
                })
            },
            BitchatCommand::ListPeers => {
                let peers = self.list_peers().await;
                Ok(CommandResult::PeerList { peers })
            },
            BitchatCommand::ListChannels => {
                let channels = self.list_channels().await;
                Ok(CommandResult::ChannelList { channels })
            },
            BitchatCommand::SetNickname { nickname } => {
                self.set_nickname(&nickname).await
            },
            BitchatCommand::Quit => {
                Ok(CommandResult::Quit)
            },
        }
    }

    /// Join a channel and announce it
    pub async fn join_channel(&self, channel: &str, password: Option<&str>) -> Result<CommandResult> {
        // For now, we'll just join the channel without password support
        // You can extend ChannelManager later to support passwords
        let joined = {
            let mut cm = self.channel_manager.lock().await;
            // Check if ChannelManager has join_channel method with or without password
            // For now, assume it only takes channel name
            match cm.join_channel(channel) {
                Ok(result) => result,
                Err(_) => false, // Handle error case
            }
        };
        
        if joined {
            // Send channel join packet
            let packet = BinaryProtocolManager::create_channel_join_packet(
                self.my_peer_id,
                channel,
            )?;
            
            #[cfg(feature = "bluetooth")]
            {
                let data = BinaryProtocolManager::encode(&packet)?;
                let bluetooth = self.bluetooth.lock().await;
                bluetooth.broadcast_message(&data).await?;
            }
            
            let message = if password.is_some() {
                format!("Joined password-protected channel {}", channel)
            } else {
                format!("Joined channel {}", channel)
            };
            
            Ok(CommandResult::Success { message })
        } else {
            Ok(CommandResult::Success { 
                message: format!("Already in channel {}", channel) 
            })
        }
    }

    /// Leave a channel and announce it
    pub async fn leave_channel(&self, channel: &str) -> Result<CommandResult> {
        let left = {
            let mut cm = self.channel_manager.lock().await;
            cm.leave_channel(channel).unwrap_or(false)
        };
        
        if left {
            // Send channel leave packet
            let packet = BinaryProtocolManager::create_channel_leave_packet(
                self.my_peer_id,
                channel,
            )?;
            
            #[cfg(feature = "bluetooth")]
            {
                let data = BinaryProtocolManager::encode(&packet)?;
                let bluetooth = self.bluetooth.lock().await;
                bluetooth.broadcast_message(&data).await?;
            }
            
            Ok(CommandResult::Success { 
                message: format!("Left channel {}", channel) 
            })
        } else {
            Ok(CommandResult::Success { 
                message: format!("Not in channel {}", channel) 
            })
        }
    }

    /// List joined channels
    pub async fn list_channels(&self) -> Vec<String> {
        let cm = self.channel_manager.lock().await;
        cm.get_joined_channels()
    }

    /// List connected peers
    pub async fn list_peers(&self) -> Vec<String> {
        // Implementation depends on your peer management structure
        vec![] // Placeholder
    }

    /// Send a channel message
    pub async fn send_channel_message(&self, channel: &str, content: &str) -> Result<()> {
        // Create message with channel info in payload
        let payload = format!("{}|{}", channel, content);
        let packet = BinaryProtocolManager::create_message_packet(
            self.my_peer_id,
            None, // Broadcast to channel
            &payload,
        )?;

        #[cfg(feature = "bluetooth")]
        {
            let data = BinaryProtocolManager::encode(&packet)?;
            let bluetooth = self.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
        }
        
        Ok(())
    }

    /// Send a private message
    pub async fn send_private_message(&self, recipient: &str, content: &str) -> Result<()> {
        // Parse recipient peer ID
        let recipient_bytes = hex::decode(recipient)?;
        if recipient_bytes.len() != 8 {
            return Err(anyhow::anyhow!("Invalid recipient peer ID"));
        }
        
        let mut recipient_id = [0u8; 8];
        recipient_id.copy_from_slice(&recipient_bytes);

        let packet = BinaryProtocolManager::create_message_packet(
            self.my_peer_id,
            Some(recipient_id),
            content,
        )?;

        #[cfg(feature = "bluetooth")]
        {
            let data = BinaryProtocolManager::encode(&packet)?;
            let bluetooth = self.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
        }
        
        Ok(())
    }

    /// Send a public message
    pub async fn send_public_message(&self, content: &str) -> Result<()> {
        let packet = BinaryProtocolManager::create_message_packet(
            self.my_peer_id,
            None,
            content,
        )?;

        #[cfg(feature = "bluetooth")]
        {
            let data = BinaryProtocolManager::encode(&packet)?;
            let bluetooth = self.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
        }
        
        Ok(())
    }

    /// Set nickname
    pub async fn set_nickname(&self, nickname: &str) -> Result<CommandResult> {
        // Store nickname and announce
        let packet = BinaryProtocolManager::create_announce_packet(
            self.my_peer_id,
            nickname,
        )?;

        #[cfg(feature = "bluetooth")]
        {
            let data = BinaryProtocolManager::encode(&packet)?;
            let bluetooth = self.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
        }
        
        Ok(CommandResult::Success { 
            message: format!("Nickname set to {}", nickname) 
        })
    }
}

// Bluetooth delegate implementation (conditional)
#[cfg(feature = "bluetooth")]
impl BitchatBluetoothDelegate for CommandProcessor {
    fn on_device_discovered(&self, device_id: &str, device_name: Option<&str>, rssi: i8) {
        println!("Device discovered: {} ({:?}) RSSI: {}", device_id, device_name, rssi);
    }

    fn on_device_connected(&self, device_id: &str, peer_id: &str) {
        println!("Device connected: {} (peer: {})", device_id, peer_id);
    }

    fn on_device_disconnected(&self, device_id: &str, peer_id: &str) {
        println!("Device disconnected: {} (peer: {})", device_id, peer_id);
    }

    fn on_message_received(&self, _from_peer: &str, data: &[u8]) {
        if let Ok(packet) = BinaryProtocolManager::decode(data) {
            // Create a simple async block to handle the packet
            let processor = self.clone();
            tokio::spawn(async move {
                processor.handle_received_packet(packet).await;
            });
        }
    }

    fn on_error(&self, message: &str) {
        eprintln!("Bluetooth error: {}", message);
    }
}

#[cfg(feature = "bluetooth")]
impl CommandProcessor {
    async fn handle_received_packet(&self, packet: BitchatPacket) {
        match packet.message_type {
            MessageType::Announce => {
                if let Ok(nickname) = String::from_utf8(packet.payload) {
                    println!("Peer {} announced as: {}", hex::encode(packet.sender_id), nickname);
                }
            },
            MessageType::Message => {
                if let Ok(content) = String::from_utf8(packet.payload) {
                    if content.contains('|') {
                        // Channel message
                        let parts: Vec<&str> = content.splitn(2, '|').collect();
                        if parts.len() == 2 {
                            println!("[{}] {}: {}", parts[0], hex::encode(packet.sender_id), parts[1]);
                        }
                    } else {
                        // Direct message
                        println!("{}: {}", hex::encode(packet.sender_id), content);
                    }
                }
            },
            MessageType::ChannelJoin => {
                if let Ok(channel) = String::from_utf8(packet.payload) {
                    println!("Peer {} joined channel {}", hex::encode(packet.sender_id), channel);
                }
            },
            MessageType::ChannelLeave => {
                if let Ok(channel) = String::from_utf8(packet.payload) {
                    println!("Peer {} left channel {}", hex::encode(packet.sender_id), channel);
                }
            },
            _ => {
                // Handle other message types as needed
            }
        }
    }
}

// Remove the duplicate helper implementations - they're already in binary.rs
// The BinaryProtocolManager implementations should be removed from here