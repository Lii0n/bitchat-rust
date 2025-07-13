// crates/core/src/channel.rs - NEW FILE
use std::collections::{HashMap, HashSet};
use anyhow::Result;

/// Channel management for BitChat
#[derive(Debug)]
pub struct ChannelManager {
    /// Channels we've joined
    joined_channels: HashSet<String>,
    /// Current active channel
    current_channel: Option<String>,
    /// Channel metadata
    channel_info: HashMap<String, ChannelInfo>,
}

#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub name: String,
    pub password_protected: bool,
    pub creator: Option<String>,
    pub member_count: usize,
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {
            joined_channels: HashSet::new(),
            current_channel: None,
            channel_info: HashMap::new(),
        }
    }

    /// Join a channel
    pub fn join_channel(&mut self, channel: &str) -> Result<bool> {
        let channel = self.normalize_channel_name(channel);
        
        if self.joined_channels.contains(&channel) {
            self.current_channel = Some(channel.clone());
            return Ok(false); // Already joined
        }

        self.joined_channels.insert(channel.clone());
        self.current_channel = Some(channel.clone());
        
        // Add basic channel info
        self.channel_info.insert(channel.clone(), ChannelInfo {
            name: channel.clone(),
            password_protected: false,
            creator: None,
            member_count: 1,
        });
        
        Ok(true)
    }

    /// Leave a channel
    pub fn leave_channel(&mut self, channel: &str) -> Result<bool> {
        let channel = self.normalize_channel_name(channel);
        
        if !self.joined_channels.contains(&channel) {
            return Ok(false); // Not joined
        }

        self.joined_channels.remove(&channel);
        self.channel_info.remove(&channel);
        
        // If this was our current channel, clear it
        if self.current_channel.as_ref() == Some(&channel) {
            self.current_channel = None;
        }
        
        Ok(true)
    }

    /// Check if we're in a channel
    pub fn is_joined(&self, channel: &str) -> bool {
        let channel = self.normalize_channel_name(channel);
        self.joined_channels.contains(&channel)
    }

    /// Get list of joined channels
    pub fn get_joined_channels(&self) -> Vec<String> {
        self.joined_channels.iter().cloned().collect()
    }

    /// Get current active channel
    pub fn get_current_channel(&self) -> Option<&String> {
        self.current_channel.as_ref()
    }

    /// Set current active channel
    pub fn set_current_channel(&mut self, channel: Option<String>) {
        self.current_channel = channel;
    }

    /// Normalize channel name (ensure it starts with #)
    fn normalize_channel_name(&self, channel: &str) -> String {
        if channel.starts_with('#') {
            channel.to_string()
        } else {
            format!("#{}", channel)
        }
    }

    /// Update channel info
    pub fn update_channel_info(&mut self, channel: &str, info: ChannelInfo) {
        let channel = self.normalize_channel_name(channel);
        self.channel_info.insert(channel, info);
    }

    /// Get channel info
    pub fn get_channel_info(&self, channel: &str) -> Option<&ChannelInfo> {
        let channel = self.normalize_channel_name(channel);
        self.channel_info.get(&channel)
    }
}

// crates/core/src/lib.rs - UPDATE BitchatCore struct
use crate::channel::ChannelManager;

pub struct BitchatCore {
    pub bluetooth: Arc<Mutex<BluetoothManager>>,
    pub crypto: CryptoManager,
    pub peer_manager: PeerManager,
    pub storage: Storage,
    pub config: Config,
    pub packet_router: Arc<RwLock<PacketRouter>>,
    pub channel_manager: Arc<Mutex<ChannelManager>>, // ADD this line
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
            channel_manager, // ADD this line
            my_peer_id,
        })
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
        
        Ok(())
    }
}

// Add to crates/core/src/lib.rs at the top
pub mod channel;

// crates/core/src/protocol/binary.rs - ADD these functions
impl BinaryProtocolManager {
    /// Create a CHANNEL_JOIN packet
    pub fn create_channel_join_packet(
        sender_id: [u8; 8],
        channel: &str,
    ) -> Result<BitchatPacket> {
        let payload = channel.as_bytes().to_vec();
        Ok(BitchatPacket::new_broadcast(
            MessageType::ChannelJoin,
            sender_id,
            payload,
        ))
    }

    /// Create a CHANNEL_LEAVE packet
    pub fn create_channel_leave_packet(
        sender_id: [u8; 8],
        channel: &str,
    ) -> Result<BitchatPacket> {
        let payload = channel.as_bytes().to_vec();
        Ok(BitchatPacket::new_broadcast(
            MessageType::ChannelLeave,
            sender_id,
            payload,
        ))
    }
}

// crates/core/src/protocol/packet.rs - ADD new message types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    Announce = 1,
    KeyExchange = 2,
    Leave = 3,
    Message = 4,
    FragmentStart = 5,
    FragmentContinue = 6,
    FragmentEnd = 7,
    ChannelAnnounce = 8,
    ChannelRetention = 9,
    DeliveryAck = 10,
    DeliveryStatusRequest = 11,
    ReadReceipt = 12,
    ChannelJoin = 13,          // ADD this
    ChannelLeave = 14,         // ADD this
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => MessageType::Announce,
            2 => MessageType::KeyExchange,
            3 => MessageType::Leave,
            4 => MessageType::Message,
            5 => MessageType::FragmentStart,
            6 => MessageType::FragmentContinue,
            7 => MessageType::FragmentEnd,
            8 => MessageType::ChannelAnnounce,
            9 => MessageType::ChannelRetention,
            10 => MessageType::DeliveryAck,
            11 => MessageType::DeliveryStatusRequest,
            12 => MessageType::ReadReceipt,
            13 => MessageType::ChannelJoin,     // ADD this
            14 => MessageType::ChannelLeave,    // ADD this
            _ => MessageType::Message,
        }
    }
}

// crates/cli/src/main.rs - UPDATE handle_command function
async fn handle_command(core: &std::sync::Arc<bitchat_core::BitchatCore>, command: &str) -> Result<bool> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(false);
    }

    match parts[0] {
        "/quit" | "/exit" | "/q" => {
            println!("👋 Goodbye!");
            return Ok(true);
        }
        "/help" | "/h" => {
            println!("Available commands:");
            println!("  /help, /h          - Show this help");
            println!("  /quit, /exit, /q   - Exit the application");
            println!("  /peers, /p         - List connected peers");
            println!("  /status, /s        - Show connection status");
            println!("  /broadcast <msg>   - Broadcast a message");
            println!("  /join, /j <channel> - Join a channel");          // ADD
            println!("  /leave <channel>   - Leave a channel");          // ADD
            println!("  /channels          - List joined channels");     // ADD
            println!("  /clear             - Clear the screen");
            println!();
            println!("Type any message (without /) to broadcast it to all peers.");
        }
        "/join" | "/j" => {                                              // ADD
            if parts.len() < 2 {
                println!("Usage: /join <channel>");
            } else {
                let channel = parts[1];
                match core.join_channel(channel).await {
                    Ok(msg) => println!("📢 {}", msg),
                    Err(e) => println!("❌ Failed to join channel: {}", e),
                }
            }
        }
        "/leave" => {                                                   // ADD
            if parts.len() < 2 {
                println!("Usage: /leave <channel>");
            } else {
                let channel = parts[1];
                match core.leave_channel(channel).await {
                    Ok(msg) => println!("📤 {}", msg),
                    Err(e) => println!("❌ Failed to leave channel: {}", e),
                }
            }
        }
        "/channels" => {                                                // ADD
            match core.list_channels().await {
                Ok(list) => println!("📋 {}", list),
                Err(e) => println!("❌ Failed to list channels: {}", e),
            }
        }
        "/peers" | "/p" => {
            let peers = core.get_connected_peers().await;
            if peers.is_empty() {
                println!("No connected peers");
            } else {
                println!("Connected peers ({}): ", peers.len());
                for peer_id in peers {
                    if let Some(peer_info) = core.get_peer_info(&peer_id).await {
                        println!("  {} - {} (RSSI: {}dBm)", 
                               peer_info.short_id(),
                               peer_info.name.as_deref().unwrap_or("Unknown"),
                               peer_info.rssi
                        );
                    } else {
                        println!("  {}", &peer_id[..8]);
                    }
                }
            }
        }
        "/broadcast" | "/b" => {
            if parts.len() < 2 {
                println!("Usage: /broadcast <message>");
            } else {
                let message = parts[1..].join(" ");
                match core.send_protocol_message(&message, None).await {
                    Ok(_) => println!("📤 Broadcast: {}", message),
                    Err(e) => println!("❌ Failed to broadcast: {}", e),
                }
            }
        }
        "/clear" => {
            print!("\x1B[2J\x1B[1;1H");
            println!("Chat history cleared");
        }
        "/status" | "/s" => {
            let peers = core.get_connected_peers().await;
            println!("BitChat Status:");
            println!("  Device: {}", core.get_my_short_peer_id());
            println!("  Connected Peers: {}", peers.len());
            println!("  Protocol: Active");
            
            // Show channel info too
            match core.list_channels().await {
                Ok(channels) => {
                    if !channels.contains("No channels") {
                        println!("  {}", channels.replace('\n', "\n  "));
                    }
                },
                Err(_) => {}
            }
        }
        _ => {
            println!("Unknown command: {}. Type /help for available commands.", parts[0]);
        }
    }

    Ok(false)
}

// Update the message processing in BitchatBluetoothDelegate
// In the MessageReceived event handler, update to handle channel messages:

impl BluetoothConnectionDelegate for BitchatBluetoothDelegate {
    fn on_bluetooth_event(&self, event: BluetoothEvent) {
        match event {
            BluetoothEvent::PeerDiscovered { peer_id, name, rssi } => {
                println!("🔍 Discovered peer: {} ({}) RSSI: {}dBm", 
                    name.as_deref().unwrap_or("Unknown"), 
                    &peer_id[..8], 
                    rssi
                );
            }
            BluetoothEvent::PeerConnected { peer_id } => {
                println!("🤝 Connected to peer: {}", &peer_id[..8]);
                
                if let Some(core) = &self.core {
                    let core_clone = core.clone();
                    tokio::spawn(async move {
                        if let Err(e) = core_clone.announce_presence().await {
                            tracing::error!("Failed to announce to new peer: {}", e);
                        }
                    });
                }
            }
            BluetoothEvent::PeerDisconnected { peer_id } => {
                println!("❌ Disconnected from peer: {}", &peer_id[..8]);
            }
            BluetoothEvent::MessageReceived { peer_id, data } => {
                if let Some(core) = &self.core {
                    let core_clone = core.clone();
                    tokio::spawn(async move {
                        // Process the packet and handle channel messages
                        if let Err(e) = core_clone.process_packet(&data).await {
                            tracing::error!("Failed to process packet from {}: {}", 
                                          &peer_id[..8], e);
                        } else {
                            // If it's a channel message, display it
                            // This would be handled in your packet processing logic
                            // For now, just process normally
                        }
                    });
                }
            }
            BluetoothEvent::ScanningStateChanged { scanning } => {
                if scanning {
                    println!("🔍 Started scanning for peers");
                } else {
                    println!("⏹️ Stopped scanning");
                }
            }
            BluetoothEvent::AdvertisingStateChanged { advertising } => {
                if advertising {
                    println!("📡 Started advertising");
                } else {
                    println!("⏹️ Stopped advertising");
                }
            }
            BluetoothEvent::PeerError { peer_id, error } => {
                println!("❌ Error with peer {}: {}", &peer_id[..8], error);
            }
        }
    }
}