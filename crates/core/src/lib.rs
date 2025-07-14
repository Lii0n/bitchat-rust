//! BitChat Core Library
//! 
//! This is the core library for BitChat, providing cryptographic, networking,
//! and protocol functionality for secure peer-to-peer messaging.

// Core modules
pub mod crypto;
pub mod protocol;
pub mod channel;
pub mod commands; // Added commands module

// Optional modules based on features
#[cfg(feature = "bluetooth")]
pub mod bluetooth;

// Re-export commonly used types
pub use crypto::CryptoManager;
pub use protocol::packet::{BitchatPacket, MessageType};
pub use protocol::binary::BinaryProtocolManager;
pub use channel::{ChannelManager, ChannelInfo};
pub use commands::{CommandProcessor, BitchatCommand, CommandResult}; // Added command exports

#[cfg(feature = "bluetooth")]
pub use bluetooth::{BluetoothEvent, BluetoothConfig, BluetoothManager, CompatibilityManager};

// Configuration and core types
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Main configuration for BitChat
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub device_name: String,
    pub data_dir: String,
    pub max_peers: usize,
    pub enable_bluetooth: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device_name: "BitChat-Device".to_string(),
            data_dir: dirs::data_dir()
                .unwrap_or_else(|| std::env::current_dir().unwrap())
                .join("bitchat")
                .to_string_lossy()
                .to_string(),
            max_peers: 100,
            enable_bluetooth: true,
        }
    }
}

/// Storage abstraction
#[derive(Debug)]
pub struct Storage {
    data_dir: String,
}

impl Storage {
    pub fn new(data_dir: &str) -> anyhow::Result<Self> {
        std::fs::create_dir_all(data_dir)?;
        Ok(Self {
            data_dir: data_dir.to_string(),
        })
    }
    
    pub fn data_dir(&self) -> &str {
        &self.data_dir
    }
}

/// Peer management
#[derive(Debug)]
pub struct PeerManager {
    peers: std::collections::HashMap<[u8; 8], PeerInfo>,
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: [u8; 8],
    pub nickname: Option<String>,
    pub last_seen: u64,
    pub connection_count: u32,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: std::collections::HashMap::new(),
        }
    }
    
    pub fn add_peer(&mut self, peer_id: [u8; 8], nickname: Option<String>) {
        let info = PeerInfo {
            peer_id,
            nickname,
            last_seen: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            connection_count: 1,
        };
        self.peers.insert(peer_id, info);
    }
    
    pub fn get_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().collect()
    }
    
    pub fn remove_peer(&mut self, peer_id: &[u8; 8]) -> bool {
        self.peers.remove(peer_id).is_some()
    }
}

/// Packet routing
#[derive(Debug)]
pub struct PacketRouter {
    my_peer_id: [u8; 8],
    routing_table: std::collections::HashMap<[u8; 8], [u8; 8]>, // dest -> next_hop
}

impl PacketRouter {
    pub fn new(my_peer_id: [u8; 8]) -> Self {
        Self { 
            my_peer_id,
            routing_table: std::collections::HashMap::new(),
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
    #[cfg(feature = "bluetooth")]
    pub bluetooth: Arc<Mutex<BluetoothManager>>,
    pub crypto: CryptoManager,
    pub peer_manager: PeerManager,
    pub storage: Storage,
    pub config: Config,
    pub packet_router: Arc<RwLock<PacketRouter>>,
    pub channel_manager: Arc<Mutex<ChannelManager>>,
    pub my_peer_id: [u8; 8],
}

// Manual Debug implementation to handle the conditional bluetooth field
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
    pub async fn new(config: Config) -> anyhow::Result<Self> {
        let storage = Storage::new(&config.data_dir)?;
        let crypto = CryptoManager::new()?;
        let peer_manager = PeerManager::new();
        
        // Generate our peer ID from device name
        let my_peer_id = crypto::utils::peer_id_from_device_name(&config.device_name);
        
        // Create packet router and channel manager
        let packet_router = Arc::new(RwLock::new(PacketRouter::new(my_peer_id)));
        let channel_manager = Arc::new(Mutex::new(ChannelManager::new()));
        
        #[cfg(feature = "bluetooth")]
        let bluetooth = {
            let bluetooth_config = BluetoothConfig::default()
                .with_device_name(config.device_name.clone());
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

    /// Join a channel and announce it
    pub async fn join_channel(&self, channel: &str) -> anyhow::Result<String> {
        let joined = {
            let mut cm = self.channel_manager.lock().await;
            cm.join_channel(channel)?
        };
        
        if joined {
            #[cfg(feature = "bluetooth")]
            {
                // Send channel join packet
                let packet = BinaryProtocolManager::create_channel_join_packet(
                    self.my_peer_id,
                    channel,
                )?;
                
                let data = BinaryProtocolManager::encode(&packet)?;
                let bluetooth = self.bluetooth.lock().await;
                bluetooth.broadcast_message(&data).await?;
            }
            
            Ok(format!("Joined channel {}", channel))
        } else {
            Ok(format!("Already in channel {}", channel))
        }
    }

    /// Leave a channel and announce it
    pub async fn leave_channel(&self, channel: &str) -> anyhow::Result<String> {
        let left = {
            let mut cm = self.channel_manager.lock().await;
            cm.leave_channel(channel)?
        };
        
        if left {
            #[cfg(feature = "bluetooth")]
            {
                // Send channel leave packet
                let packet = BinaryProtocolManager::create_channel_leave_packet(
                    self.my_peer_id,
                    channel,
                )?;
                
                let data = BinaryProtocolManager::encode(&packet)?;
                let bluetooth = self.bluetooth.lock().await;
                bluetooth.broadcast_message(&data).await?;
            }
            
            Ok(format!("Left channel {}", channel))
        } else {
            Ok(format!("Not in channel {}", channel))
        }
    }

    /// List joined channels
    pub async fn list_channels(&self) -> anyhow::Result<String> {
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
    pub async fn send_channel_message(&self, channel: &str, content: &str) -> anyhow::Result<()> {
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
        
        #[cfg(not(feature = "bluetooth"))]
        {
            // Log the message when bluetooth is disabled
            tracing::info!("Would send to channel {}: {}", channel, content);
        }
        
        Ok(())
    }

    /// Get peer information
    pub fn get_peers(&self) -> Vec<&PeerInfo> {
        self.peer_manager.get_peers()
    }

    /// Add a new peer
    pub fn add_peer(&mut self, peer_id: [u8; 8], nickname: Option<String>) {
        self.peer_manager.add_peer(peer_id, nickname);
    }

    /// Remove a peer
    pub fn remove_peer(&mut self, peer_id: &[u8; 8]) -> bool {
        self.peer_manager.remove_peer(peer_id)
    }
}