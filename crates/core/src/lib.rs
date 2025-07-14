// crates/core/src/lib.rs
//! BitChat Core Library
//! 
//! This is the core library for BitChat, providing cryptographic, networking,
//! and protocol functionality for secure peer-to-peer messaging.

// Core modules
pub mod crypto;
pub mod protocol;
pub mod channel;
pub mod commands;
pub mod config;

// Optional modules based on features
#[cfg(feature = "bluetooth")]
pub mod bluetooth;

// Re-export commonly used types
pub use crypto::CryptoManager;
pub use protocol::packet::{BitchatPacket, MessageType};
pub use protocol::binary::BinaryProtocolManager;
pub use channel::{ChannelManager, ChannelInfo};
pub use commands::{CommandProcessor, BitchatCommand, CommandResult};
pub use config::Config;

#[cfg(feature = "bluetooth")]
pub use bluetooth::{BluetoothEvent, BluetoothConfig, BluetoothManager};

// Configuration and core types
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};

/// Storage abstraction
#[derive(Debug, Clone)]
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
        let storage = Storage::new(&config.data_dir.to_string_lossy())?;
        let crypto = CryptoManager::new()?;
        let peer_manager = PeerManager::new();
        
        // Generate our peer ID from device name
        let my_peer_id = crate::protocol::peer_utils::peer_id_from_device_name(&config.device_name);
        
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
    
    pub fn get_peer_id(&self) -> [u8; 8] {
        self.my_peer_id
    }
}