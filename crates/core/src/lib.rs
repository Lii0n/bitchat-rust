pub mod config;
pub mod crypto;
pub mod storage;
pub mod protocol;
pub mod commands;

#[cfg(feature = "bluetooth")]
pub mod bluetooth;

// Re-export main types
pub use config::Config;
pub use crypto::CryptoManager;
pub use storage::Storage;
pub use protocol::{BitchatPacket, MessageType, BinaryProtocolManager};

#[cfg(feature = "bluetooth")]
pub use bluetooth::{BluetoothManager, BluetoothConfig, BluetoothEvent};

use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use anyhow::Result;

/// Channel management
#[derive(Debug)]
pub struct ChannelManager {
    channels: std::collections::HashMap<String, Channel>,
}

#[derive(Debug, Clone)]
pub struct Channel {
    pub name: String,
    pub password: Option<String>,
    pub members: std::collections::HashSet<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {
            channels: std::collections::HashMap::new(),
        }
    }
    
    pub fn create_channel(&mut self, name: String, password: Option<String>) -> Result<()> {
        let channel = Channel {
            name: name.clone(),
            password,
            members: std::collections::HashSet::new(),
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
    pub last_seen: chrono::DateTime<chrono::Utc>,
    pub public_key: Option<Vec<u8>>,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: std::collections::HashMap::new(),
        }
    }
    
    pub fn add_peer(&mut self, peer_id: [u8; 8], nickname: Option<String>) {
        let peer_info = PeerInfo {
            peer_id,
            nickname,
            last_seen: chrono::Utc::now(),
            public_key: None,
        };
        self.peers.insert(peer_id, peer_info);
    }
    
    pub fn get_peer(&self, peer_id: &[u8; 8]) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }
    
    pub fn update_peer_nickname(&mut self, peer_id: &[u8; 8], nickname: String) {
        if let Some(peer) = self.peers.get_mut(peer_id) {
            peer.nickname = Some(nickname);
            peer.last_seen = chrono::Utc::now();
        }
    }
    
    pub fn remove_peer(&mut self, peer_id: &[u8; 8]) -> bool {
        self.peers.remove(peer_id).is_some()
    }
    
    pub fn get_all_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values().collect()
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
    
    #[cfg(feature = "bluetooth")]
    pub async fn start_bluetooth(&self) -> Result<()> {
        use tracing::info;
        
        let bluetooth_manager = self.bluetooth.lock().await;
        let bluetooth_manager_clone = Arc::new(bluetooth_manager.clone());
        
        // Start the Bluetooth manager in a separate task
        tokio::spawn(async move {
            if let Err(e) = bluetooth_manager_clone.start().await {
                tracing::error!("Bluetooth manager failed: {}", e);
            }
        });
        
        info!("Bluetooth manager started");
        Ok(())
    }
    
    #[cfg(feature = "bluetooth")]
    pub async fn stop_bluetooth(&self) -> Result<()> {
        let bluetooth = self.bluetooth.lock().await;
        bluetooth.stop().await?;
        Ok(())
    }
    
    #[cfg(feature = "bluetooth")]
    pub async fn send_message(&self, content: &str) -> Result<()> {
        let packet = BinaryProtocolManager::create_message_packet(
            self.my_peer_id,
            None, // Broadcast
            content,
        )?;
        
        let data = BinaryProtocolManager::encode(&packet)?;
        let bluetooth = self.bluetooth.lock().await;
        bluetooth.broadcast_message(&data).await?;
        Ok(())
    }
    
    #[cfg(feature = "bluetooth")]
    pub async fn start_bluetooth_with_delegate<D: BitchatBluetoothDelegate + Send + Sync + 'static>(
        &self, 
        delegate: Arc<D>
    ) -> Result<()> {
        use tracing::info;
        
        // Set the delegate in the bluetooth manager
        {
            let mut bluetooth_manager = self.bluetooth.lock().await;
            bluetooth_manager.set_delegate(delegate);
        }
        
        let bluetooth_manager = self.bluetooth.lock().await;
        let bluetooth_manager_clone = Arc::new(bluetooth_manager.clone());
        
        // Start the Bluetooth manager in a separate task
        tokio::spawn(async move {
            if let Err(e) = bluetooth_manager_clone.start().await {
                tracing::error!("Bluetooth manager failed: {}", e);
            }
        });
        
        info!("Bluetooth manager started with delegate");
        Ok(())
    }
}

// Delegate trait for handling Bluetooth events  
pub trait BitchatBluetoothDelegate {
    fn on_device_discovered(&self, device_id: &str, device_name: Option<&str>, rssi: i8);
    fn on_device_connected(&self, device_id: &str, peer_id: &str);
    fn on_device_disconnected(&self, device_id: &str, peer_id: &str);
    fn on_message_received(&self, from_peer: &str, data: &[u8]);
    fn on_error(&self, message: &str);
}