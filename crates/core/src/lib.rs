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
pub mod protocol;
pub mod storage;
pub mod config;

// Re-export main types
pub use bluetooth::BluetoothManager;
pub use crypto::{CryptoManager, KeyPair};
pub use message::{Message, MessageType, Channel};
pub use peer::{Peer, PeerManager};
pub use protocol::{BitchatProtocol, Packet};
pub use storage::Storage;
pub use config::Config;

// Re-export Bluetooth types for easy access
pub use bluetooth::{BluetoothEvent, BluetoothConnectionDelegate, ConnectedPeer, BluetoothConfig};

use anyhow::Result;

/// Initialize the BitChat core with configuration
pub async fn init(config: Config) -> Result<BitchatCore> {
    Ok(BitchatCore::new(config).await?)
}

/// Main BitChat core structure
pub struct BitchatCore {
    pub bluetooth: BluetoothManager,
    pub crypto: CryptoManager,
    pub peer_manager: PeerManager,
    pub storage: Storage,
    pub config: Config,
}

impl BitchatCore {
    pub async fn new(config: Config) -> Result<Self> {
        let storage = Storage::new(&config.data_dir)?;
        let crypto = CryptoManager::new()?;
        let peer_manager = PeerManager::new();
        
        // Create Bluetooth manager with custom config
        let bluetooth_config = BluetoothConfig::default()
            .with_device_name(config.device_name.clone())
            .with_verbose_logging();  // Fixed: removed the boolean argument
        let bluetooth = BluetoothManager::with_config(bluetooth_config).await?;

        Ok(Self {
            bluetooth,
            crypto,
            peer_manager,
            storage,
            config,
        })
    }

    pub async fn start(&mut self) -> Result<()> {
        tracing::info!("Starting BitChat core");
        self.bluetooth.start_scanning().await?;
        self.bluetooth.start_advertising().await?;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        tracing::info!("Stopping BitChat core");
        self.bluetooth.stop().await?;
        Ok(())
    }

    /// Send a message to a specific peer
    pub async fn send_message_to_peer(&self, peer_id: &str, message: &str) -> Result<()> {
        self.bluetooth.send_message_to_peer(peer_id, message.as_bytes()).await
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&self, message: &str) -> Result<()> {
        self.bluetooth.broadcast_message(message.as_bytes()).await
    }

    /// Get list of connected peers
    pub async fn get_connected_peers(&self) -> Vec<String> {
        self.bluetooth.get_connected_peers().await
    }

    /// Get detailed peer information
    pub async fn get_peer_info(&self, peer_id: &str) -> Option<ConnectedPeer> {
        self.bluetooth.get_peer_info(peer_id).await
    }

    /// Get Bluetooth event receiver (call once during initialization)
    pub async fn take_bluetooth_events(&self) -> Option<tokio::sync::mpsc::UnboundedReceiver<BluetoothEvent>> {
        self.bluetooth.take_event_receiver().await
    }
}
