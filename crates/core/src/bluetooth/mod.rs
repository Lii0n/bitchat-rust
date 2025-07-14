// Replace crates/core/src/bluetooth/mod.rs

//! Bluetooth mesh networking for BitChat
//! 
//! Provides platform-specific Bluetooth implementations with full dual-role support

pub mod config;
pub mod events;
pub mod compatibility;

// Platform-specific implementations
#[cfg(windows)]
pub mod windows;
#[cfg(not(windows))]
pub mod manager; // Fallback btleplug implementation

// Re-export main types
pub use config::BluetoothConfig;
pub use events::{BluetoothEvent, BluetoothEventListener, LoggingEventListener};
pub use compatibility::CompatibilityManager;

// Platform-specific manager
#[cfg(windows)]
pub use windows::WindowsBluetoothManager as BluetoothManager;
#[cfg(not(windows))]
pub use manager::BluetoothManager;

use crate::protocol::BitchatPacket;
use anyhow::Result;

/// Trait for Bluetooth manager implementations
pub trait BluetoothManagerTrait {
    /// Start Bluetooth operations (scanning and advertising)
    async fn start(&mut self) -> Result<()>;
    
    /// Stop all Bluetooth operations
    async fn stop(&mut self) -> Result<()>;
    
    /// Send packet to specific peer
    async fn send_packet(&self, peer_id: &str, packet: &BitchatPacket) -> Result<()>;
    
    /// Send packet to all connected peers
    async fn broadcast_packet(&self, packet: &BitchatPacket) -> Result<()>;
    
    /// Get list of connected peer IDs
    async fn get_connected_peers(&self) -> Vec<String>;
    
    /// Get debug information
    async fn get_debug_info(&self) -> String;
}

/// Create platform-specific Bluetooth manager
pub async fn create_bluetooth_manager(config: BluetoothConfig) -> Result<Box<dyn BluetoothManagerTrait + Send + Sync>> {
    #[cfg(windows)]
    {
        let manager = windows::WindowsBluetoothManager::new(config).await?;
        Ok(Box::new(manager))
    }
    
    #[cfg(not(windows))]
    {
        let manager = manager::BluetoothManager::new(config).await?;
        Ok(Box::new(manager))
    }
}

/// Bluetooth service UUIDs used by BitChat (must match iOS/Android exactly)
pub mod service_uuids {
    use uuid::Uuid;
    
    /// Primary BitChat service UUID
    pub const BITCHAT_SERVICE: Uuid = uuid::uuid!("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");
    
    /// BitChat characteristic UUID for data exchange
    pub const BITCHAT_CHARACTERISTIC: Uuid = uuid::uuid!("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D");
}

/// Connection constants matching iOS/Android behavior
pub mod constants {
    use std::time::Duration;
    
    /// Maximum number of simultaneous connections
    pub const MAX_CONNECTIONS: usize = 8;
    
    /// RSSI threshold for connections (-85 dBm, same as iOS)
    pub const RSSI_THRESHOLD: i16 = -85;
    
    /// Connection timeout
    pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
    
    /// Scan interval
    pub const SCAN_INTERVAL: Duration = Duration::from_secs(5);
    
    /// Maximum connection retry attempts
    pub const MAX_RETRY_ATTEMPTS: u32 = 3;
    
    /// Retry backoff time
    pub const RETRY_BACKOFF: Duration = Duration::from_secs(60);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{MessageType, peer_utils};

    #[tokio::test]
    async fn test_bluetooth_config_creation() {
        let config = BluetoothConfig::default();
        assert!(config.validate().is_ok());
        assert_eq!(config.device_name.len(), 8);
        assert!(peer_utils::is_valid_peer_id_string(&config.device_name));
    }

    #[tokio::test]
    async fn test_service_uuids() {
        // Ensure UUIDs match the iOS/Android implementation
        assert_eq!(
            service_uuids::BITCHAT_SERVICE.to_string().to_uppercase(),
            "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C"
        );
        assert_eq!(
            service_uuids::BITCHAT_CHARACTERISTIC.to_string().to_uppercase(),
            "A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D"
        );
    }

    #[test]
    fn test_constants() {
        assert_eq!(constants::MAX_CONNECTIONS, 8);
        assert_eq!(constants::RSSI_THRESHOLD, -85);
        assert_eq!(constants::MAX_RETRY_ATTEMPTS, 3);
    }
}