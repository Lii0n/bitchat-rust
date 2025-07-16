pub mod compatibility;
pub mod config;
pub mod events;
pub mod manager;

#[cfg(windows)]
pub mod windows;

// Re-export main types
pub use config::BluetoothConfig;
pub use events::BluetoothEvent;
pub use manager::BluetoothManager;

// Re-export types that other modules expect
pub use events::{ConnectedPeer, DiscoveredDevice};
pub use manager::{PlatformPeerData, PlatformDeviceData};

// Service UUIDs
pub mod service_uuids {
    use uuid::Uuid;
    
    /// Primary BitChat service UUID
    pub const BITCHAT_SERVICE: Uuid = uuid::uuid!("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");
    
    /// BitChat characteristic UUID for data exchange  
    pub const BITCHAT_CHARACTERISTIC: Uuid = uuid::uuid!("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D");
}