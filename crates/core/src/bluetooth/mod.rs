//! Bluetooth mesh networking module
//! 
//! This module provides the complete Bluetooth LE mesh networking functionality
//! for BitChat, including device discovery, connection management, and message routing.

pub mod manager;
pub mod events;

// Re-export the main types for easy access
pub use manager::BluetoothConnectionManager;
pub use events::{BluetoothEvent, BluetoothConnectionDelegate, ConnectedPeer, BluetoothConfig};

// For backwards compatibility, also export as BluetoothManager
pub use manager::BluetoothConnectionManager as BluetoothManager;

// Constants that should be available to the rest of the codebase
pub use manager::{BITCHAT_SERVICE_UUID, MESSAGE_CHARACTERISTIC_UUID};
