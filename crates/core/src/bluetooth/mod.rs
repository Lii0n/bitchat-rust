//! Bluetooth Low Energy mesh networking module with iOS/Android compatibility

pub mod manager;
pub mod events;
pub mod compatibility;

pub use manager::BluetoothConnectionManager;
pub use events::{BluetoothEvent, BluetoothConfig, ConnectedPeer};
pub use compatibility::CompatibilityManager;