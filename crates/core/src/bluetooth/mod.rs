//! Bluetooth Low Energy mesh networking module with iOS/Android compatibility

pub mod events;
pub mod compatibility;
pub mod manager;

pub use events::{BluetoothEvent, BluetoothConfig, ConnectedPeer};
pub use compatibility::CompatibilityManager;
pub use manager::BluetoothManager;