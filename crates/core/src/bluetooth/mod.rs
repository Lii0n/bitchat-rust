pub mod events;
pub mod compatibility;

#[cfg(feature = "bluetooth")]
pub mod manager;

pub use events::{BluetoothEvent, BluetoothConfig, ConnectedPeer};
pub use compatibility::CompatibilityManager;

#[cfg(feature = "bluetooth")]
pub use manager::BluetoothManager;