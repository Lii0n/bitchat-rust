// ==============================================================================
// UPDATED crates/core/src/bluetooth/mod.rs
// ==============================================================================

pub mod compatibility;
pub mod config;
pub mod events;
pub mod manager;
pub mod constants;

#[cfg(windows)]
pub mod windows;

// Re-export main types
pub use config::BluetoothConfig;
pub use events::{BluetoothEvent, BluetoothEventListener, LoggingEventListener};
pub use manager::{BluetoothManager, ConnectedPeer, DiscoveredDevice};
pub use constants::*;

// Get platform info
pub fn get_platform_info() -> &'static str {
    #[cfg(windows)]
    return "Windows WinRT";
    
    #[cfg(not(windows))]
    return "Cross-platform btleplug";
}