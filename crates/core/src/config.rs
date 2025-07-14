// crates/core/src/config.rs - Fixed version

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub data_dir: PathBuf,
    pub device_name: String,
    pub auto_accept_channels: bool,
    pub max_peers: usize,
    pub scan_interval_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        let data_dir = dirs::data_dir()
            .unwrap_or_else(|| {
                // Windows fallback to AppData\Roaming
                std::env::var("APPDATA")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| PathBuf::from("."))
            })
            .join("BitChat");
            
        Self {
            data_dir,
            // UPDATED: Generate 8-character hex ID to match Swift format exactly
            device_name: generate_swift_compatible_peer_id(),
            auto_accept_channels: false,
            max_peers: 10,
            scan_interval_ms: 5000,
        }
    }
}

/// Generate peer ID in the same format as Swift (8 hex characters, uppercase)
fn generate_swift_compatible_peer_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 4] = rng.gen();
    hex::encode(bytes).to_uppercase()
}