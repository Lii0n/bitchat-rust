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
            device_name: format!("BitChat-{}", uuid::Uuid::new_v4().to_string()[..8].to_uppercase()),
            auto_accept_channels: false,
            max_peers: 10,
            scan_interval_ms: 5000,
        }
    }
}
