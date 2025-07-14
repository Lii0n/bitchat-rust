use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub device_name: String,
    pub data_dir: PathBuf,
    pub bluetooth_enabled: bool,
    pub max_connections: usize,
    pub scan_duration_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            device_name: "BitChat".to_string(),
            data_dir: dirs::data_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("bitchat"),
            bluetooth_enabled: true,
            max_connections: 8,
            scan_duration_ms: 10000,
        }
    }
}

impl Config {
    pub fn load_from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_json::from_str(&content)?;
        Ok(config)
    }

    pub fn save_to_file(&self, path: &PathBuf) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}