// Replace crates/core/src/config.rs

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::protocol::peer_utils;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub data_dir: PathBuf,
    pub device_name: String, // Now stores the 8-character hex peer ID
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
            // Generate iOS/Android compatible 8-character hex peer ID
            device_name: peer_utils::generate_compatible_peer_id(),
            auto_accept_channels: false,
            max_peers: 10,
            scan_interval_ms: 5000,
        }
    }
}

impl Config {
    /// Create config with deterministic peer ID from system info
    pub fn with_deterministic_peer_id() -> Self {
        let mut config = Self::default();
        
        // Generate deterministic peer ID from system-specific info
        let system_info = format!(
            "{}|{}|{}",
            std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "unknown".to_string()),
            std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "user".to_string()),
            config.data_dir.to_string_lossy()
        );
        
        config.device_name = peer_utils::peer_id_from_device_info(&system_info);
        config
    }
    
    /// Get peer ID as bytes for internal use
    pub fn get_peer_id_bytes(&self) -> [u8; 8] {
        peer_utils::peer_id_string_to_bytes(&self.device_name)
            .unwrap_or_else(|_| {
                tracing::warn!("Invalid peer ID in config: {}, generating new one", self.device_name);
                peer_utils::peer_id_string_to_bytes(&peer_utils::generate_compatible_peer_id()).unwrap()
            })
    }
    
    /// Get peer ID as string for iOS/Android compatibility
    pub fn get_peer_id_string(&self) -> &str {
        &self.device_name
    }
    
    /// Update peer ID (useful for testing or manual override)
    pub fn set_peer_id(&mut self, peer_id: &str) -> Result<(), String> {
        if peer_utils::is_valid_peer_id_string(peer_id) {
            self.device_name = peer_id.to_uppercase();
            Ok(())
        } else {
            Err(format!("Invalid peer ID format: {}", peer_id))
        }
    }
    
    /// Get Bluetooth advertisement name (same as peer ID for iOS/Android compatibility)
    pub fn get_advertisement_name(&self) -> String {
        peer_utils::create_advertisement_name(&self.device_name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.device_name.len(), 8);
        assert!(peer_utils::is_valid_peer_id_string(&config.device_name));
    }

    #[test]
    fn test_deterministic_config() {
        let config1 = Config::with_deterministic_peer_id();
        let config2 = Config::with_deterministic_peer_id();
        
        // Should be deterministic (same system = same peer ID)
        assert_eq!(config1.device_name, config2.device_name);
        assert!(peer_utils::is_valid_peer_id_string(&config1.device_name));
    }

    #[test]
    fn test_peer_id_operations() {
        let mut config = Config::default();
        
        // Test setting valid peer ID
        assert!(config.set_peer_id("A1B2C3D4").is_ok());
        assert_eq!(config.get_peer_id_string(), "A1B2C3D4");
        
        // Test setting invalid peer ID
        assert!(config.set_peer_id("invalid").is_err());
        
        // Test bytes conversion
        let bytes = config.get_peer_id_bytes();
        assert_eq!(bytes[0], 0xA1);
        assert_eq!(bytes[1], 0xB2);
        assert_eq!(bytes[2], 0xC3);
        assert_eq!(bytes[3], 0xD4);
    }

    #[test]
    fn test_advertisement_name() {
        let mut config = Config::default();
        config.set_peer_id("A1B2C3D4").unwrap();
        
        let ad_name = config.get_advertisement_name();
        assert_eq!(ad_name, "A1B2C3D4");
    }
}