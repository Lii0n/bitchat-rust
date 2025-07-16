// ==============================================================================
// crates/core/src/bluetooth/config.rs
// ==============================================================================

//! Bluetooth configuration for BitChat

use crate::bluetooth::constants::peer_id;
use std::time::Duration;

/// Configuration for Bluetooth operations
#[derive(Debug, Clone)]
pub struct BluetoothConfig {
    /// Device name for Bluetooth advertising (peer ID format)
    pub device_name: String,
    /// Peer ID in bytes  
    pub peer_id: [u8; 8],
    /// Maximum number of connections
    pub max_connections: usize,
    /// RSSI threshold for connections
    pub rssi_threshold: i16,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Scan interval
    pub scan_interval: Duration,
    /// Maximum retry attempts
    pub max_retry_attempts: u32,
    /// Retry backoff duration
    pub retry_backoff: Duration,
}

impl Default for BluetoothConfig {
    fn default() -> Self {
        let peer_id_string = peer_id::generate_random_peer_id();
        let peer_id_bytes = peer_id::string_to_bytes(&peer_id_string)
            .unwrap_or_else(|_| [0u8; 8]);

        Self {
            device_name: peer_id_string,
            peer_id: peer_id_bytes,
            max_connections: 8,
            rssi_threshold: -85,
            connection_timeout: Duration::from_secs(10),
            scan_interval: Duration::from_secs(5),
            max_retry_attempts: 3,
            retry_backoff: Duration::from_secs(60),
        }
    }
}

impl BluetoothConfig {
    /// Create new config with device name (builder pattern)
    pub fn with_device_name(device_name: String) -> Self {
        let peer_id_bytes = peer_id::string_to_bytes(&device_name)
            .unwrap_or_else(|_| [0u8; 8]);
        
        Self {
            device_name,
            peer_id: peer_id_bytes,
            max_connections: 8,
            rssi_threshold: -85,
            connection_timeout: Duration::from_secs(10),
            scan_interval: Duration::from_secs(5),
            max_retry_attempts: 3,
            retry_backoff: Duration::from_secs(60),
        }
    }
    
    /// Set device name on existing config
    pub fn set_device_name(&mut self, device_name: String) {
        self.device_name = device_name.clone();
        self.peer_id = peer_id::string_to_bytes(&device_name)
            .unwrap_or_else(|_| [0u8; 8]);
    }
    
    /// Set max connections
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }
    
    /// Set RSSI threshold
    pub fn with_rssi_threshold(mut self, rssi_threshold: i16) -> Self {
        self.rssi_threshold = rssi_threshold;
        self
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.device_name.is_empty() {
            return Err("Device name cannot be empty".to_string());
        }
        
        if !peer_id::is_valid_peer_id_string(&self.device_name) {
            return Err("Invalid device name format".to_string());
        }
        
        if self.max_connections == 0 {
            return Err("Max connections must be greater than 0".to_string());
        }
        
        Ok(())
    }
    
    /// Get advertisement name for Bluetooth
    pub fn advertisement_name(&self) -> String {
        format!("BC_{}", self.device_name)
    }
    
    /// Get peer ID as string
    pub fn peer_id_string(&self) -> String {
        peer_id::bytes_to_string(&self.peer_id)
    }
}