// Create crates/core/src/bluetooth/config.rs (this file was missing)

//! Bluetooth configuration compatible with iOS/Android BitChat

use serde::{Deserialize, Serialize};
use crate::protocol::peer_utils;

/// Bluetooth configuration for BitChat mesh networking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothConfig {
    /// 8-byte peer identifier used in binary protocol
    pub peer_id: [u8; 8],
    
    /// Device name for Bluetooth advertisement (8-character hex)
    pub device_name: String,
    
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    
    /// Scan interval in milliseconds
    pub scan_interval_ms: u64,
    
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    
    /// RSSI threshold for connections (-85 dBm like iOS)
    pub rssi_threshold: i16,
    
    /// Enable debug logging
    pub debug_logging: bool,
}

impl Default for BluetoothConfig {
    fn default() -> Self {
        // Generate iOS/Android compatible peer ID
        let peer_id_string = peer_utils::generate_compatible_peer_id();
        let peer_id_bytes = peer_utils::peer_id_string_to_bytes(&peer_id_string)
            .expect("Generated peer ID should be valid");
        
        Self {
            peer_id: peer_id_bytes,
            device_name: peer_id_string,
            max_connections: 8,
            scan_interval_ms: 5000,
            connection_timeout_secs: 10,
            rssi_threshold: -85,
            debug_logging: true,
        }
    }
}

impl BluetoothConfig {
    /// Create config with custom device name (deterministic)
    pub fn with_device_name(device_name: String) -> Self {
        let peer_id_string = peer_utils::peer_id_from_device_info(&device_name);
        let peer_id_bytes = peer_utils::peer_id_string_to_bytes(&peer_id_string)
            .expect("Generated peer ID should be valid");
        
        Self {
            peer_id: peer_id_bytes,
            device_name: peer_id_string,
            ..Default::default()
        }
    }
    
    /// Create config with specific peer ID
    pub fn with_peer_id(peer_id_string: &str) -> Result<Self, String> {
        if !peer_utils::is_valid_peer_id_string(peer_id_string) {
            return Err(format!("Invalid peer ID format: {}", peer_id_string));
        }
        
        let peer_id_bytes = peer_utils::peer_id_string_to_bytes(peer_id_string)
            .map_err(|e| e.to_string())?;
        
        Ok(Self {
            peer_id: peer_id_bytes,
            device_name: peer_id_string.to_uppercase(),
            ..Default::default()
        })
    }
    
    /// Get peer ID as string for iOS/Android compatibility
    pub fn get_peer_id_string(&self) -> String {
        peer_utils::bytes_to_peer_id_string(&self.peer_id)
    }
    
    /// Get Bluetooth advertisement name
    pub fn get_advertisement_name(&self) -> String {
        peer_utils::create_advertisement_name(&self.device_name)
    }
    
    /// Update connection limits for performance tuning
    pub fn with_connection_limits(mut self, max_connections: usize, scan_interval_ms: u64) -> Self {
        self.max_connections = max_connections;
        self.scan_interval_ms = scan_interval_ms;
        self
    }
    
    /// Update RSSI threshold for range control
    pub fn with_rssi_threshold(mut self, threshold: i16) -> Self {
        self.rssi_threshold = threshold;
        self
    }
    
    /// Enable or disable debug logging
    pub fn with_debug_logging(mut self, enabled: bool) -> Self {
        self.debug_logging = enabled;
        self
    }
    
    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if !peer_utils::is_valid_peer_id_bytes(&self.peer_id) {
            return Err("Invalid peer ID bytes".to_string());
        }
        
        if !peer_utils::is_valid_peer_id_string(&self.device_name) {
            return Err("Invalid device name format".to_string());
        }
        
        if self.max_connections == 0 {
            return Err("Max connections must be greater than 0".to_string());
        }
        
        if self.scan_interval_ms < 1000 {
            return Err("Scan interval must be at least 1 second".to_string());
        }
        
        if self.rssi_threshold > -20 {
            return Err("RSSI threshold too high (should be around -85)".to_string());
        }
        
        Ok(())
    }
}