// ==============================================================================
// crates/core/src/bluetooth/constants.rs  
// ==============================================================================

//! Constants for BitChat Bluetooth operations

use uuid::Uuid;
use std::time::Duration;

/// Service UUIDs for BitChat
pub mod service_uuids {
    use super::*;
    
    /// Primary BitChat service UUID
    pub const BITCHAT_SERVICE: Uuid = uuid::uuid!("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");
    
    /// BitChat characteristic UUID for data exchange  
    pub const BITCHAT_CHARACTERISTIC: Uuid = uuid::uuid!("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D");
}

/// Connection-related constants
pub mod connection {
    use super::*;
    
    /// Maximum number of simultaneous connections
    pub const MAX_CONNECTIONS: usize = 8;
    
    /// RSSI threshold for connections (-85 dBm)  
    pub const RSSI_THRESHOLD: i16 = -85;
    
    /// Connection timeout
    pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
    
    /// Maximum connection retry attempts
    pub const MAX_RETRY_ATTEMPTS: u32 = 3;
    
    /// Retry backoff time
    pub const RETRY_BACKOFF: Duration = Duration::from_secs(60);
    
    /// Keepalive interval
    pub const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
}

/// Scanning constants
pub mod scanning {
    use super::*;
    
    /// Scan interval
    pub const SCAN_INTERVAL: Duration = Duration::from_secs(5);
}

/// Peer ID utilities and constants
pub mod peer_id {
    /// Length of peer ID string (16 hex characters = 8 bytes)
    pub const PEER_ID_STRING_LENGTH: usize = 16;
    
    /// Check if a peer ID string is valid format
    pub fn is_valid_peer_id_string(peer_id: &str) -> bool {
        peer_id.len() == PEER_ID_STRING_LENGTH && 
        peer_id.chars().all(|c| c.is_ascii_hexdigit())
    }
    
    /// Generate a random peer ID string
    pub fn generate_random_peer_id() -> String {
        use rand::RngCore;
        let mut bytes = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut bytes);
        hex::encode(bytes).to_uppercase()
    }
    
    /// Convert peer ID bytes to string
    pub fn bytes_to_string(bytes: &[u8; 8]) -> String {
        hex::encode(bytes).to_uppercase()
    }
    
    /// Convert peer ID string to bytes
    pub fn string_to_bytes(peer_id: &str) -> Result<[u8; 8], String> {
        if !is_valid_peer_id_string(peer_id) {
            return Err(format!("Invalid peer ID format: {}", peer_id));
        }
        
        let decoded = hex::decode(peer_id)
            .map_err(|e| format!("Failed to decode peer ID: {}", e))?;
        
        if decoded.len() != 8 {
            return Err(format!("Peer ID must be 8 bytes, got {}", decoded.len()));
        }
        
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&decoded);
        Ok(bytes)
    }
}