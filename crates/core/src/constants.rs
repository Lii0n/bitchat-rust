//! Global constants for BitChat

use uuid::Uuid;
use std::time::Duration;

/// Service UUIDs for BitChat Bluetooth communication
pub mod service_uuids {
    use super::*;
    
    /// Primary BitChat service UUID
    pub const BITCHAT_SERVICE: Uuid = uuid::uuid!("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");
    
    /// BitChat characteristic UUID for data exchange
    pub const BITCHAT_CHARACTERISTIC: Uuid = uuid::uuid!("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D");
}

/// Bluetooth connection constants
pub mod bluetooth {
    use super::*;
    
    /// Maximum number of simultaneous connections
    pub const MAX_CONNECTIONS: usize = 8;
    
    /// RSSI threshold for connections (-85 dBm)
    pub const RSSI_THRESHOLD: i16 = -85;
    
    /// Connection timeout
    pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(10);
    
    /// Scan interval
    pub const SCAN_INTERVAL: Duration = Duration::from_secs(5);
    
    /// Maximum connection retry attempts
    pub const MAX_RETRY_ATTEMPTS: u32 = 3;
    
    /// Retry backoff time
    pub const RETRY_BACKOFF: Duration = Duration::from_secs(60);
}

/// Protocol version and limits
pub mod protocol {
    /// Current protocol version
    pub const VERSION: u8 = 1;
    
    /// Maximum packet size (bytes)
    pub const MAX_PACKET_SIZE: usize = 512;
    
    /// Maximum payload size (bytes)  
    pub const MAX_PAYLOAD_SIZE: usize = 400;
    
    /// Maximum TTL (time-to-live) hops
    pub const MAX_TTL: u8 = 7;
}