// ==============================================================================
// crates/core/src/bluetooth/constants.rs
// Bluetooth constants and UUIDs - FIXED for permissionlesstech/bitchat compatibility
// ==============================================================================

//! Bluetooth constants and protocol definitions
//! 
//! Contains UUIDs, service definitions, and other constants used in BitChat BLE operations.
//! UPDATED to match permissionlesstech/bitchat protocol specification.

use uuid::Uuid;

/// BitChat service and characteristic UUIDs - FIXED FOR COMPATIBILITY
pub mod service_uuids {
    use super::*;
    
    /// Main BitChat service UUID - CORRECTED to match permissionlesstech/bitchat
    /// OLD: 6E400001_B5A3_F393_E0A9_E50E24DCCA9E (Nordic UART - WRONG!)
    /// NEW: F47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5C (BitChat - CORRECT!)
    pub const BITCHAT_SERVICE: Uuid = Uuid::from_u128(0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5C);
    
    /// BitChat TX characteristic UUID (for sending data)
    pub const BITCHAT_TX_CHARACTERISTIC: Uuid = Uuid::from_u128(0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5D);
    
    /// BitChat RX characteristic UUID (for receiving data)
    pub const BITCHAT_RX_CHARACTERISTIC: Uuid = Uuid::from_u128(0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5E);
    
    /// Legacy support - keeping old names but with correct UUIDs
    pub const MESSAGE_CHARACTERISTIC: Uuid = BITCHAT_TX_CHARACTERISTIC;
    pub const CONTROL_CHARACTERISTIC: Uuid = BITCHAT_RX_CHARACTERISTIC;
    
    /// Additional characteristics for future expansion
    pub const DISCOVERY_CHARACTERISTIC: Uuid = Uuid::from_u128(0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5F);
    pub const CHANNEL_CHARACTERISTIC: Uuid = Uuid::from_u128(0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B60);
}

/// LEGACY: String constants for compatibility with windows.rs
pub const BITCHAT_SERVICE: &str = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C";
pub const BITCHAT_TX_CHARACTERISTIC: &str = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5D";
pub const BITCHAT_RX_CHARACTERISTIC: &str = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5E";

/// Standard Bluetooth UUIDs
pub mod standard_uuids {
    use super::*;
    
    /// Generic Access Profile service
    pub const GAP_SERVICE: Uuid = Uuid::from_u128(0x00001800_0000_1000_8000_00805F9B34FB);
    
    /// Device Name characteristic
    pub const DEVICE_NAME_CHARACTERISTIC: Uuid = Uuid::from_u128(0x00002A00_0000_1000_8000_00805F9B34FB);
    
    /// Appearance characteristic
    pub const APPEARANCE_CHARACTERISTIC: Uuid = Uuid::from_u128(0x00002A01_0000_1000_8000_00805F9B34FB);
    
    /// Generic Attribute Profile service
    pub const GATT_SERVICE: Uuid = Uuid::from_u128(0x00001801_0000_1000_8000_00805F9B34FB);
}

/// Protocol constants
pub mod protocol {
    /// Maximum BLE MTU size (most devices support this)
    pub const MAX_MTU_SIZE: usize = 512;
    
    /// Default MTU size for compatibility
    pub const DEFAULT_MTU_SIZE: usize = 244;
    
    /// Maximum message size before fragmentation
    pub const MAX_MESSAGE_SIZE: usize = 1024;
    
    /// Fragment header size
    pub const FRAGMENT_HEADER_SIZE: usize = 4;
    
    /// Maximum payload per fragment
    pub const MAX_FRAGMENT_PAYLOAD: usize = DEFAULT_MTU_SIZE - FRAGMENT_HEADER_SIZE;
    
    /// Protocol version (matching permissionlesstech/bitchat)
    pub const PROTOCOL_VERSION: u8 = 1;
    
    /// Magic bytes to identify BitChat packets (updated for compatibility)
    pub const MAGIC_BYTES: [u8; 2] = [0xBC, 0x01];
}

/// Timing constants
pub mod timing {
    use std::time::Duration;
    
    /// Default scan duration
    pub const DEFAULT_SCAN_DURATION: Duration = Duration::from_secs(5);
    
    /// Default advertising interval (iOS/macOS compatible)
    pub const DEFAULT_ADVERTISING_INTERVAL: Duration = Duration::from_millis(1000);
    
    /// Connection timeout
    pub const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
    
    /// Heartbeat interval (keep connections alive)
    pub const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(60);
    
    /// Peer discovery interval
    pub const DISCOVERY_INTERVAL: Duration = Duration::from_secs(10);
    
    /// Maximum time to wait for response
    pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);
    
    /// Reconnection delay after disconnect
    pub const RECONNECTION_DELAY: Duration = Duration::from_secs(5);
    
    /// Maximum reconnection attempts
    pub const MAX_RECONNECTION_ATTEMPTS: u32 = 3;
}

/// Device identification constants - UPDATED for iOS/macOS compatibility
pub mod device {
    /// Maximum device name length
    pub const MAX_DEVICE_NAME_LENGTH: usize = 31;
    
    /// Minimum device name length
    pub const MIN_DEVICE_NAME_LENGTH: usize = 3;
    
    /// Device ID length (hex characters) - iOS/macOS uses 16 hex chars
    pub const DEVICE_ID_LENGTH: usize = 16;
    
    /// DEPRECATED: BitChat device name prefix (iOS/macOS doesn't use prefix)
    pub const DEVICE_NAME_PREFIX: &str = "";
    
    /// Legacy Windows device name prefix (for backward compatibility)
    pub const LEGACY_DEVICE_NAME_PREFIX: &str = "BC_";
    
    /// Short device name prefix (for limited advertising space)
    pub const SHORT_NAME_PREFIX: &str = "BC_";
}

/// Power management constants
pub mod power {
    /// Battery level thresholds for power modes
    pub const BATTERY_CRITICAL: u8 = 10;
    pub const BATTERY_LOW: u8 = 30;
    pub const BATTERY_MEDIUM: u8 = 60;
    
    /// Power mode scan intervals (milliseconds)
    pub const PERFORMANCE_SCAN_INTERVAL: u16 = 100;
    pub const BALANCED_SCAN_INTERVAL: u16 = 200;
    pub const POWER_SAVER_SCAN_INTERVAL: u16 = 500;
    pub const ULTRA_LOW_POWER_SCAN_INTERVAL: u16 = 1000;
    
    /// Power mode connection intervals (milliseconds)
    pub const PERFORMANCE_CONNECTION_INTERVAL: u16 = 50;
    pub const BALANCED_CONNECTION_INTERVAL: u16 = 100;
    pub const POWER_SAVER_CONNECTION_INTERVAL: u16 = 200;
    pub const ULTRA_LOW_POWER_CONNECTION_INTERVAL: u16 = 500;
}

/// Error codes for BitChat protocol
pub mod error_codes {
    /// No error
    pub const NO_ERROR: u8 = 0x00;
    
    /// Unknown error
    pub const UNKNOWN_ERROR: u8 = 0x01;
    
    /// Invalid packet format
    pub const INVALID_PACKET: u8 = 0x02;
    
    /// Unsupported protocol version
    pub const UNSUPPORTED_VERSION: u8 = 0x03;
    
    /// Authentication failed
    pub const AUTH_FAILED: u8 = 0x04;
    
    /// Channel not found
    pub const CHANNEL_NOT_FOUND: u8 = 0x05;
    
    /// Permission denied
    pub const PERMISSION_DENIED: u8 = 0x06;
    
    /// Rate limit exceeded
    pub const RATE_LIMIT_EXCEEDED: u8 = 0x07;
    
    /// Buffer overflow
    pub const BUFFER_OVERFLOW: u8 = 0x08;
    
    /// Connection lost
    pub const CONNECTION_LOST: u8 = 0x09;
    
    /// Timeout
    pub const TIMEOUT: u8 = 0x0A;
}

/// Message types for BitChat protocol
pub mod message_types {
    /// Heartbeat/ping message
    pub const HEARTBEAT: u8 = 0x01;
    
    /// Text message
    pub const TEXT_MESSAGE: u8 = 0x02;
    
    /// Binary data
    pub const BINARY_DATA: u8 = 0x03;
    
    /// Channel join request
    pub const CHANNEL_JOIN: u8 = 0x04;
    
    /// Channel leave notification
    pub const CHANNEL_LEAVE: u8 = 0x05;
    
    /// Peer discovery announcement
    pub const PEER_DISCOVERY: u8 = 0x06;
    
    /// Authentication challenge
    pub const AUTH_CHALLENGE: u8 = 0x07;
    
    /// Authentication response
    pub const AUTH_RESPONSE: u8 = 0x08;
    
    /// Key exchange
    pub const KEY_EXCHANGE: u8 = 0x09;
    
    /// Encrypted message
    pub const ENCRYPTED_MESSAGE: u8 = 0x0A;
    
    /// File transfer start
    pub const FILE_TRANSFER_START: u8 = 0x0B;
    
    /// File transfer chunk
    pub const FILE_TRANSFER_CHUNK: u8 = 0x0C;
    
    /// File transfer end
    pub const FILE_TRANSFER_END: u8 = 0x0D;
    
    /// Status update
    pub const STATUS_UPDATE: u8 = 0x0E;
    
    /// Error notification
    pub const ERROR_NOTIFICATION: u8 = 0xFF;
}

/// Advertising data constants - UPDATED for BitChat compatibility
pub mod advertising {
    /// Maximum advertising data length
    pub const MAX_ADVERTISING_DATA_LENGTH: usize = 31;
    
    /// Maximum scan response data length
    pub const MAX_SCAN_RESPONSE_LENGTH: usize = 31;
    
    /// Company ID for BitChat manufacturer data (unassigned range)
    pub const BITCHAT_COMPANY_ID: u16 = 0xFFFF;
    
    /// Advertising flags
    pub const ADV_FLAGS: u8 = 0x06; // LE General Discoverable + BR/EDR Not Supported
    
    /// Service data prefix for BitChat
    pub const SERVICE_DATA_PREFIX: [u8; 2] = [0xBC, 0x01]; // BitChat v1
    
    /// Check if device name matches iOS/macOS BitChat format
    pub fn is_ios_macos_format(name: &str) -> bool {
        name.len() == 16 && name.chars().all(|c| c.is_ascii_hexdigit())
    }
    
    /// Check if device name matches Windows legacy format
    pub fn is_windows_legacy_format(name: &str) -> bool {
        name.starts_with("BC_") && name.len() == 19 && 
        name[3..].chars().all(|c| c.is_ascii_hexdigit())
    }
    
    /// Check if device name matches Pi format
    pub fn is_pi_format(name: &str) -> bool {
        if let Some(peer_part) = name.split('_').last() {
            peer_part.len() >= 8 && peer_part.chars().all(|c| c.is_ascii_hexdigit())
        } else {
            false
        }
    }
    
    /// Extract peer ID from any supported device name format
    pub fn extract_peer_id(device_name: &str) -> Option<String> {
        // iOS/macOS format: exactly 16 hex characters
        if is_ios_macos_format(device_name) {
            return Some(device_name.to_uppercase());
        }
        
        // Windows legacy format: BC_ + 16 hex chars
        if is_windows_legacy_format(device_name) {
            return Some(device_name[3..].to_uppercase());
        }
        
        // Pi format: anything_<hex chars>
        if is_pi_format(device_name) {
            if let Some(peer_part) = device_name.split('_').last() {
                let normalized = if peer_part.len() >= 16 {
                    peer_part.chars().take(16).collect::<String>()
                } else {
                    format!("{:0<16}", peer_part)
                };
                return Some(normalized.to_uppercase());
            }
        }
        
        None
    }
}

/// Connection parameters
pub mod connection {
    /// Minimum connection interval (7.5ms units)
    pub const MIN_CONNECTION_INTERVAL: u16 = 6; // 7.5ms
    
    /// Maximum connection interval (7.5ms units)  
    pub const MAX_CONNECTION_INTERVAL: u16 = 800; // 1000ms
    
    /// Slave latency (number of connection events)
    pub const SLAVE_LATENCY: u16 = 0;
    
    /// Supervision timeout (10ms units)
    pub const SUPERVISION_TIMEOUT: u16 = 400; // 4000ms
    
    /// Minimum CE length (0.625ms units)
    pub const MIN_CE_LENGTH: u16 = 0;
    
    /// Maximum CE length (0.625ms units)
    pub const MAX_CE_LENGTH: u16 = 0xFFFF;
}

/// Security constants
pub mod security {
    /// Minimum encryption key size
    pub const MIN_KEY_SIZE: u8 = 16;
    
    /// Maximum encryption key size
    pub const MAX_KEY_SIZE: u8 = 16;
    
    /// Authentication timeout
    pub const AUTH_TIMEOUT_SECONDS: u64 = 30;
    
    /// Maximum failed authentication attempts
    pub const MAX_AUTH_ATTEMPTS: u32 = 3;
    
    /// Authentication retry delay
    pub const AUTH_RETRY_DELAY_SECONDS: u64 = 5;
}

/// Peer ID utilities and constants - UPDATED for 16-char hex format
pub mod peer_id {
    /// Length of peer ID string (16 hex characters = 8 bytes) - iOS/macOS standard
    pub const PEER_ID_STRING_LENGTH: usize = 16;
    
    /// Check if a peer ID string is valid format
    pub fn is_valid_peer_id_string(peer_id: &str) -> bool {
        peer_id.len() == PEER_ID_STRING_LENGTH && 
        peer_id.chars().all(|c| c.is_ascii_hexdigit())
    }
    
    /// Generate a random peer ID string (iOS/macOS compatible)
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
            return Err(format!("Invalid peer ID length: expected 8 bytes, got {}", decoded.len()));
        }
        
        let mut result = [0u8; 8];
        result.copy_from_slice(&decoded);
        Ok(result)
    }
}

/// Helper functions for working with UUIDs
pub mod service_uuid_helpers {
    use super::service_uuids;
    use uuid::Uuid;
    
    /// Check if a UUID belongs to BitChat services
    pub fn is_bitchat_service(uuid: &Uuid) -> bool {
        *uuid == service_uuids::BITCHAT_SERVICE
    }
    
    /// Check if a UUID is a BitChat characteristic
    pub fn is_bitchat_characteristic(uuid: &Uuid) -> bool {
        matches!(*uuid, 
            service_uuids::BITCHAT_TX_CHARACTERISTIC |
            service_uuids::BITCHAT_RX_CHARACTERISTIC |
            service_uuids::MESSAGE_CHARACTERISTIC |
            service_uuids::CONTROL_CHARACTERISTIC |
            service_uuids::DISCOVERY_CHARACTERISTIC |
            service_uuids::CHANNEL_CHARACTERISTIC
        )
    }
    
    /// Get characteristic name from UUID
    pub fn characteristic_name(uuid: &Uuid) -> Option<&'static str> {
        match *uuid {
            service_uuids::BITCHAT_TX_CHARACTERISTIC => Some("BitChat TX"),
            service_uuids::BITCHAT_RX_CHARACTERISTIC => Some("BitChat RX"),
            service_uuids::MESSAGE_CHARACTERISTIC => Some("Message"),
            service_uuids::CONTROL_CHARACTERISTIC => Some("Control"),
            service_uuids::DISCOVERY_CHARACTERISTIC => Some("Discovery"),
            service_uuids::CHANNEL_CHARACTERISTIC => Some("Channel"),
            _ => None,
        }
    }
    
    /// Get all BitChat characteristic UUIDs
    pub fn get_all_characteristics() -> Vec<Uuid> {
        vec![
            service_uuids::BITCHAT_TX_CHARACTERISTIC,
            service_uuids::BITCHAT_RX_CHARACTERISTIC,
            service_uuids::DISCOVERY_CHARACTERISTIC,
            service_uuids::CHANNEL_CHARACTERISTIC,
        ]
    }
    
    /// Validate a service UUID for BitChat compatibility
    pub fn validate_service_uuid(uuid: &Uuid) -> Result<(), String> {
        if is_bitchat_service(uuid) {
            Ok(())
        } else {
            Err(format!("Invalid BitChat service UUID: {} (expected {})", 
                       uuid, service_uuids::BITCHAT_SERVICE))
        }
    }
    
    /// Validate a characteristic UUID for BitChat compatibility
    pub fn validate_characteristic_uuid(uuid: &Uuid) -> Result<(), String> {
        if is_bitchat_characteristic(uuid) {
            Ok(())
        } else {
            Err(format!("Invalid BitChat characteristic UUID: {}", uuid))
        }
    }
}

/// Helper functions for message types
pub mod message_type_helpers {
    use super::message_types;
    
    /// Check if message type is valid
    pub fn is_valid(msg_type: u8) -> bool {
        matches!(msg_type,
            message_types::HEARTBEAT |
            message_types::TEXT_MESSAGE |
            message_types::BINARY_DATA |
            message_types::CHANNEL_JOIN |
            message_types::CHANNEL_LEAVE |
            message_types::PEER_DISCOVERY |
            message_types::AUTH_CHALLENGE |
            message_types::AUTH_RESPONSE |
            message_types::KEY_EXCHANGE |
            message_types::ENCRYPTED_MESSAGE |
            message_types::FILE_TRANSFER_START |
            message_types::FILE_TRANSFER_CHUNK |
            message_types::FILE_TRANSFER_END |
            message_types::STATUS_UPDATE |
            message_types::ERROR_NOTIFICATION
        )
    }
    
    /// Get message type name
    pub fn name(msg_type: u8) -> &'static str {
        match msg_type {
            message_types::HEARTBEAT => "Heartbeat",
            message_types::TEXT_MESSAGE => "Text Message",
            message_types::BINARY_DATA => "Binary Data",
            message_types::CHANNEL_JOIN => "Channel Join",
            message_types::CHANNEL_LEAVE => "Channel Leave",
            message_types::PEER_DISCOVERY => "Peer Discovery",
            message_types::AUTH_CHALLENGE => "Auth Challenge",
            message_types::AUTH_RESPONSE => "Auth Response",
            message_types::KEY_EXCHANGE => "Key Exchange",
            message_types::ENCRYPTED_MESSAGE => "Encrypted Message",
            message_types::FILE_TRANSFER_START => "File Transfer Start",
            message_types::FILE_TRANSFER_CHUNK => "File Transfer Chunk",
            message_types::FILE_TRANSFER_END => "File Transfer End",
            message_types::STATUS_UPDATE => "Status Update",
            message_types::ERROR_NOTIFICATION => "Error Notification",
            _ => "Unknown",
        }
    }
    
    /// Get all valid message types
    pub fn get_all_types() -> Vec<u8> {
        vec![
            message_types::HEARTBEAT,
            message_types::TEXT_MESSAGE,
            message_types::BINARY_DATA,
            message_types::CHANNEL_JOIN,
            message_types::CHANNEL_LEAVE,
            message_types::PEER_DISCOVERY,
            message_types::AUTH_CHALLENGE,
            message_types::AUTH_RESPONSE,
            message_types::KEY_EXCHANGE,
            message_types::ENCRYPTED_MESSAGE,
            message_types::FILE_TRANSFER_START,
            message_types::FILE_TRANSFER_CHUNK,
            message_types::FILE_TRANSFER_END,
            message_types::STATUS_UPDATE,
            message_types::ERROR_NOTIFICATION,
        ]
    }
    
    /// Check if message type requires encryption
    pub fn requires_encryption(msg_type: u8) -> bool {
        matches!(msg_type,
            message_types::TEXT_MESSAGE |
            message_types::BINARY_DATA |
            message_types::FILE_TRANSFER_START |
            message_types::FILE_TRANSFER_CHUNK |
            message_types::FILE_TRANSFER_END
        )
    }
    
    /// Check if message type is for control/management
    pub fn is_control_message(msg_type: u8) -> bool {
        matches!(msg_type,
            message_types::HEARTBEAT |
            message_types::CHANNEL_JOIN |
            message_types::CHANNEL_LEAVE |
            message_types::PEER_DISCOVERY |
            message_types::AUTH_CHALLENGE |
            message_types::AUTH_RESPONSE |
            message_types::KEY_EXCHANGE |
            message_types::STATUS_UPDATE |
            message_types::ERROR_NOTIFICATION
        )
    }
}

/// Protocol validation helpers
pub mod validation {
    use super::*;
    
    /// Validate protocol version
    pub fn validate_protocol_version(version: u8) -> Result<(), String> {
        if version == protocol::PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(format!("Unsupported protocol version: {} (expected {})", 
                       version, protocol::PROTOCOL_VERSION))
        }
    }
    
    /// Validate magic bytes
    pub fn validate_magic_bytes(bytes: &[u8; 2]) -> Result<(), String> {
        if bytes == &protocol::MAGIC_BYTES {
            Ok(())
        } else {
            Err(format!("Invalid magic bytes: {:?} (expected {:?})", 
                       bytes, protocol::MAGIC_BYTES))
        }
    }
    
    /// Validate device name format (iOS/macOS priority)
    pub fn validate_device_name(name: &str) -> Result<(), String> {
        // Check iOS/macOS format first (16 hex chars)
        if advertising::is_ios_macos_format(name) {
            return Ok(());
        }
        
        // Check Windows legacy format
        if advertising::is_windows_legacy_format(name) {
            return Ok(());
        }
        
        // Check Pi format
        if advertising::is_pi_format(name) {
            return Ok(());
        }
        
        // If none match, apply general validation
        if name.len() < device::MIN_DEVICE_NAME_LENGTH {
            return Err(format!("Device name too short: {} (minimum {})", 
                              name.len(), device::MIN_DEVICE_NAME_LENGTH));
        }
        
        if name.len() > device::MAX_DEVICE_NAME_LENGTH {
            return Err(format!("Device name too long: {} (maximum {})", 
                              name.len(), device::MAX_DEVICE_NAME_LENGTH));
        }
        
        Ok(())
    }
}