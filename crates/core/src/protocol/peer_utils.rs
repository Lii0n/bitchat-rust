// Replace crates/core/src/protocol/peer_utils.rs

//! Peer utility functions compatible with iOS/Android BitChat
//! 
//! iOS/Android use 8-character UPPERCASE hex strings as both peer IDs and device names
//! for Bluetooth advertisement. This module ensures compatibility.

use sha2::{Sha256, Digest};
use anyhow::Result;
use rand::RngCore;

/// Generate a peer ID compatible with iOS/Android (8 hex characters, uppercase)
/// This creates a random 4-byte value encoded as 8 uppercase hex characters
pub fn generate_compatible_peer_id() -> String {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 4];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes).to_uppercase()
}

/// Generate deterministic peer ID from device identifier
/// For consistency across app restarts, derive from stable device info
pub fn peer_id_from_device_info(device_info: &str) -> String {
    let hash = Sha256::digest(device_info.as_bytes());
    // Take first 4 bytes and encode as 8 hex characters (uppercase)
    hex::encode(&hash[..4]).to_uppercase()
}

/// Convert between internal [u8; 8] format and iOS/Android string format
pub fn bytes_to_peer_id_string(bytes: &[u8; 8]) -> String {
    // iOS/Android only use first 4 bytes as the peer ID
    hex::encode(&bytes[..4]).to_uppercase()
}

/// Convert iOS/Android peer ID string to internal [u8; 8] format
pub fn peer_id_string_to_bytes(peer_id: &str) -> Result<[u8; 8]> {
    if peer_id.len() != 8 {
        return Err(anyhow::anyhow!("Peer ID must be exactly 8 hex characters, got {}", peer_id.len()));
    }
    
    // Validate hex characters
    if !peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!("Peer ID must contain only hex characters"));
    }
    
    // Decode first 4 bytes from hex
    let decoded = hex::decode(peer_id)?;
    if decoded.len() != 4 {
        return Err(anyhow::anyhow!("Invalid hex decode length"));
    }
    
    // Convert to [u8; 8] format (pad with zeros)
    let mut bytes = [0u8; 8];
    bytes[..4].copy_from_slice(&decoded);
    
    Ok(bytes)
}

/// Generate deterministic peer ID from device name (DEPRECATED - use peer_id_from_device_info)
/// This ensures the same device always gets the same peer ID
pub fn peer_id_from_device_name(device_name: &str) -> [u8; 8] {
    // Convert to iOS/Android compatible format first
    let peer_id_string = peer_id_from_device_info(device_name);
    peer_id_string_to_bytes(&peer_id_string).unwrap_or([0u8; 8])
}

/// Extract peer ID from Bluetooth device name (iOS/Android format)
pub fn extract_peer_id_from_device_name(device_name: &str) -> Option<String> {
    // iOS/Android use the peer ID directly as the device name
    if device_name.len() == 8 && device_name.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(device_name.to_uppercase())
    } else {
        None
    }
}

/// Check if peer ID string is valid iOS/Android format
pub fn is_valid_peer_id_string(peer_id: &str) -> bool {
    peer_id.len() == 8 && peer_id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Validate that a peer ID byte array is well-formed
pub fn is_valid_peer_id_bytes(peer_id: &[u8; 8]) -> bool {
    // Check that first 4 bytes are not all zeros (the actual peer ID part)
    !peer_id[..4].iter().all(|&b| b == 0)
}

/// Convert internal [u8; 8] peer ID to hex string for display
pub fn peer_id_to_hex_string(peer_id: &[u8; 8]) -> String {
    hex::encode(peer_id).to_uppercase()
}

/// Parse peer ID from full 16-character hex string
pub fn peer_id_from_hex_string(hex_str: &str) -> Result<[u8; 8]> {
    if hex_str.len() != 16 {
        return Err(anyhow::anyhow!("Hex string must be exactly 16 characters"));
    }
    
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 8 {
        return Err(anyhow::anyhow!("Invalid hex decode length"));
    }
    
    let mut peer_id = [0u8; 8];
    peer_id.copy_from_slice(&bytes);
    Ok(peer_id)
}

/// Generate a random peer ID in internal [u8; 8] format
pub fn generate_random_peer_id_bytes() -> [u8; 8] {
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 8];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// Compare two peer IDs for connection arbitration (iOS/Android compatible)
/// Returns true if local_peer_id should initiate connection to remote_peer_id
pub fn should_initiate_connection(local_peer_id: &str, remote_peer_id: &str) -> bool {
    // Use lexicographic comparison on the 8-character hex strings
    // Lower peer ID connects to higher peer ID
    local_peer_id < remote_peer_id
}

/// Generate a short display name for a peer ID
pub fn peer_id_to_short_display(peer_id: &str) -> String {
    if peer_id.len() >= 4 {
        peer_id[..4].to_string()
    } else {
        peer_id.to_string()
    }
}

/// Generate a human-readable nickname from a peer ID string
pub fn peer_id_to_nickname(peer_id: &str) -> String {
    if peer_id.len() >= 6 {
        format!("User_{}", &peer_id[..6])
    } else {
        format!("User_{}", peer_id)
    }
}

/// Generate device name for Bluetooth advertisement (iOS/Android compatible)
pub fn create_advertisement_name(peer_id: &str) -> String {
    // iOS/Android use the 8-character peer ID directly as the device name
    peer_id.to_uppercase()
}

pub fn is_valid_peer_id(peer_id: &[u8; 8]) -> bool {
    is_valid_peer_id_bytes(peer_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compatible_peer_id_generation() {
        let peer_id = generate_compatible_peer_id();
        assert_eq!(peer_id.len(), 8);
        assert!(peer_id.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(peer_id.chars().all(|c| c.is_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn test_peer_id_from_device_info() {
        let peer_id1 = peer_id_from_device_info("test-device");
        let peer_id2 = peer_id_from_device_info("test-device");
        let peer_id3 = peer_id_from_device_info("different-device");
        
        assert_eq!(peer_id1, peer_id2); // Should be deterministic
        assert_ne!(peer_id1, peer_id3); // Different inputs should give different IDs
        assert_eq!(peer_id1.len(), 8);
    }

    #[test]
    fn test_string_bytes_conversion() {
        let peer_id_str = "A1B2C3D4";
        let bytes = peer_id_string_to_bytes(&peer_id_str).unwrap();
        let converted_back = bytes_to_peer_id_string(&bytes);
        
        assert_eq!(converted_back, peer_id_str);
        assert_eq!(bytes[0], 0xA1);
        assert_eq!(bytes[1], 0xB2);
        assert_eq!(bytes[2], 0xC3);
        assert_eq!(bytes[3], 0xD4);
        assert_eq!(bytes[4], 0x00); // Padded with zeros
    }

    #[test]
    fn test_extract_peer_id_from_device_name() {
        assert_eq!(extract_peer_id_from_device_name("A1B2C3D4"), Some("A1B2C3D4".to_string()));
        assert_eq!(extract_peer_id_from_device_name("12345678"), Some("12345678".to_string()));
        assert_eq!(extract_peer_id_from_device_name("invalid"), None);
        assert_eq!(extract_peer_id_from_device_name("A1B2C3D4E5"), None); // Too long
        assert_eq!(extract_peer_id_from_device_name("A1B2C3"), None); // Too short
    }

    #[test]
    fn test_connection_arbitration() {
        assert!(should_initiate_connection("A1234567", "B1234567")); // A < B
        assert!(!should_initiate_connection("B1234567", "A1234567")); // B > A
        assert!(!should_initiate_connection("A1234567", "A1234567")); // Equal
    }

    #[test]
    fn test_validation() {
        assert!(is_valid_peer_id_string("A1B2C3D4"));
        assert!(is_valid_peer_id_string("12345678"));
        assert!(!is_valid_peer_id_string("invalid"));
        assert!(!is_valid_peer_id_string("A1B2C3D")); // Too short
        
        let valid_bytes = peer_id_string_to_bytes("A1B2C3D4").unwrap();
        let invalid_bytes = [0u8; 8];
        
        assert!(is_valid_peer_id_bytes(&valid_bytes));
        assert!(!is_valid_peer_id_bytes(&invalid_bytes));
    }

    #[test]
    fn test_advertisement_name() {
        let peer_id = "A1B2C3D4";
        let ad_name = create_advertisement_name(peer_id);
        assert_eq!(ad_name, "A1B2C3D4");
    }

    #[test]
    fn test_case_insensitive_input() {
        let result = peer_id_string_to_bytes("a1b2c3d4").unwrap();
        let expected = peer_id_string_to_bytes("A1B2C3D4").unwrap();
        assert_eq!(result, expected);
    }
}