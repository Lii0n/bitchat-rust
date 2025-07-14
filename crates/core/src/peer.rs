//! Peer utility functions for BitChat protocol

use sha2::{Sha256, Digest};

/// Convert peer ID to short hex string (first 4 bytes)
pub fn short_peer_id(peer_id: &[u8; 8]) -> String {
    hex::encode(&peer_id[..4])
}

/// Convert peer ID to full hex string  
pub fn peer_id_to_string(peer_id: &[u8; 8]) -> String {
    hex::encode(peer_id)
}

/// Parse peer ID from hex string
pub fn string_to_peer_id(hex_str: &str) -> anyhow::Result<[u8; 8]> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 8 {
        return Err(anyhow::anyhow!("Invalid peer ID length: expected 8 bytes, got {}", bytes.len()));
    }
    let mut peer_id = [0u8; 8];
    peer_id.copy_from_slice(&bytes);
    Ok(peer_id)
}

/// Generate deterministic peer ID from device name
/// This ensures the same device always gets the same peer ID
pub fn peer_id_from_device_name(device_name: &str) -> [u8; 8] {
    let hash = Sha256::digest(device_name.as_bytes());
    let mut peer_id = [0u8; 8];
    peer_id.copy_from_slice(&hash[..8]);
    peer_id
}

/// Generate peer ID from arbitrary seed data
pub fn peer_id_from_seed(seed: &[u8]) -> [u8; 8] {
    let hash = Sha256::digest(seed);
    let mut peer_id = [0u8; 8];
    peer_id.copy_from_slice(&hash[..8]);
    peer_id
}

/// Validate that a peer ID is well-formed
pub fn is_valid_peer_id(peer_id: &[u8; 8]) -> bool {
    // Check that it's not all zeros (invalid)
    !peer_id.iter().all(|&b| b == 0)
}

/// Generate a human-readable nickname from a peer ID
pub fn peer_id_to_nickname(peer_id: &[u8; 8]) -> String {
    // Use the first 6 characters of the hex representation
    let hex = hex::encode(peer_id);
    format!("User_{}", &hex[..6].to_uppercase())
}

/// Check if two peer IDs are equal
pub fn peer_ids_equal(a: &[u8; 8], b: &[u8; 8]) -> bool {
    a == b
}

/// Calculate distance between two peer IDs (for routing algorithms)
pub fn peer_id_distance(a: &[u8; 8], b: &[u8; 8]) -> u64 {
    let mut distance = 0u64;
    for i in 0..8 {
        distance ^= (a[i] ^ b[i]) as u64;
        if i < 7 {
            distance <<= 8;
        }
    }
    distance
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_conversions() {
        let peer_id = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        
        // Test full hex conversion
        let hex_string = peer_id_to_string(&peer_id);
        assert_eq!(hex_string, "0123456789abcdef");
        
        // Test parsing back
        let parsed = string_to_peer_id(&hex_string).unwrap();
        assert_eq!(parsed, peer_id);
        
        // Test short ID
        let short_id = short_peer_id(&peer_id);
        assert_eq!(short_id, "01234567");
    }

    #[test]
    fn test_peer_id_from_device_name() {
        let device_name = "TestDevice";
        let peer_id1 = peer_id_from_device_name(device_name);
        let peer_id2 = peer_id_from_device_name(device_name);
        
        // Should be deterministic
        assert_eq!(peer_id1, peer_id2);
        assert_eq!(peer_id1.len(), 8);
        
        // Different names should produce different IDs
        let peer_id3 = peer_id_from_device_name("DifferentDevice");
        assert_ne!(peer_id1, peer_id3);
    }

    #[test]
    fn test_peer_id_validation() {
        let valid_peer_id = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let invalid_peer_id = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        assert!(is_valid_peer_id(&valid_peer_id));
        assert!(!is_valid_peer_id(&invalid_peer_id));
    }

    #[test]
    fn test_nickname_generation() {
        let peer_id = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let nickname = peer_id_to_nickname(&peer_id);
        assert_eq!(nickname, "User_012345");
    }

    #[test]
    fn test_peer_id_distance() {
        let peer_a = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let peer_b = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let peer_c = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        
        // Same peer IDs should have distance 0
        assert_eq!(peer_id_distance(&peer_a, &peer_b), 0);
        
        // Different peer IDs should have non-zero distance
        assert_ne!(peer_id_distance(&peer_a, &peer_c), 0);
        
        // Distance should be symmetric
        assert_eq!(peer_id_distance(&peer_a, &peer_c), peer_id_distance(&peer_c, &peer_a));
    }

    #[test]
    fn test_string_parsing_errors() {
        // Test invalid hex
        assert!(string_to_peer_id("invalid_hex").is_err());
        
        // Test wrong length
        assert!(string_to_peer_id("0123").is_err());
        assert!(string_to_peer_id("0123456789abcdef0123").is_err());
    }
}