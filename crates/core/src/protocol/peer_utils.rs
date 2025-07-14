// crates/core/src/protocol/peer_utils.rs
//! Utility functions for peer management and identification

use sha2::{Sha256, Digest};
use anyhow::Result;

/// Generate a peer ID from device name (deterministic)
pub fn peer_id_from_device_name(device_name: &str) -> [u8; 8] {
    let hash = Sha256::digest(device_name.as_bytes());
    let mut peer_id = [0u8; 8];
    peer_id.copy_from_slice(&hash[..8]);
    peer_id
}

/// Generate a peer ID from arbitrary seed data
pub fn peer_id_from_seed(seed: &[u8]) -> [u8; 8] {
    let hash = Sha256::digest(seed);
    let mut peer_id = [0u8; 8];
    peer_id.copy_from_slice(&hash[..8]);
    peer_id
}

/// Convert peer ID to hex string
pub fn peer_id_to_hex(peer_id: &[u8; 8]) -> String {
    hex::encode(peer_id).to_uppercase()
}

/// Parse peer ID from hex string
pub fn peer_id_from_hex(hex_str: &str) -> Result<[u8; 8]> {
    let bytes = hex::decode(hex_str)?;
    if bytes.len() != 8 {
        return Err(anyhow::anyhow!("Invalid peer ID length: expected 8 bytes, got {}", bytes.len()));
    }
    
    let mut peer_id = [0u8; 8];
    peer_id.copy_from_slice(&bytes);
    Ok(peer_id)
}

/// Generate a random peer ID (for testing or anonymous use)
pub fn generate_random_peer_id() -> [u8; 8] {
    use rand::RngCore;
    let mut peer_id = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut peer_id);
    peer_id
}

/// Validate peer ID format
pub fn is_valid_peer_id(peer_id: &[u8]) -> bool {
    peer_id.len() == 8 && !peer_id.iter().all(|&b| b == 0)
}

/// Create a short display name for a peer ID (first 4 hex chars)
pub fn peer_id_short_display(peer_id: &[u8; 8]) -> String {
    hex::encode(&peer_id[..2]).to_uppercase()
}

/// Check if two peer IDs are equal
pub fn peer_ids_equal(a: &[u8; 8], b: &[u8; 8]) -> bool {
    a == b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_from_device_name() {
        let peer_id1 = peer_id_from_device_name("test-device");
        let peer_id2 = peer_id_from_device_name("test-device");
        let peer_id3 = peer_id_from_device_name("different-device");
        
        assert_eq!(peer_id1, peer_id2); // Should be deterministic
        assert_ne!(peer_id1, peer_id3); // Different names should give different IDs
    }

    #[test]
    fn test_hex_conversion() {
        let peer_id = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let hex_str = peer_id_to_hex(&peer_id);
        assert_eq!(hex_str, "0123456789ABCDEF");
        
        let parsed = peer_id_from_hex(&hex_str).unwrap();
        assert_eq!(parsed, peer_id);
    }

    #[test]
    fn test_validation() {
        let valid_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let invalid_id = [0, 0, 0, 0, 0, 0, 0, 0];
        
        assert!(is_valid_peer_id(&valid_id));
        assert!(!is_valid_peer_id(&invalid_id));
    }
}