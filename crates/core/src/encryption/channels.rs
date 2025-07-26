// ==============================================================================
// crates/core/src/encryption/channels.rs - Channel Encryption
// ==============================================================================

//! Password-protected channel encryption for BitChat
//! 
//! This module handles encryption for group channels using password-derived keys.
//! Uses Argon2id for password hashing and ChaCha20-Poly1305 for encryption.

use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},  // Removed AeadCore since it's unused
    ChaCha20Poly1305, Nonce, Key
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, Algorithm, Version, Params};
use argon2::password_hash::{rand_core::RngCore, PasswordHashString, SaltString};
use std::collections::HashMap;
use anyhow::{Result, anyhow};
use tracing::{debug, warn, info};

// ==============================================================================
// CHANNEL ENCRYPTION MANAGER
// ==============================================================================

/// Manages encryption for password-protected channels
#[derive(Debug)]
pub struct ChannelEncryption {
    /// Active channel ciphers by channel name
    channel_ciphers: HashMap<String, ChannelCipher>,
    
    /// Argon2 configuration for password hashing
    argon2: Argon2<'static>,
    
    /// Channel statistics
    stats: ChannelStats,
}

/// Individual channel cipher state
struct ChannelCipher {  // Removed Debug derive since ChaCha20Poly1305 doesn't implement Debug
    /// Channel name
    name: String,
    
    /// Encryption cipher
    cipher: ChaCha20Poly1305,
    
    /// Password hash for verification
    password_hash: PasswordHashString,
    
    /// Salt used for key derivation
    salt: SaltString,
    
    /// Message counter for nonce generation
    message_counter: u64,
    
    /// When this channel was joined
    joined_at: std::time::Instant,
    
    /// Number of messages encrypted/decrypted
    message_count: u64,
}

// Manual Debug implementation for ChannelCipher
impl std::fmt::Debug for ChannelCipher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChannelCipher")
            .field("name", &self.name)
            .field("message_counter", &self.message_counter)
            .field("joined_at", &self.joined_at)
            .field("message_count", &self.message_count)
            .finish_non_exhaustive() // Hides the cipher field
    }
}

/// Channel encryption statistics
#[derive(Debug, Clone, Default)]
pub struct ChannelStats {
    pub active_channels: usize,
    pub total_messages: u64,
    pub total_encrypted: u64,
    pub total_decrypted: u64,
}

impl ChannelEncryption {
    /// Create new channel encryption manager
    pub fn new() -> Self {
        // Configure Argon2 with secure parameters
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(32 * 1024, 3, 1, Some(32)).unwrap(), // 32MB memory, 3 iterations, 1 thread
        );
        
        Self {
            channel_ciphers: HashMap::new(),
            argon2,
            stats: ChannelStats::default(),
        }
    }
    
    /// Join a password-protected channel
    pub fn join_channel(&mut self, channel_name: &str, password: &str) -> Result<()> {
        if self.channel_ciphers.contains_key(channel_name) {
            return Err(anyhow!("Already joined channel: {}", channel_name));
        }
        
        // Generate salt for this channel
        let salt = SaltString::generate(&mut OsRng);
        
        // Derive key from password using Argon2
        let password_hash = self.argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow!("Password hashing failed: {}", e))?;
        
        // Extract derived key for encryption
        let hash = password_hash.hash.ok_or_else(|| anyhow!("No hash in password"))?;
        let key_bytes = hash.as_bytes();
        
        if key_bytes.len() < 32 {
            return Err(anyhow!("Derived key too short: {} bytes", key_bytes.len()));
        }
        
        let key = Key::clone_from_slice(&key_bytes[..32]);
        let cipher = ChaCha20Poly1305::new(&key);
        
        // Create channel cipher
        let channel_cipher = ChannelCipher {
            name: channel_name.to_string(),
            cipher,
            password_hash: password_hash.serialize(),
            salt,
            message_counter: 0,
            joined_at: std::time::Instant::now(),
            message_count: 0,
        };
        
        self.channel_ciphers.insert(channel_name.to_string(), channel_cipher);
        self.update_stats();
        
        info!("🔐 Joined password-protected channel: {}", channel_name);
        Ok(())
    }
    
    /// Leave a channel
    pub fn leave_channel(&mut self, channel_name: &str) {
        if self.channel_ciphers.remove(channel_name).is_some() {
            self.update_stats();
            info!("🚪 Left channel: {}", channel_name);
        } else {
            warn!("Attempted to leave channel not joined: {}", channel_name);
        }
    }
    
    /// Encrypt message for channel
    pub fn encrypt_channel_message(&mut self, channel_name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let channel_cipher = self.channel_ciphers.get_mut(channel_name)
            .ok_or_else(|| anyhow!("Not joined to channel: {}", channel_name))?;
        
        // Get the message counter before generating nonce to avoid borrow issues
        let message_counter = channel_cipher.message_counter;
        
        // Generate nonce from message counter (now a static method)
        let nonce = Self::generate_nonce(message_counter);
        
        // Encrypt message
        let ciphertext = channel_cipher.cipher.encrypt(&nonce, plaintext)
            .map_err(|_| anyhow!("Channel encryption failed for: {}", channel_name))?;
        
        // Update counters
        channel_cipher.message_counter += 1;
        channel_cipher.message_count += 1;
        self.stats.total_encrypted += 1;
        self.stats.total_messages += 1;
        
        // Prepend nonce to ciphertext for transmission
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        
        debug!("🔒 Encrypted message for channel: {} ({} bytes)", channel_name, result.len());
        Ok(result)
    }
    
    /// Decrypt message from channel
    pub fn decrypt_channel_message(&mut self, channel_name: &str, data: &[u8]) -> Result<Vec<u8>> {
        let channel_cipher = self.channel_ciphers.get_mut(channel_name)
            .ok_or_else(|| anyhow!("Not joined to channel: {}", channel_name))?;
        
        if data.len() < 12 {
            return Err(anyhow!("Channel message too short: {} bytes", data.len()));
        }
        
        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&data[..12]);
        let ciphertext = &data[12..];
        
        // Decrypt message
        let plaintext = channel_cipher.cipher.decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("Channel decryption failed for: {}", channel_name))?;
        
        // Update counters
        channel_cipher.message_count += 1;
        self.stats.total_decrypted += 1;
        self.stats.total_messages += 1;
        
        debug!("🔓 Decrypted message from channel: {} ({} bytes)", channel_name, plaintext.len());
        Ok(plaintext)
    }
    
    /// Verify channel password
    pub fn verify_channel_password(&self, channel_name: &str, password: &str) -> Result<bool> {
        let channel_cipher = self.channel_ciphers.get(channel_name)
            .ok_or_else(|| anyhow!("Not joined to channel: {}", channel_name))?;
        
        // Convert PasswordHashString to &str for PasswordHash::new
        let password_hash_str = channel_cipher.password_hash.as_str();
        let parsed_hash = PasswordHash::new(password_hash_str)
            .map_err(|e| anyhow!("Failed to parse password hash: {}", e))?;
        
        Ok(self.argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
    }
    
    /// Get list of joined channels
    pub fn get_joined_channels(&self) -> Vec<String> {
        self.channel_ciphers.keys().cloned().collect()
    }
    
    /// Check if joined to a specific channel
    pub fn is_joined(&self, channel_name: &str) -> bool {
        self.channel_ciphers.contains_key(channel_name)
    }
    
    /// Get channel statistics
    pub fn get_stats(&self) -> ChannelStats {
        self.stats.clone()
    }
    
    /// Get detailed channel information
    pub fn get_channel_info(&self, channel_name: &str) -> Option<ChannelInfo> {
        self.channel_ciphers.get(channel_name).map(|cipher| ChannelInfo {
            name: cipher.name.clone(),
            joined_at: cipher.joined_at,
            message_count: cipher.message_count,
            message_counter: cipher.message_counter,
        })
    }
    
    /// Clear all channels (useful for logout/reset)
    pub fn clear_all_channels(&mut self) {
        let count = self.channel_ciphers.len();
        self.channel_ciphers.clear();
        self.update_stats();
        
        if count > 0 {
            info!("🧹 Cleared {} channels", count);
        }
    }
    
    // ==============================================================================
    // PRIVATE HELPER METHODS
    // ==============================================================================
    
    /// Generate nonce from counter (static method to avoid borrow issues)
    fn generate_nonce(counter: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&counter.to_le_bytes());
        // Last 4 bytes remain zero for simplicity
        *Nonce::from_slice(&nonce_bytes)
    }
    
    /// Update internal statistics
    fn update_stats(&mut self) {
        self.stats.active_channels = self.channel_ciphers.len();
    }
}

impl Default for ChannelEncryption {
    fn default() -> Self {
        Self::new()
    }
}

// ==============================================================================
// SUPPORTING TYPES
// ==============================================================================

/// Information about a joined channel
#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub name: String,
    pub joined_at: std::time::Instant,
    pub message_count: u64,
    pub message_counter: u64,
}

// ==============================================================================
// CHANNEL KEY DERIVATION UTILITIES
// ==============================================================================

/// Utilities for channel key management
pub mod key_utils {
    use super::*;
    
    /// Generate a secure channel password
    pub fn generate_channel_password(length: usize) -> String {
        use rand::distributions::{Alphanumeric, DistString};
        Alphanumeric.sample_string(&mut OsRng, length)
    }
    
    /// Validate channel password strength
    pub fn validate_password_strength(password: &str) -> Result<PasswordStrength> {
        let len = password.len();
        
        if len < 6 {
            return Ok(PasswordStrength::TooShort);
        }
        
        let has_upper = password.chars().any(|c| c.is_ascii_uppercase());
        let has_lower = password.chars().any(|c| c.is_ascii_lowercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());
        
        let complexity_score = [has_upper, has_lower, has_digit, has_special]
            .iter()
            .map(|&b| if b { 1 } else { 0 })
            .sum::<i32>();
        
        match (len, complexity_score) {
            (6..=7, 0..=1) => Ok(PasswordStrength::Weak),
            (6..=7, 2..=3) => Ok(PasswordStrength::Fair),
            (8..=11, 0..=2) => Ok(PasswordStrength::Fair),
            (8..=11, 3..=4) => Ok(PasswordStrength::Good),
            (12.., 0..=2) => Ok(PasswordStrength::Good),
            (12.., 3..=4) => Ok(PasswordStrength::Strong),
            _ => Ok(PasswordStrength::Fair),
        }
    }
    
    /// Password strength levels
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum PasswordStrength {
        TooShort,
        Weak,
        Fair,
        Good,
        Strong,
    }
}

// ==============================================================================
// TESTS
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_channel_creation() {
        let mut channels = ChannelEncryption::new();
        
        let result = channels.join_channel("test", "password123");
        assert!(result.is_ok());
        assert!(channels.is_joined("test"));
        assert_eq!(channels.get_joined_channels().len(), 1);
    }
    
    #[test]
    fn test_channel_encryption_decryption() {
        let mut channels = ChannelEncryption::new();
        channels.join_channel("test", "password123").unwrap();
        
        let plaintext = b"Hello, channel!";
        let ciphertext = channels.encrypt_channel_message("test", plaintext).unwrap();
        let decrypted = channels.decrypt_channel_message("test", &ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_password_verification() {
        let mut channels = ChannelEncryption::new();
        channels.join_channel("test", "password123").unwrap();
        
        assert!(channels.verify_channel_password("test", "password123").unwrap());
        assert!(!channels.verify_channel_password("test", "wrongpassword").unwrap());
    }
    
    #[test]
    fn test_channel_management() {
        let mut channels = ChannelEncryption::new();
        
        // Join multiple channels
        channels.join_channel("channel1", "pass1").unwrap();
        channels.join_channel("channel2", "pass2").unwrap();
        
        let joined = channels.get_joined_channels();
        assert_eq!(joined.len(), 2);
        assert!(joined.contains(&"channel1".to_string()));
        assert!(joined.contains(&"channel2".to_string()));
        
        // Leave one channel
        channels.leave_channel("channel1");
        assert_eq!(channels.get_joined_channels().len(), 1);
        assert!(!channels.is_joined("channel1"));
        assert!(channels.is_joined("channel2"));
    }
    
    #[test]
    fn test_password_strength() {
        use key_utils::*;
        
        assert_eq!(validate_password_strength("123").unwrap(), PasswordStrength::TooShort);
        assert_eq!(validate_password_strength("password").unwrap(), PasswordStrength::Weak);
        assert_eq!(validate_password_strength("Password123").unwrap(), PasswordStrength::Good);
        assert_eq!(validate_password_strength("MyStr0ng!P@ssw0rd").unwrap(), PasswordStrength::Strong);
    }
}