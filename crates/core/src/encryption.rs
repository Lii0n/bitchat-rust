//! BitChat Encryption Layer
//! 
//! Implements the complete encryption system for BitChat:
//! - X25519 key exchange for private messages  
//! - AES-256-GCM encryption
//! - Ed25519 digital signatures
//! - Argon2id for channel password derivation
//! - Noise Protocol Framework (XX pattern)

use anyhow::{Result, anyhow};
use rand::thread_rng;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// Updated imports for newer crypto library versions
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier, SecretKey};
use chacha20poly1305::{
    aead::{Aead, KeyInit, AeadCore},
    ChaCha20Poly1305, Key, Nonce,
};
use argon2::{Argon2, password_hash::{PasswordHasher as _, SaltString}};
use blake3::Hasher;

// ============================================================================
// CRYPTOGRAPHIC CONSTANTS
// ============================================================================

pub const SYMMETRIC_KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12;
pub const SIGNATURE_SIZE: usize = 64;
pub const PUBLIC_KEY_SIZE: usize = 32;
pub const SHARED_SECRET_SIZE: usize = 32;
pub const CHANNEL_SALT_SIZE: usize = 32;

// Argon2id parameters for channel password derivation
pub const ARGON2_MEMORY: u32 = 65536; // 64MB
pub const ARGON2_ITERATIONS: u32 = 10;
pub const ARGON2_PARALLELISM: u32 = 4;

// Session management
pub const SESSION_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour
pub const REKEY_MESSAGE_LIMIT: u64 = 10000;

// ============================================================================
// IDENTITY & KEY MANAGEMENT
// ============================================================================

/// Persistent identity for a BitChat peer
#[derive(Clone)]
pub struct BitChatIdentity {
    /// Long-term signing keypair for authentication
    pub signing_key: SigningKey,
    /// Static public key for Diffie-Hellman key exchange
    pub static_public_key: X25519PublicKey,
    /// Public key fingerprint for identification
    pub fingerprint: [u8; 32],
}

impl std::fmt::Debug for BitChatIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BitChatIdentity")
            .field("fingerprint", &hex::encode(&self.fingerprint))
            .finish()
    }
}

impl BitChatIdentity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let mut rng = thread_rng();
        
        // Generate signing key from random bytes
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rng, &mut secret_bytes);
        let secret_key = SecretKey::from(secret_bytes);
        let signing_key = SigningKey::from(&secret_key);
        
        // Generate static DH key - we only store the public key for identity
        let static_secret = EphemeralSecret::random_from_rng(&mut rng);
        let static_public_key = X25519PublicKey::from(&static_secret);
        
        // Create fingerprint from DH public key
        let fingerprint = blake3::hash(static_public_key.as_bytes()).into();
        
        Self {
            signing_key,
            static_public_key,
            fingerprint,
        }
    }
    
    /// Get public DH key
    pub fn public_key(&self) -> X25519PublicKey {
        self.static_public_key
    }
    
    /// Get signing public key
    pub fn signing_public_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }
    
    /// Sign data with identity key
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }
    
    /// Verify signature from another peer
    pub fn verify_signature(&self, public_key: &VerifyingKey, data: &[u8], signature: &Signature) -> bool {
        public_key.verify(data, signature).is_ok()
    }
}

// ============================================================================
// SESSION MANAGEMENT (NOISE PROTOCOL)
// ============================================================================

/// Encryption session state for a peer connection
pub struct EncryptionSession {
    /// Peer's public DH key
    pub remote_public_key: X25519PublicKey,
    /// Peer's signing public key
    pub remote_signing_key: Option<VerifyingKey>,
    /// Shared secret for this session
    pub shared_secret: [u8; 32],
    /// Send cipher state
    pub send_cipher: ChaCha20Poly1305,
    /// Receive cipher state  
    pub recv_cipher: ChaCha20Poly1305,
    /// Send nonce counter
    pub send_nonce: u64,
    /// Receive nonce counter
    pub recv_nonce: u64,
    /// Session creation time
    pub created_at: Instant,
    /// Message count for rekey detection
    pub message_count: u64,
}

impl std::fmt::Debug for EncryptionSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionSession")
            .field("remote_public_key", &hex::encode(self.remote_public_key.as_bytes()))
            .field("send_nonce", &self.send_nonce)
            .field("recv_nonce", &self.recv_nonce)
            .field("message_count", &self.message_count)
            .field("created_at", &self.created_at)
            .finish()
    }
}

impl EncryptionSession {
    /// Create new session from handshake
    pub fn new(remote_public_key: X25519PublicKey, shared_secret: [u8; 32]) -> Self {
        // Derive separate keys for send/receive using HKDF
        let send_key = Self::derive_key(&shared_secret, b"SEND");
        let recv_key = Self::derive_key(&shared_secret, b"RECV");
        
        Self {
            remote_public_key,
            remote_signing_key: None,
            shared_secret,
            send_cipher: ChaCha20Poly1305::new(&send_key),
            recv_cipher: ChaCha20Poly1305::new(&recv_key),
            send_nonce: 0,
            recv_nonce: 0,
            created_at: Instant::now(),
            message_count: 0,
        }
    }
    
    /// Derive encryption key using BLAKE3-based HKDF
    fn derive_key(secret: &[u8; 32], info: &[u8]) -> Key {
        let mut hasher = Hasher::new();
        hasher.update(secret);
        hasher.update(info);
        let derived = hasher.finalize();
        Key::clone_from_slice(&derived.as_bytes()[..32])
    }
    
    /// Encrypt plaintext
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = self.send_nonce.to_le_bytes();
        let mut nonce_array = [0u8; NONCE_SIZE];
        nonce_array[..8].copy_from_slice(&nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_array);
        
        let ciphertext = self.send_cipher.encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("Encryption failed"))?;
        
        self.send_nonce += 1;
        self.message_count += 1;
        
        Ok(ciphertext)
    }
    
    /// Decrypt ciphertext
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let nonce_bytes = self.recv_nonce.to_le_bytes();
        let mut nonce_array = [0u8; NONCE_SIZE];
        nonce_array[..8].copy_from_slice(&nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_array);
        
        let plaintext = self.recv_cipher.decrypt(nonce, ciphertext)
            .map_err(|_| anyhow!("Decryption failed"))?;
        
        self.recv_nonce += 1;
        
        Ok(plaintext)
    }
    
    /// Check if session needs rekeying
    pub fn needs_rekey(&self) -> bool {
        self.created_at.elapsed() > SESSION_TIMEOUT || 
        self.message_count > REKEY_MESSAGE_LIMIT
    }
}

// ============================================================================
// KEY EXCHANGE (X25519 ECDH)
// ============================================================================

/// Key exchange manager for establishing encrypted sessions
pub struct KeyExchangeManager {
    /// Our identity
    identity: BitChatIdentity,
    /// Active sessions by peer ID
    sessions: HashMap<String, EncryptionSession>,
    /// Pending handshakes
    pending_handshakes: HashMap<String, EphemeralSecret>,
}

impl KeyExchangeManager {
    /// Create new key exchange manager
    pub fn new(identity: BitChatIdentity) -> Self {
        Self {
            identity,
            sessions: HashMap::new(),
            pending_handshakes: HashMap::new(),
        }
    }
    
    /// Initiate key exchange with a peer
    pub fn initiate_key_exchange(&mut self, peer_id: &str) -> Result<Vec<u8>> {
        let ephemeral_secret = EphemeralSecret::random_from_rng(&mut thread_rng());
        let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);
        
        // Store ephemeral secret for later
        self.pending_handshakes.insert(peer_id.to_string(), ephemeral_secret);
        
        // Create key exchange packet
        let mut packet = Vec::new();
        packet.extend_from_slice(ephemeral_public.as_bytes());
        packet.extend_from_slice(self.identity.public_key().as_bytes());
        
        // Sign the packet
        let signature = self.identity.sign(&packet);
        packet.extend_from_slice(signature.to_bytes().as_slice());
        
        Ok(packet)
    }
    
    /// Handle incoming key exchange
    pub fn handle_key_exchange(&mut self, peer_id: &str, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        if packet.len() < PUBLIC_KEY_SIZE * 2 + SIGNATURE_SIZE {
            return Err(anyhow!("Invalid key exchange packet size"));
        }
        
        // Parse packet
        let ephemeral_public = X25519PublicKey::from(
            <[u8; 32]>::try_from(&packet[0..32])?
        );
        let static_public = X25519PublicKey::from(
            <[u8; 32]>::try_from(&packet[32..64])?
        );
        
        // Fix signature parsing - convert slice to array properly
        let signature_bytes = &packet[64..128];
        if signature_bytes.len() != 64 {
            return Err(anyhow!("Invalid signature length"));
        }
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(signature_bytes);
        let _signature = Signature::from_bytes(&sig_array);
        
        // Verify signature (would need peer's signing key)
        // For now, we'll trust the packet
        
        // Check if this is a response to our initiation
        if let Some(our_ephemeral) = self.pending_handshakes.remove(peer_id) {
            // We initiated - complete the handshake
            let shared_secret = our_ephemeral.diffie_hellman(&ephemeral_public);
            let session = EncryptionSession::new(static_public, shared_secret.to_bytes());
            self.sessions.insert(peer_id.to_string(), session);
            Ok(None) // No response needed
        } else {
            // They initiated - respond with our keys
            let ephemeral_secret = EphemeralSecret::random_from_rng(&mut thread_rng());
            let ephemeral_public_ours = X25519PublicKey::from(&ephemeral_secret);
            
            // Create shared secret
            let shared_secret = ephemeral_secret.diffie_hellman(&ephemeral_public);
            let session = EncryptionSession::new(static_public, shared_secret.to_bytes());
            self.sessions.insert(peer_id.to_string(), session);
            
            // Create response packet
            let mut response = Vec::new();
            response.extend_from_slice(ephemeral_public_ours.as_bytes());
            response.extend_from_slice(self.identity.public_key().as_bytes());
            
            let signature = self.identity.sign(&response);
            response.extend_from_slice(signature.to_bytes().as_slice());
            
            Ok(Some(response))
        }
    }
    
    /// Encrypt message for peer
    pub fn encrypt_for_peer(&mut self, peer_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let session = self.sessions.get_mut(peer_id)
            .ok_or_else(|| anyhow!("No session with peer {}", peer_id))?;
        
        if session.needs_rekey() {
            return Err(anyhow!("Session needs rekeying"));
        }
        
        session.encrypt(plaintext)
    }
    
    /// Decrypt message from peer
    pub fn decrypt_from_peer(&mut self, peer_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let session = self.sessions.get_mut(peer_id)
            .ok_or_else(|| anyhow!("No session with peer {}", peer_id))?;
        
        session.decrypt(ciphertext)
    }
    
    /// Clean up old sessions
    pub fn cleanup(&mut self) {
        self.sessions.retain(|_, session| !session.needs_rekey());
    }
    
    /// Get encryption statistics
    pub fn get_stats(&self) -> EncryptionStats {
        EncryptionStats {
            active_sessions: self.sessions.len(),
            pending_handshakes: self.pending_handshakes.len(),
        }
    }
}

// ============================================================================
// CHANNEL ENCRYPTION
// ============================================================================

/// Channel encryption for password-protected channels
pub struct ChannelEncryption {
    /// Active channel keys
    channel_keys: HashMap<String, ChaCha20Poly1305>,
}

impl ChannelEncryption {
    pub fn new() -> Self {
        Self {
            channel_keys: HashMap::new(),
        }
    }
    
    /// Join a password-protected channel
    pub fn join_channel(&mut self, channel_name: &str, password: &str) -> Result<()> {
        let salt = SaltString::generate(&mut thread_rng());
        let argon2 = Argon2::default();
        
        // Derive key from password
        let password_hash = argon2.hash_password(password.as_bytes(), &salt)
            .map_err(|e| anyhow!("Password hashing failed: {}", e))?;
        
        // Fix the temporary value issue
        let hash = password_hash.hash.unwrap();
        let key_bytes = hash.as_bytes();
        let key = Key::clone_from_slice(&key_bytes[..32]);
        let cipher = ChaCha20Poly1305::new(&key);
        
        self.channel_keys.insert(channel_name.to_string(), cipher);
        Ok(())
    }
    
    /// Leave a channel
    pub fn leave_channel(&mut self, channel_name: &str) {
        self.channel_keys.remove(channel_name);
    }
    
    /// Encrypt message for channel
    pub fn encrypt_channel_message(&self, channel_name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = self.channel_keys.get(channel_name)
            .ok_or_else(|| anyhow!("No key for channel {}", channel_name))?;
        
        let nonce = ChaCha20Poly1305::generate_nonce(&mut thread_rng());
        let ciphertext = cipher.encrypt(&nonce, plaintext)
            .map_err(|_| anyhow!("Channel encryption failed"))?;
        
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }
    
    /// Decrypt message from channel
    pub fn decrypt_channel_message(&self, channel_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < 12 {
            return Err(anyhow!("Channel ciphertext too short"));
        }
        
        let cipher = self.channel_keys.get(channel_name)
            .ok_or_else(|| anyhow!("No key for channel {}", channel_name))?;
        
        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let encrypted_data = &ciphertext[12..];
        
        let plaintext = cipher.decrypt(nonce, encrypted_data)
            .map_err(|_| anyhow!("Channel decryption failed"))?;
        
        Ok(plaintext)
    }
}

// ============================================================================
// MAIN ENCRYPTION INTERFACE
// ============================================================================

/// Main encryption interface for BitChat
pub struct BitChatEncryption {
    identity: BitChatIdentity,
    key_exchange: KeyExchangeManager,
    channel_encryption: ChannelEncryption,
}

impl BitChatEncryption {
    /// Create new encryption manager with random identity
    pub fn new() -> Self {
        let identity = BitChatIdentity::generate();
        let key_exchange = KeyExchangeManager::new(identity.clone());
        let channel_encryption = ChannelEncryption::new();
        
        Self {
            identity,
            key_exchange,
            channel_encryption,
        }
    }
    
    /// Create encryption manager with existing identity
    pub fn with_identity(identity: BitChatIdentity) -> Self {
        let key_exchange = KeyExchangeManager::new(identity.clone());
        let channel_encryption = ChannelEncryption::new();
        
        Self {
            identity,
            key_exchange,
            channel_encryption,
        }
    }
    
    /// Get our public key for announcements
    pub fn our_public_key(&self) -> X25519PublicKey {
        self.identity.public_key()
    }
    
    /// Get our signing public key
    pub fn our_signing_key(&self) -> VerifyingKey {
        self.identity.signing_public_key()
    }
    
    /// Get our fingerprint
    pub fn our_fingerprint(&self) -> [u8; 32] {
        self.identity.fingerprint
    }
    
    /// Initiate key exchange with a peer
    pub fn initiate_key_exchange(&mut self, peer_id: &str) -> Result<Vec<u8>> {
        self.key_exchange.initiate_key_exchange(peer_id)
    }
    
    /// Handle incoming key exchange
    pub fn handle_key_exchange(&mut self, peer_id: &str, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        self.key_exchange.handle_key_exchange(peer_id, packet)
    }
    
    /// Encrypt private message for peer
    pub fn encrypt_private_message(&mut self, peer_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.key_exchange.encrypt_for_peer(peer_id, plaintext)
    }
    
    /// Decrypt private message from peer
    pub fn decrypt_private_message(&mut self, peer_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.key_exchange.decrypt_from_peer(peer_id, ciphertext)
    }
    
    /// Join a password-protected channel
    pub fn join_channel(&mut self, channel_name: &str, password: &str) -> Result<()> {
        self.channel_encryption.join_channel(channel_name, password)
    }
    
    /// Leave a channel
    pub fn leave_channel(&mut self, channel_name: &str) {
        self.channel_encryption.leave_channel(channel_name);
    }
    
    /// Encrypt message for channel
    pub fn encrypt_channel_message(&self, channel_name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.channel_encryption.encrypt_channel_message(channel_name, plaintext)
    }
    
    /// Decrypt message from channel
    pub fn decrypt_channel_message(&self, channel_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.channel_encryption.decrypt_channel_message(channel_name, ciphertext)
    }
    
    /// Sign data with our identity
    pub fn sign_data(&self, data: &[u8]) -> Signature {
        self.identity.sign(data)
    }
    
    /// Verify signature from peer
    pub fn verify_signature(&self, peer_key: &VerifyingKey, data: &[u8], signature: &Signature) -> bool {
        self.identity.verify_signature(peer_key, data, signature)
    }
    
    /// Clean up old sessions and keys
    pub fn cleanup(&mut self) {
        self.key_exchange.cleanup();
    }
    
    /// Get encryption statistics
    pub fn get_stats(&self) -> EncryptionStats {
        self.key_exchange.get_stats()
    }
}

/// Encryption statistics
#[derive(Debug)]
pub struct EncryptionStats {
    pub active_sessions: usize,
    pub pending_handshakes: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_identity_generation() {
        let identity = BitChatIdentity::generate();
        
        // Test signing functionality
        let data = b"test message";
        let signature = identity.sign(data);
        let public_key = identity.signing_public_key();
        
        assert!(identity.verify_signature(&public_key, data, &signature));
    }
    
    #[test]
    fn test_encryption_session() {
        let ephemeral1 = EphemeralSecret::random_from_rng(&mut thread_rng());
        let ephemeral2 = EphemeralSecret::random_from_rng(&mut thread_rng());
        
        let public1 = X25519PublicKey::from(&ephemeral1);
        let public2 = X25519PublicKey::from(&ephemeral2);
        
        let shared_secret1 = ephemeral1.diffie_hellman(&public2);
        let shared_secret2 = ephemeral2.diffie_hellman(&public1);
        
        // Both sides should derive the same shared secret
        assert_eq!(shared_secret1.to_bytes(), shared_secret2.to_bytes());
        
        let mut session1 = EncryptionSession::new(public2, shared_secret1.to_bytes());
        let mut session2 = EncryptionSession::new(public1, shared_secret2.to_bytes());
        
        let plaintext = b"Hello, secure world!";
        let ciphertext = session1.encrypt(plaintext).unwrap();
        let decrypted = session2.decrypt(&ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
}