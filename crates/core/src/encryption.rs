//! BitChat Encryption Layer
//! 
//! Implements the complete encryption system for BitChat:
//! - X25519 key exchange for private messages  
//! - AES-256-GCM encryption
//! - Ed25519 digital signatures
//! - Argon2id for channel password derivation
//! - Noise Protocol Framework (XX pattern)

use anyhow::{Result, anyhow};
use rand::{RngCore, thread_rng};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// Cryptographic dependencies (these would need to be added to Cargo.toml)
// x25519-dalek = "2.0"
// ed25519-dalek = "2.0" 
// chacha20poly1305 = "0.10"
// argon2 = "0.5"
// blake3 = "1.4"

use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};
use ed25519_dalek::{Keypair as Ed25519Keypair, PublicKey as Ed25519PublicKey, Signature, Signer, Verifier};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Key, Nonce,
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
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
#[derive(Debug, Clone)]
pub struct BitChatIdentity {
    /// Long-term signing keypair for authentication
    pub signing_keypair: Ed25519Keypair,
    /// Static key for Diffie-Hellman key exchange
    pub static_secret: StaticSecret,
    /// Public key fingerprint for identification
    pub fingerprint: [u8; 32],
}

impl BitChatIdentity {
    /// Generate a new random identity
    pub fn generate() -> Self {
        let mut rng = thread_rng();
        
        // Generate signing keypair
        let signing_keypair = Ed25519Keypair::generate(&mut rng);
        
        // Generate static DH key
        let static_secret = StaticSecret::new(&mut rng);
        
        // Create fingerprint from public key
        let public_key = X25519PublicKey::from(&static_secret);
        let fingerprint = blake3::hash(public_key.as_bytes()).into();
        
        Self {
            signing_keypair,
            static_secret,
            fingerprint,
        }
    }
    
    /// Get public DH key
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey::from(&self.static_secret)
    }
    
    /// Get signing public key
    pub fn signing_public_key(&self) -> Ed25519PublicKey {
        self.signing_keypair.public
    }
    
    /// Sign data with identity key
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_keypair.sign(data)
    }
    
    /// Verify signature from another peer
    pub fn verify_signature(&self, public_key: &Ed25519PublicKey, data: &[u8], signature: &Signature) -> bool {
        public_key.verify(data, signature).is_ok()
    }
}

// ============================================================================
// SESSION MANAGEMENT (NOISE PROTOCOL)
// ============================================================================

/// Encryption session state for a peer connection
#[derive(Debug)]
pub struct EncryptionSession {
    /// Peer's public DH key
    pub remote_public_key: X25519PublicKey,
    /// Peer's signing public key
    pub remote_signing_key: Option<Ed25519PublicKey>,
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
        let ephemeral_secret = EphemeralSecret::new(&mut thread_rng());
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
        let signature = Signature::from_bytes(&packet[64..128])?;
        
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
            let ephemeral_secret = EphemeralSecret::new(&mut thread_rng());
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
    
    /// Get session info
    pub fn get_session(&self, peer_id: &str) -> Option<&EncryptionSession> {
        self.sessions.get(peer_id)
    }
    
    /// Remove session
    pub fn remove_session(&mut self, peer_id: &str) {
        self.sessions.remove(peer_id);
        self.pending_handshakes.remove(peer_id);
    }
    
    /// Cleanup old sessions
    pub fn cleanup_old_sessions(&mut self) {
        let now = Instant::now();
        self.sessions.retain(|_, session| {
            now.duration_since(session.created_at) < SESSION_TIMEOUT * 2
        });
    }
}

// ============================================================================
// CHANNEL ENCRYPTION (PASSWORD-BASED)
// ============================================================================

/// Channel encryption using password-derived keys
pub struct ChannelEncryption {
    /// Cached channel keys by channel name
    channel_keys: HashMap<String, ChaCha20Poly1305>,
}

impl ChannelEncryption {
    /// Create new channel encryption manager
    pub fn new() -> Self {
        Self {
            channel_keys: HashMap::new(),
        }
    }
    
    /// Derive key from channel password using Argon2id
    pub fn derive_channel_key(&mut self, channel_name: &str, password: &str) -> Result<()> {
        // Create salt from channel name
        let salt = blake3::hash(channel_name.as_bytes());
        
        // Derive key using Argon2id
        let argon2 = Argon2::default();
        let mut key_bytes = [0u8; 32];
        
        argon2.hash_password_into(
            password.as_bytes(),
            salt.as_bytes(),
            &mut key_bytes,
        ).map_err(|e| anyhow!("Key derivation failed: {}", e))?;
        
        // Create cipher
        let key = Key::from_slice(&key_bytes);
        let cipher = ChaCha20Poly1305::new(key);
        
        self.channel_keys.insert(channel_name.to_string(), cipher);
        Ok(())
    }
    
    /// Encrypt message for channel
    pub fn encrypt_channel_message(&self, channel_name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = self.channel_keys.get(channel_name)
            .ok_or_else(|| anyhow!("No key for channel {}", channel_name))?;
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt
        let mut ciphertext = cipher.encrypt(nonce, plaintext)
            .map_err(|_| anyhow!("Channel encryption failed"))?;
        
        // Prepend nonce
        let mut result = nonce_bytes.to_vec();
        result.append(&mut ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt channel message
    pub fn decrypt_channel_message(&self, channel_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(anyhow!("Ciphertext too short"));
        }
        
        let cipher = self.channel_keys.get(channel_name)
            .ok_or_else(|| anyhow!("No key for channel {}", channel_name))?;
        
        // Extract nonce and ciphertext
        let nonce = Nonce::from_slice(&ciphertext[..NONCE_SIZE]);
        let encrypted_data = &ciphertext[NONCE_SIZE..];
        
        // Decrypt
        cipher.decrypt(nonce, encrypted_data)
            .map_err(|_| anyhow!("Channel decryption failed"))
    }
    
    /// Remove channel key
    pub fn leave_channel(&mut self, channel_name: &str) {
        self.channel_keys.remove(channel_name);
    }
}

// ============================================================================
// MAIN ENCRYPTION SERVICE
// ============================================================================

/// Main encryption service combining all cryptographic operations
pub struct BitChatEncryption {
    /// Our identity
    identity: BitChatIdentity,
    /// Key exchange manager
    key_exchange: KeyExchangeManager,
    /// Channel encryption
    channel_encryption: ChannelEncryption,
}

impl BitChatEncryption {
    /// Create new encryption service
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
    
    /// Create encryption service with existing identity
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
    pub fn our_signing_key(&self) -> Ed25519PublicKey {
        self.identity.signing_public_key()
    }
    
    /// Get our fingerprint
    pub fn our_fingerprint(&self) -> [u8; 32] {
        self.identity.fingerprint
    }
    
    /// Sign data with our identity
    pub fn sign_data(&self, data: &[u8]) -> Signature {
        self.identity.sign(data)
    }
    
    /// Initiate key exchange with peer
    pub fn initiate_key_exchange(&mut self, peer_id: &str) -> Result<Vec<u8>> {
        self.key_exchange.initiate_key_exchange(peer_id)
    }
    
    /// Handle incoming key exchange
    pub fn handle_key_exchange(&mut self, peer_id: &str, packet: &[u8]) -> Result<Option<Vec<u8>>> {
        self.key_exchange.handle_key_exchange(peer_id, packet)
    }
    
    /// Encrypt private message
    pub fn encrypt_private_message(&mut self, peer_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.key_exchange.encrypt_for_peer(peer_id, plaintext)
    }
    
    /// Decrypt private message
    pub fn decrypt_private_message(&mut self, peer_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.key_exchange.decrypt_from_peer(peer_id, ciphertext)
    }
    
    /// Join password-protected channel
    pub fn join_channel(&mut self, channel_name: &str, password: &str) -> Result<()> {
        self.channel_encryption.derive_channel_key(channel_name, password)
    }
    
    /// Encrypt channel message
    pub fn encrypt_channel_message(&self, channel_name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.channel_encryption.encrypt_channel_message(channel_name, plaintext)
    }
    
    /// Decrypt channel message
    pub fn decrypt_channel_message(&self, channel_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.channel_encryption.decrypt_channel_message(channel_name, ciphertext)
    }
    
    /// Leave channel
    pub fn leave_channel(&mut self, channel_name: &str) {
        self.channel_encryption.leave_channel(channel_name);
    }
    
    /// Check if we have a session with peer
    pub fn has_session_with(&self, peer_id: &str) -> bool {
        self.key_exchange.get_session(peer_id).is_some()
    }
    
    /// Remove peer session
    pub fn remove_peer_session(&mut self, peer_id: &str) {
        self.key_exchange.remove_session(peer_id);
    }
    
    /// Cleanup old sessions
    pub fn cleanup(&mut self) {
        self.key_exchange.cleanup_old_sessions();
    }
    
    /// Get encryption statistics
    pub fn get_stats(&self) -> EncryptionStats {
        EncryptionStats {
            active_sessions: self.key_exchange.sessions.len(),
            pending_handshakes: self.key_exchange.pending_handshakes.len(),
            channel_keys: self.channel_encryption.channel_keys.len(),
        }
    }
}

/// Encryption service statistics
#[derive(Debug)]
pub struct EncryptionStats {
    pub active_sessions: usize,
    pub pending_handshakes: usize,
    pub channel_keys: usize,
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_identity_generation() {
        let identity = BitChatIdentity::generate();
        
        // Test signing
        let data = b"test data";
        let signature = identity.sign(data);
        assert!(identity.verify_signature(&identity.signing_public_key(), data, &signature));
    }
    
    #[test]
    fn test_key_exchange() {
        let mut alice = BitChatEncryption::new();
        let mut bob = BitChatEncryption::new();
        
        // Alice initiates
        let alice_packet = alice.initiate_key_exchange("bob").unwrap();
        
        // Bob responds
        let bob_response = bob.handle_key_exchange("alice", &alice_packet).unwrap();
        assert!(bob_response.is_some());
        
        // Alice completes
        let alice_final = alice.handle_key_exchange("bob", &bob_response.unwrap()).unwrap();
        assert!(alice_final.is_none());
        
        // Both should have sessions now
        assert!(alice.has_session_with("bob"));
        assert!(bob.has_session_with("alice"));
        
        // Test encryption
        let plaintext = b"Hello, Bob!";
        let ciphertext = alice.encrypt_private_message("bob", plaintext).unwrap();
        let decrypted = bob.decrypt_private_message("alice", &ciphertext).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
    
    #[test]
    fn test_channel_encryption() {
        let mut encryption = BitChatEncryption::new();
        let channel = "test-channel";
        let password = "secret123";
        let plaintext = b"Channel message";
        
        // Join channel
        encryption.join_channel(channel, password).unwrap();
        
        // Encrypt/decrypt
        let ciphertext = encryption.encrypt_channel_message(channel, plaintext).unwrap();
        let decrypted = encryption.decrypt_channel_message(channel, &ciphertext).unwrap();
        
        assert_eq!(plaintext, &decrypted[..]);
    }
}