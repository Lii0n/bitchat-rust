//! Comprehensive cryptographic implementation for BitChat
//! 
//! This module provides end-to-end encryption, key management, digital signatures,
//! and secure key exchange using industry-standard cryptographic primitives.

use anyhow::{Result, anyhow};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, KeyInit, AeadInPlace};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use sha2::{Sha256, Digest};
use hkdf::Hkdf;
use rand::{RngCore, CryptoRng};
use rand_core::OsRng;
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

// Re-export commonly used types
pub use ed25519_dalek::{Signature as Ed25519Signature, SIGNATURE_LENGTH};
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const X25519_PUBLIC_KEY_LENGTH: usize = 32;

/// Main cryptographic manager handling all security operations
#[derive(Debug)]
pub struct CryptoManager {
    /// Our permanent identity keypair for signatures
    identity_signing_key: SigningKey,
    identity_verifying_key: VerifyingKey,
    /// Cached shared secrets for active conversations
    shared_secrets: HashMap<[u8; 8], SharedSecretCache>,
    /// Random number generator
    rng: OsRng,
}

/// Cached shared secret with metadata
#[derive(Debug, Clone, ZeroizeOnDrop)]
struct SharedSecretCache {
    #[zeroize(skip)]
    peer_id: [u8; 8],
    shared_secret: [u8; 32],
    #[zeroize(skip)]
    created_at: u64,
    #[zeroize(skip)]
    last_used: u64,
}

/// Key exchange bundle containing both public keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyExchangeBundle {
    pub x25519_public: [u8; 32],
    pub ed25519_public: [u8; 32],
    pub timestamp: u64,
}

/// Encrypted message container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedMessage {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
    pub tag: [u8; 16],
}

/// Digital signature with metadata - Fixed serialization issue
#[derive(Debug, Clone)]
pub struct MessageSignature {
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
    pub timestamp: u64,
}

// Manual Serialize/Deserialize implementation for MessageSignature to handle [u8; 64]
impl Serialize for MessageSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("MessageSignature", 3)?;
        state.serialize_field("signature", &self.signature.as_slice())?;
        state.serialize_field("public_key", &self.public_key.as_slice())?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for MessageSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, Visitor, SeqAccess, MapAccess};
        use std::fmt;

        struct MessageSignatureVisitor;

        impl<'de> Visitor<'de> for MessageSignatureVisitor {
            type Value = MessageSignature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct MessageSignature")
            }

            fn visit_map<V>(self, mut map: V) -> Result<MessageSignature, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut signature: Option<Vec<u8>> = None;
                let mut public_key: Option<Vec<u8>> = None;
                let mut timestamp: Option<u64> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        "signature" => {
                            if signature.is_some() {
                                return Err(de::Error::duplicate_field("signature"));
                            }
                            signature = Some(map.next_value()?);
                        }
                        "public_key" => {
                            if public_key.is_some() {
                                return Err(de::Error::duplicate_field("public_key"));
                            }
                            public_key = Some(map.next_value()?);
                        }
                        "timestamp" => {
                            if timestamp.is_some() {
                                return Err(de::Error::duplicate_field("timestamp"));
                            }
                            timestamp = Some(map.next_value()?);
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                let signature = signature.ok_or_else(|| de::Error::missing_field("signature"))?;
                let public_key = public_key.ok_or_else(|| de::Error::missing_field("public_key"))?;
                let timestamp = timestamp.ok_or_else(|| de::Error::missing_field("timestamp"))?;

                if signature.len() != 64 {
                    return Err(de::Error::custom("signature must be 64 bytes"));
                }
                if public_key.len() != 32 {
                    return Err(de::Error::custom("public_key must be 32 bytes"));
                }

                let mut sig_array = [0u8; 64];
                let mut key_array = [0u8; 32];
                sig_array.copy_from_slice(&signature);
                key_array.copy_from_slice(&public_key);

                Ok(MessageSignature {
                    signature: sig_array,
                    public_key: key_array,
                    timestamp,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["signature", "public_key", "timestamp"];
        deserializer.deserialize_struct("MessageSignature", FIELDS, MessageSignatureVisitor)
    }
}

impl CryptoManager {
    /// Create a new crypto manager with a fresh identity
    pub fn new() -> Result<Self> {
        let mut csprng = OsRng;
        let identity_signing_key = SigningKey::generate(&mut csprng); // Fixed: use generate method properly
        let identity_verifying_key = identity_signing_key.verifying_key();
        
        Ok(Self {
            identity_signing_key,
            identity_verifying_key,
            shared_secrets: HashMap::new(),
            rng: OsRng,
        })
    }

    /// Create crypto manager from existing identity key
    pub fn from_identity_key(private_key: &[u8]) -> Result<Self> {
        if private_key.len() != 32 {
            return Err(anyhow!("Invalid private key length: expected 32 bytes"));
        }

        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(private_key);
        
        let identity_signing_key = SigningKey::from_bytes(&key_bytes);
        let identity_verifying_key = identity_signing_key.verifying_key();

        Ok(Self {
            identity_signing_key,
            identity_verifying_key,
            shared_secrets: HashMap::new(),
            rng: OsRng,
        })
    }

    /// Get our public identity key
    pub fn public_key(&self) -> [u8; 32] {
        self.identity_verifying_key.to_bytes()
    }

    /// Get our private identity key (use carefully!)
    pub fn private_key(&self) -> [u8; 32] {
        self.identity_signing_key.to_bytes()
    }

    /// Generate a random key for symmetric encryption
    pub fn generate_random_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Generate ephemeral keypair for key exchange
    pub fn generate_ephemeral_keypair(&self) -> (EphemeralSecret, X25519PublicKey) {
        let secret = EphemeralSecret::random_from_rng(OsRng); // Fixed: use proper method
        let public = X25519PublicKey::from(&secret);
        (secret, public)
    }

    /// Create key exchange bundle with both identity and ephemeral keys
    pub fn create_key_exchange_bundle(&self) -> Result<(KeyExchangeBundle, EphemeralSecret)> {
        let (ephemeral_secret, ephemeral_public) = self.generate_ephemeral_keypair();
        
        let bundle = KeyExchangeBundle {
            x25519_public: ephemeral_public.to_bytes(),
            ed25519_public: self.public_key(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs(),
        };

        Ok((bundle, ephemeral_secret))
    }

    /// Process received key exchange and establish shared secret
    pub fn process_key_exchange(
        &mut self,
        peer_id: [u8; 8],
        remote_bundle: &KeyExchangeBundle,
        our_ephemeral_secret: EphemeralSecret,
    ) -> Result<()> {
        // Validate timestamp (within 5 minutes)
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if remote_bundle.timestamp.abs_diff(now) > 300 {
            return Err(anyhow!("Key exchange timestamp too old or in future"));
        }

        // Create shared secret using X25519
        let remote_public = X25519PublicKey::from(remote_bundle.x25519_public);
        let shared_secret = our_ephemeral_secret.diffie_hellman(&remote_public);

        // Derive encryption key using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut derived_key = [0u8; 32];
        hk.expand(b"bitchat-v1-encryption", &mut derived_key)
            .map_err(|e| anyhow!("HKDF expansion failed: {}", e))?;

        // Cache the shared secret
        let cache = SharedSecretCache {
            peer_id,
            shared_secret: derived_key,
            created_at: now,
            last_used: now,
        };
        
        self.shared_secrets.insert(peer_id, cache);
        Ok(())
    }

    /// Encrypt message for a specific peer
    pub fn encrypt_for_peer(&mut self, peer_id: [u8; 8], plaintext: &[u8]) -> Result<EncryptedMessage> {
        // Fixed borrowing issue: split the operation
        let shared_secret = {
            let cache = self.shared_secrets.get_mut(&peer_id)
                .ok_or_else(|| anyhow!("No shared secret for peer"))?;

            // Update last used timestamp
            cache.last_used = SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs();

            cache.shared_secret // Copy the key
        };

        self.encrypt_with_key(plaintext, &shared_secret)
    }

    /// Decrypt message from a specific peer
    pub fn decrypt_from_peer(&self, peer_id: [u8; 8], encrypted: &EncryptedMessage) -> Result<Vec<u8>> {
        let cache = self.shared_secrets.get(&peer_id)
            .ok_or_else(|| anyhow!("No shared secret for peer"))?;

        self.decrypt_with_key(encrypted, &cache.shared_secret)
    }

    /// Encrypt data with a specific key
    pub fn encrypt_with_key(&self, plaintext: &[u8], key: &[u8; 32]) -> Result<EncryptedMessage> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt in place
        let mut buffer = plaintext.to_vec();
        let tag = cipher.encrypt_in_place_detached(nonce, b"", &mut buffer)
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        Ok(EncryptedMessage {
            nonce: nonce_bytes,
            ciphertext: buffer,
            tag: tag.into(),
        })
    }

    /// Decrypt data with a specific key
    pub fn decrypt_with_key(&self, encrypted: &EncryptedMessage, key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let nonce = Nonce::from_slice(&encrypted.nonce);
        let tag = chacha20poly1305::Tag::from_slice(&encrypted.tag);

        let mut buffer = encrypted.ciphertext.clone();
        cipher.decrypt_in_place_detached(nonce, b"", &mut buffer, tag)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        Ok(buffer)
    }

    /// Sign a message with our identity key
    pub fn sign_message(&self, message: &[u8]) -> MessageSignature {
        let signature = self.identity_signing_key.sign(message);
        
        MessageSignature {
            signature: signature.to_bytes(),
            public_key: self.public_key(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Verify a message signature
    pub fn verify_signature(&self, message: &[u8], sig: &MessageSignature) -> Result<bool> {
        // Check timestamp (within reasonable bounds)
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        if sig.timestamp.abs_diff(now) > 3600 { // 1 hour tolerance
            return Ok(false);
        }

        let public_key = VerifyingKey::from_bytes(&sig.public_key)
            .map_err(|e| anyhow!("Invalid public key: {}", e))?;
        
        let signature = Signature::from_bytes(&sig.signature);

        Ok(public_key.verify(message, &signature).is_ok())
    }

    /// Generate shared secret from ephemeral keys (for initial key exchange)
    pub fn generate_shared_secret(&self) -> (EphemeralSecret, X25519PublicKey) {
        self.generate_ephemeral_keypair()
    }

    /// Derive shared secret from our private key and their public key
    pub fn derive_shared_secret(&self, our_secret: EphemeralSecret, their_public: &[u8]) -> Result<[u8; 32]> {
        if their_public.len() != 32 {
            return Err(anyhow!("Invalid public key length: expected 32 bytes"));
        }

        let mut public_bytes = [0u8; 32];
        public_bytes.copy_from_slice(their_public);
        let their_public_key = X25519PublicKey::from(public_bytes);
        
        let shared_secret = our_secret.diffie_hellman(&their_public_key);
        
        // Derive key using HKDF
        let hk = Hkdf::<Sha256>::new(None, shared_secret.as_bytes());
        let mut derived_key = [0u8; 32];
        hk.expand(b"bitchat-v1-encryption", &mut derived_key)
            .map_err(|e| anyhow!("HKDF expansion failed: {}", e))?;

        Ok(derived_key)
    }

    /// Hash data using SHA-256
    pub fn hash(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// Generate a secure random peer ID
    pub fn generate_peer_id(&self) -> [u8; 8] {
        let mut peer_id = [0u8; 8];
        OsRng.fill_bytes(&mut peer_id);
        peer_id
    }

    /// Clean up old shared secrets (call periodically)
    pub fn cleanup_old_secrets(&mut self, max_age_seconds: u64) -> usize {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let old_count = self.shared_secrets.len();
        self.shared_secrets.retain(|_, cache| {
            now - cache.last_used < max_age_seconds
        });
        
        old_count - self.shared_secrets.len()
    }

    /// Get number of cached shared secrets
    pub fn cached_secrets_count(&self) -> usize {
        self.shared_secrets.len()
    }

    /// Check if we have a shared secret for a peer
    pub fn has_shared_secret(&self, peer_id: [u8; 8]) -> bool {
        self.shared_secrets.contains_key(&peer_id)
    }

    /// Remove shared secret for a specific peer
    pub fn remove_shared_secret(&mut self, peer_id: [u8; 8]) -> bool {
        self.shared_secrets.remove(&peer_id).is_some()
    }

    /// Create message authentication code (MAC) for data integrity
    pub fn create_mac(&self, data: &[u8], key: &[u8; 32]) -> [u8; 32] {
        use hmac::{Hmac, Mac};
        type HmacSha256 = Hmac<Sha256>;
        
        let mut mac = HmacSha256::new_from_slice(key)
            .expect("HMAC can take key of any size");
        mac.update(data);
        mac.finalize().into_bytes().into()
    }

    /// Verify message authentication code
    pub fn verify_mac(&self, data: &[u8], key: &[u8; 32], expected_mac: &[u8; 32]) -> bool {
        let computed_mac = self.create_mac(data, key);
        
        // Constant-time comparison to prevent timing attacks
        use subtle::ConstantTimeEq;
        computed_mac.ct_eq(expected_mac).into()
    }

    /// Generate a cryptographically secure random nonce
    pub fn generate_nonce(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);
        nonce
    }

    /// Secure key derivation from password (for password-protected channels)
    pub fn derive_key_from_password(&self, password: &str, salt: &[u8]) -> Result<[u8; 32]> {
        use argon2::{Argon2, PasswordHasher};
        use argon2::password_hash::{PasswordHasher as _, SaltString};
        
        if salt.len() < 16 {
            return Err(anyhow!("Salt too short: minimum 16 bytes required"));
        }

        // Use first 22 bytes of salt for Argon2 (base64 encoded length requirement)
        let salt_string = SaltString::encode_b64(&salt[..22])
            .map_err(|e| anyhow!("Salt encoding failed: {}", e))?;

        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.as_bytes(), &salt_string)
            .map_err(|e| anyhow!("Password hashing failed: {}", e))?;

        // Extract the first 32 bytes of the hash as our key
        let hash_bytes = hash.hash.ok_or_else(|| anyhow!("No hash in result"))?;
        if hash_bytes.len() < 32 {
            return Err(anyhow!("Hash too short"));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&hash_bytes.as_bytes()[..32]);
        Ok(key)
    }
}

// Implement zeroization for sensitive data
impl Drop for CryptoManager {
    fn drop(&mut self) {
        // Clear shared secrets
        for (_, mut cache) in self.shared_secrets.drain() {
            cache.shared_secret.zeroize();
        }
    }
}

// Utility functions for key management
pub mod utils {
    use super::*;

    /// Convert public key to hex string
    pub fn public_key_to_hex(key: &[u8; 32]) -> String {
        hex::encode(key)
    }

    /// Parse public key from hex string
    pub fn public_key_from_hex(hex_str: &str) -> Result<[u8; 32]> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| anyhow!("Invalid hex: {}", e))?;
        
        if bytes.len() != 32 {
            return Err(anyhow!("Invalid key length: expected 32 bytes"));
        }

        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    /// Generate a deterministic peer ID from a seed
    pub fn peer_id_from_seed(seed: &[u8]) -> [u8; 8] {
        let hash = Sha256::digest(seed);
        let mut peer_id = [0u8; 8];
        peer_id.copy_from_slice(&hash[..8]);
        peer_id
    }

    /// Generate peer ID from device name (for consistency across platforms)
    pub fn peer_id_from_device_name(device_name: &str) -> [u8; 8] {
        peer_id_from_seed(device_name.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_manager_creation() {
        let crypto = CryptoManager::new().unwrap();
        assert_eq!(crypto.public_key().len(), 32);
    }

    #[test]
    fn test_key_generation() {
        let crypto = CryptoManager::new().unwrap();
        let key1 = crypto.generate_random_key();
        let key2 = crypto.generate_random_key();
        
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 32);
    }

    #[test]
    fn test_signing_and_verification() {
        let crypto = CryptoManager::new().unwrap();
        let message = b"Hello, BitChat!";
        
        let signature = crypto.sign_message(message);
        assert!(crypto.verify_signature(message, &signature).unwrap());
        
        // Test with wrong message
        let wrong_message = b"Wrong message";
        assert!(!crypto.verify_signature(wrong_message, &signature).unwrap());
    }

    #[test]
    fn test_encryption_decryption() {
        let crypto = CryptoManager::new().unwrap();
        let key = crypto.generate_random_key();
        let plaintext = b"Hello, world!";
        
        let encrypted = crypto.encrypt_with_key(plaintext, &key).unwrap();
        let decrypted = crypto.decrypt_with_key(&encrypted, &key).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_shared_secret_derivation() {
        let crypto1 = CryptoManager::new().unwrap();
        let crypto2 = CryptoManager::new().unwrap();
        
        let (secret1, public1) = crypto1.generate_shared_secret();
        let (secret2, public2) = crypto2.generate_shared_secret();
        
        let shared1 = crypto1.derive_shared_secret(secret1, &public2.to_bytes()).unwrap();
        let shared2 = crypto2.derive_shared_secret(secret2, &public1.to_bytes()).unwrap();
        
        assert_eq!(shared1, shared2);
    }
}