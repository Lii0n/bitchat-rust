use anyhow::Result;
use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce
};
use rand::RngCore;

/// Cryptographic key pair
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        
        Self {
            signing_key,
            verifying_key,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature {
        self.signing_key.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.verifying_key
            .verify(message, signature)
            .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))
    }
}

/// Crypto manager for encryption, decryption, and key management
pub struct CryptoManager {
    pub keypair: KeyPair,
}

impl CryptoManager {
    pub fn new() -> Result<Self> {
        Ok(Self {
            keypair: KeyPair::generate(),
        })
    }

    pub fn from_keypair(keypair: KeyPair) -> Self {
        Self { keypair }
    }

    /// Generate a shared secret using X25519 key exchange
    pub fn generate_shared_secret(&self) -> (EphemeralSecret, X25519PublicKey) {
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        (secret, public)
    }

    /// Derive shared secret from our private key and their public key
    pub fn derive_shared_secret(&self, our_secret: EphemeralSecret, their_public: &X25519PublicKey) -> SharedSecret {
        our_secret.diffie_hellman(their_public)
    }

    /// Encrypt data using ChaCha20-Poly1305
    pub fn encrypt(&self, data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key)?;
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher
            .encrypt(nonce, data)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        
        // Prepend nonce to ciphertext
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce_bytes);
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }

    /// Decrypt data using ChaCha20-Poly1305
    pub fn decrypt(&self, encrypted_data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>> {
        if encrypted_data.len() < 12 {
            return Err(anyhow::anyhow!("Encrypted data too short"));
        }
        
        let cipher = ChaCha20Poly1305::new_from_slice(key)?;
        
        // Extract nonce and ciphertext
        let (nonce_bytes, ciphertext) = encrypted_data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        
        Ok(plaintext)
    }

    /// Create a signature for a message
    pub fn sign_message(&self, message: &[u8]) -> Signature {
        self.keypair.sign(message)
    }

    /// Verify a signature for a message using a public key
    pub fn verify_signature(&self, message: &[u8], signature: &Signature, public_key: &VerifyingKey) -> Result<()> {
        public_key
            .verify(message, signature)
            .map_err(|e| anyhow::anyhow!("Signature verification failed: {}", e))
    }

    /// Generate a random key for symmetric encryption
    pub fn generate_random_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    /// Derive a key from shared secret using simple key derivation
    pub fn derive_key_from_shared_secret(&self, shared_secret: &SharedSecret) -> [u8; 32] {
        *shared_secret.as_bytes()
    }

    /// Get our public verifying key
    pub fn get_public_key(&self) -> &VerifyingKey {
        &self.keypair.verifying_key
    }

    /// Get our signing key (use carefully)
    pub fn get_signing_key(&self) -> &SigningKey {
        &self.keypair.signing_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = KeyPair::generate();
        let message = b"test message";
        let signature = keypair.sign(message);
        assert!(keypair.verify(message, &signature).is_ok());
    }

    #[test]
    fn test_encryption_decryption() {
        let crypto = CryptoManager::new().unwrap();
        let key = crypto.generate_random_key();
        let plaintext = b"Hello, world!";
        
        let encrypted = crypto.encrypt(plaintext, &key).unwrap();
        let decrypted = crypto.decrypt(&encrypted, &key).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_key_exchange() {
        let crypto1 = CryptoManager::new().unwrap();
        let crypto2 = CryptoManager::new().unwrap();
        
        let (secret1, public1) = crypto1.generate_shared_secret();
        let (secret2, public2) = crypto2.generate_shared_secret();
        
        let shared1 = crypto1.derive_shared_secret(secret1, &public2);
        let shared2 = crypto2.derive_shared_secret(secret2, &public1);
        
        assert_eq!(shared1.as_bytes(), shared2.as_bytes());
    }
}