use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, SharedSecret};

pub struct CryptoManager {
    signing_key: SigningKey,
    x25519_secret: Option<EphemeralSecret>,
    x25519_public: X25519PublicKey,
}

impl CryptoManager {
    pub fn new() -> Result<Self> {
        let mut secret_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut secret_bytes);
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let x25519_secret = EphemeralSecret::random_from_rng(&mut OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        Ok(Self {
            signing_key,
            x25519_secret: Some(x25519_secret),
            x25519_public,
        })
    }

    pub fn get_public_keys(&self) -> (VerifyingKey, X25519PublicKey) {
        (self.signing_key.verifying_key(), self.x25519_public)
    }

    pub fn get_combined_public_key_data(&self) -> Vec<u8> {
        let mut data = Vec::with_capacity(64);
        data.extend_from_slice(self.x25519_public.as_bytes());
        data.extend_from_slice(self.signing_key.verifying_key().as_bytes());
        data
    }

    pub fn sign_data(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }

    pub fn verify_signature(&self, data: &[u8], signature: &Signature, public_key: &VerifyingKey) -> bool {
        public_key.verify(data, signature).is_ok()
    }

    pub fn create_shared_secret(&mut self, their_public_key: &X25519PublicKey) -> Option<SharedSecret> {
        self.x25519_secret.take().map(|secret| secret.diffie_hellman(their_public_key))
    }

    pub fn encrypt_message(&self, plaintext: &[u8], shared_secret: &SharedSecret) -> Result<Vec<u8>> {
        let key = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())?;
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ciphertext = key.encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        
        let mut result = Vec::with_capacity(12 + ciphertext.len());
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt_message(&self, encrypted_data: &[u8], shared_secret: &SharedSecret) -> Result<Vec<u8>> {
        if encrypted_data.len() < 12 {
            return Err(anyhow::anyhow!("Encrypted data too short"));
        }

        let nonce = Nonce::from_slice(&encrypted_data[..12]);
        let ciphertext = &encrypted_data[12..];
        
        let key = ChaCha20Poly1305::new_from_slice(shared_secret.as_bytes())?;
        let plaintext = key.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;
        Ok(plaintext)
    }
}

impl Drop for CryptoManager {
    fn drop(&mut self) {
        // Zeroize sensitive data if possible
        // Note: SigningKey doesn't implement Zeroize in ed25519-dalek 2.x
        // The sensitive data will be cleared when the struct is dropped
    }
}
