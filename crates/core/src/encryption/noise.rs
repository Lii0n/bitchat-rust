//! Noise Protocol XX Implementation for BitChat Moon Protocol
//! 
//! This module implements the Noise XX pattern using the snow library,
//! providing the standardized handshake that iOS BitChat clients expect.

use anyhow::{Result, anyhow};
use snow::{Builder, HandshakeState, TransportState};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};
use zeroize::ZeroizeOnDrop;

// ============================================================================
// NOISE PROTOCOL CONSTANTS
// ============================================================================

const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_MESSAGE_SIZE: usize = 65535;
const NOISE_MAX_HANDSHAKE_SIZE: usize = 1024;
const NOISE_TAG_SIZE: usize = 16;
const NOISE_MAX_MESSAGES_PER_SESSION: u64 = 10000;
const NOISE_SESSION_TIMEOUT_SECS: u64 = 3600;

// ============================================================================
// NOISE SESSION MANAGEMENT
// ============================================================================

/// Noise Protocol session state
#[derive(ZeroizeOnDrop)]
pub struct NoiseSession {
    /// Peer identifier
    peer_id: String,
    
    /// Current transport state (after handshake completion)
    #[zeroize(skip)]  // TransportState doesn't implement Zeroize
    transport: Option<TransportState>,
    
    /// Remote peer's static public key (for verification)
    remote_static_key: Option<[u8; 32]>,
    
    /// Session creation time
    #[zeroize(skip)]
    created_at: Instant,
    
    /// Message counter for this session
    message_count: u64,
    
    /// Whether we initiated this session
    is_initiator: bool,
}

impl std::fmt::Debug for NoiseSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseSession")
            .field("peer_id", &self.peer_id)
            .field("has_transport", &self.transport.is_some())
            .field("created_at", &self.created_at)
            .field("message_count", &self.message_count)
            .field("is_initiator", &self.is_initiator)
            .finish()
    }
}

impl NoiseSession {
    /// Create new session from completed handshake
    fn new(peer_id: String, transport: TransportState, remote_static_key: Option<[u8; 32]>, is_initiator: bool) -> Self {
        Self {
            peer_id,
            transport: Some(transport),
            remote_static_key,
            created_at: Instant::now(),
            message_count: 0,
            is_initiator,
        }
    }
    
    /// Encrypt message using transport state
    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let transport = self.transport.as_mut()
            .ok_or_else(|| anyhow!("No transport state for session"))?;
        
        if plaintext.len() > MAX_MESSAGE_SIZE {
            return Err(anyhow!("Message too large: {} bytes", plaintext.len()));
        }
        
        let mut ciphertext = vec![0u8; plaintext.len() + NOISE_TAG_SIZE];
        let len = transport.write_message(plaintext, &mut ciphertext)
            .map_err(|e| anyhow!("Noise encryption failed: {}", e))?;
        
        ciphertext.truncate(len);
        self.message_count += 1;
        
        debug!("🔒 Encrypted {} bytes for {}", len, self.peer_id);
        Ok(ciphertext)
    }
    
    /// Decrypt message using transport state
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let transport = self.transport.as_mut()
            .ok_or_else(|| anyhow!("No transport state for session"))?;
        
        let mut plaintext = vec![0u8; ciphertext.len()];
        let len = transport.read_message(ciphertext, &mut plaintext)
            .map_err(|e| anyhow!("Noise decryption failed: {}", e))?;
        
        plaintext.truncate(len);
        
        debug!("🔓 Decrypted {} bytes from {}", len, self.peer_id);
        Ok(plaintext)
    }
    
    /// Check if session needs renewal
    pub fn needs_renewal(&self) -> bool {
        let age = self.created_at.elapsed();
        let timeout = Duration::from_secs(NOISE_SESSION_TIMEOUT_SECS);
        
        age > timeout || self.message_count > NOISE_MAX_MESSAGES_PER_SESSION
    }
    
    /// Get remote peer's static key
    pub fn remote_static_key(&self) -> Option<[u8; 32]> {
        self.remote_static_key
    }
}

// ============================================================================
// HANDSHAKE STATE MANAGEMENT  
// ============================================================================

/// Active handshake state
struct ActiveHandshake {
    state: HandshakeState,
    peer_id: String,
    created_at: Instant,
    is_initiator: bool,
}

impl std::fmt::Debug for ActiveHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ActiveHandshake")
            .field("peer_id", &self.peer_id)
            .field("is_initiator", &self.is_initiator)
            .field("created_at", &self.created_at)
            .finish()
    }
}

// ============================================================================
// MAIN NOISE MANAGER
// ============================================================================

/// Manages Noise Protocol sessions and handshakes
pub struct NoiseManager {
    /// Our static keypair
    static_keypair: snow::Keypair,
    
    /// Active sessions by peer ID
    sessions: HashMap<String, NoiseSession>,
    
    /// Active handshakes by peer ID
    handshakes: HashMap<String, ActiveHandshake>,
    
    /// Statistics
    stats: NoiseStats,
}

impl std::fmt::Debug for NoiseManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NoiseManager")
            .field("sessions", &self.sessions.len())
            .field("handshakes", &self.handshakes.len())
            .field("stats", &self.stats)
            .finish()
    }
}

#[derive(Debug, Clone, Default)]
pub struct NoiseStats {
    pub active_sessions: usize,
    pub active_handshakes: usize,
    pub total_handshakes: u64,
    pub total_messages: u64,
    pub failed_handshakes: u64,
    pub expired_sessions: u64,
}

impl NoiseManager {
    /// Create new Noise manager with random keypair
    pub fn new() -> Result<Self> {
        let builder = Builder::new(NOISE_PARAMS.parse()?);
        
        let static_keypair = builder.generate_keypair()?;
        
        info!("🔑 Generated Noise static keypair: {}", 
              hex::encode(&static_keypair.public[..8]));
        
        Ok(Self {
            static_keypair,
            sessions: HashMap::new(),
            handshakes: HashMap::new(),
            stats: NoiseStats::default(),
        })
    }
    
    /// Create Noise manager with existing keypair
    pub fn with_keypair(private_key: [u8; 32]) -> Result<Self> {
        let builder = Builder::new(NOISE_PARAMS.parse()?)
            .local_private_key(&private_key);
        let static_keypair = builder.generate_keypair()?;
        
        info!("🔑 Loaded Noise static keypair: {}", 
              hex::encode(&static_keypair.public[..8]));
        
        Ok(Self {
            static_keypair,
            sessions: HashMap::new(),
            handshakes: HashMap::new(),
            stats: NoiseStats::default(),
        })
    }
    
    /// Get our static public key
    pub fn our_static_public_key(&self) -> &[u8] {
        &self.static_keypair.public
    }
    
    /// Initiate handshake with peer (XX pattern message 1: -> e)
    pub fn initiate_handshake(&mut self, peer_id: &str) -> Result<Vec<u8>> {
        if self.handshakes.contains_key(peer_id) {
            return Err(anyhow!("Handshake already active with {}", peer_id));
        }
        
        if self.sessions.contains_key(peer_id) {
            debug!("Session already exists with {}, initiating rekey", peer_id);
        }
        
        // Build handshake state as initiator
        let builder = Builder::new(NOISE_PARAMS.parse()?)
            .local_private_key(&self.static_keypair.private)
            .build_initiator()?;
        
        let mut handshake_state = builder;
        let mut buffer = vec![0u8; NOISE_MAX_HANDSHAKE_SIZE];
        
        // Send first message (-> e)
        let len = handshake_state.write_message(&[], &mut buffer)
            .map_err(|e| anyhow!("Failed to write handshake message 1: {}", e))?;
        
        buffer.truncate(len);
        
        // Store handshake state
        let handshake = ActiveHandshake {
            state: handshake_state,
            peer_id: peer_id.to_string(),
            created_at: Instant::now(),
            is_initiator: true,
        };
        
        self.handshakes.insert(peer_id.to_string(), handshake);
        self.stats.total_handshakes += 1;
        self.update_stats();
        
        info!("🤝 Initiated Noise handshake with {} ({} bytes)", peer_id, len);
        Ok(buffer)
    }
    
    /// Handle incoming handshake message
    pub fn handle_handshake_message(&mut self, peer_id: &str, message: &[u8]) -> Result<Option<Vec<u8>>> {
        // Check if we have an active handshake
        if let Some(handshake) = self.handshakes.remove(peer_id) {
            // Continue existing handshake
            self.continue_handshake(peer_id, handshake, message)
        } else {
            // New handshake from peer (we are responder)
            self.start_responder_handshake(peer_id, message)
        }
    }
    
    /// Continue existing handshake
    fn continue_handshake(&mut self, peer_id: &str, mut handshake: ActiveHandshake, message: &[u8]) -> Result<Option<Vec<u8>>> {
        let mut buffer = vec![0u8; NOISE_MAX_HANDSHAKE_SIZE];
        let mut payload = Vec::new();
        
        // Read the incoming message
        let _len = handshake.state.read_message(message, &mut payload)
            .map_err(|e| anyhow!("Failed to read handshake message: {}", e))?;
        
        // Check if handshake is complete
        if handshake.state.is_handshake_finished() {
            // Handshake complete - create session
            let transport = handshake.state.into_transport_mode()
                .map_err(|e| anyhow!("Failed to enter transport mode: {}", e))?;
            
            let remote_static_key = transport.get_remote_static().map(|k| {
                let mut key = [0u8; 32];
                key.copy_from_slice(k);
                key
            });
            
            let session = NoiseSession::new(
                peer_id.to_string(),
                transport,
                remote_static_key,
                handshake.is_initiator
            );
            
            self.sessions.insert(peer_id.to_string(), session);
            self.update_stats();
            
            info!("✅ Noise handshake completed with {}", peer_id);
            Ok(None) // No response needed
        } else {
            // Need to send response
            let len = handshake.state.write_message(&[], &mut buffer)
                .map_err(|e| anyhow!("Failed to write handshake response: {}", e))?;
            
            buffer.truncate(len);
            
            // Put handshake back if not finished
            if !handshake.state.is_handshake_finished() {
                self.handshakes.insert(peer_id.to_string(), handshake);
                self.update_stats();
            }
            
            debug!("🤝 Sent handshake response to {} ({} bytes)", peer_id, len);
            Ok(Some(buffer))
        }
    }
    
    /// Start new handshake as responder
    fn start_responder_handshake(&mut self, peer_id: &str, message: &[u8]) -> Result<Option<Vec<u8>>> {
        // Build handshake state as responder
        let builder = Builder::new(NOISE_PARAMS.parse()?)
            .local_private_key(&self.static_keypair.private)
            .build_responder()?;
        
        let mut handshake_state = builder;
        let mut payload = Vec::new();
        
        // Read first message (<- e)
        let _len = handshake_state.read_message(message, &mut payload)
            .map_err(|e| anyhow!("Failed to read initial handshake: {}", e))?;
        
        // Send response message (-> e, ee, s, es)
        let mut buffer = vec![0u8; NOISE_MAX_HANDSHAKE_SIZE];
        let len = handshake_state.write_message(&[], &mut buffer)
            .map_err(|e| anyhow!("Failed to write handshake response: {}", e))?;
        
        buffer.truncate(len);
        
        // Store handshake state for final message
        let handshake = ActiveHandshake {
            state: handshake_state,
            peer_id: peer_id.to_string(),
            created_at: Instant::now(),
            is_initiator: false,
        };
        
        self.handshakes.insert(peer_id.to_string(), handshake);
        self.stats.total_handshakes += 1;
        self.update_stats();
        
        info!("🤝 Started responder handshake with {} ({} bytes)", peer_id, len);
        Ok(Some(buffer))
    }
    
    /// Encrypt message for peer
    pub fn encrypt_message(&mut self, peer_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let session = self.sessions.get_mut(peer_id)
            .ok_or_else(|| anyhow!("No session with peer {}", peer_id))?;
        
        if session.needs_renewal() {
            return Err(anyhow!("Session with {} needs renewal", peer_id));
        }
        
        let ciphertext = session.encrypt(plaintext)?;
        self.stats.total_messages += 1;
        Ok(ciphertext)
    }
    
    /// Decrypt message from peer
    pub fn decrypt_message(&mut self, peer_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let session = self.sessions.get_mut(peer_id)
            .ok_or_else(|| anyhow!("No session with peer {}", peer_id))?;
        
        session.decrypt(ciphertext)
    }
    
    /// Check if we have an active session with peer
    pub fn has_session(&self, peer_id: &str) -> bool {
        self.sessions.contains_key(peer_id)
    }
    
    /// Check if we have an active handshake with peer  
    pub fn has_handshake(&self, peer_id: &str) -> bool {
        self.handshakes.contains_key(peer_id)
    }
    
    /// Remove session (for cleanup or rekey)
    pub fn remove_session(&mut self, peer_id: &str) -> bool {
        let existed = self.sessions.remove(peer_id).is_some();
        if existed {
            self.update_stats();
            debug!("🗑️ Removed session with {}", peer_id);
        }
        existed
    }
    
    /// Clean up expired sessions and handshakes
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        let handshake_timeout = Duration::from_secs(30); // 30 second handshake timeout
        
        // Clean up expired handshakes
        let expired_handshakes: Vec<String> = self.handshakes
            .iter()
            .filter(|(_, h)| now.duration_since(h.created_at) > handshake_timeout)
            .map(|(id, _)| id.clone())
            .collect();
        
        let expired_handshake_count = expired_handshakes.len();
        
        for peer_id in expired_handshakes {
            self.handshakes.remove(&peer_id);
            self.stats.failed_handshakes += 1;
            warn!("⏰ Expired handshake with {}", peer_id);
        }
        
        // Clean up expired sessions
        let expired_sessions: Vec<String> = self.sessions
            .iter()
            .filter(|(_, s)| s.needs_renewal())
            .map(|(id, _)| id.clone())
            .collect();
        
        let expired_session_count = expired_sessions.len();
        
        for peer_id in expired_sessions {
            self.sessions.remove(&peer_id);
            self.stats.expired_sessions += 1;
            warn!("⏰ Expired session with {}", peer_id);
        }
        
        if expired_handshake_count > 0 || expired_session_count > 0 {
            self.update_stats();
        }
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> NoiseStats {
        self.stats.clone()
    }
    
    /// Get list of active peers
    pub fn active_peers(&self) -> Vec<String> {
        self.sessions.keys().cloned().collect()
    }
    
    /// Update internal statistics
    fn update_stats(&mut self) {
        self.stats.active_sessions = self.sessions.len();
        self.stats.active_handshakes = self.handshakes.len();
    }
}

impl Default for NoiseManager {
    fn default() -> Self {
        Self::new().expect("Failed to create Noise manager")
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_noise_handshake() {
        let mut alice = NoiseManager::new().unwrap();
        let mut bob = NoiseManager::new().unwrap();
        
        // Alice initiates handshake
        let msg1 = alice.initiate_handshake("bob").unwrap();
        
        // Bob responds
        let msg2 = bob.handle_handshake_message("alice", &msg1).unwrap().unwrap();
        
        // Alice completes handshake
        let result = alice.handle_handshake_message("bob", &msg2).unwrap();
        assert!(result.is_none()); // No final message in XX pattern
        
        // Both should have sessions now
        assert!(alice.has_session("bob"));
        assert!(bob.has_session("alice"));
    }
    
    #[tokio::test] 
    async fn test_noise_encryption() {
        let mut alice = NoiseManager::new().unwrap();
        let mut bob = NoiseManager::new().unwrap();
        
        // Complete handshake first
        let msg1 = alice.initiate_handshake("bob").unwrap();
        let msg2 = bob.handle_handshake_message("alice", &msg1).unwrap().unwrap();
        alice.handle_handshake_message("bob", &msg2).unwrap();
        
        // Test encryption/decryption
        let plaintext = b"Hello, Noise Protocol!";
        let ciphertext = alice.encrypt_message("bob", plaintext).unwrap();
        let decrypted = bob.decrypt_message("alice", &ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
}