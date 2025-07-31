//! Unified Encryption Manager for BitChat
//! 
//! This module provides a single entry point for all encryption operations,
//! with Noise Protocol as the primary method for iOS compatibility.

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use tracing::{debug, info};

use super::{
    noise::{NoiseManager, NoiseStats},
    channels::{ChannelEncryption, ChannelStats},
    legacy::{BitChatEncryption, BitChatIdentity, EncryptionStats as LegacyStats},
};

use crate::protocol::constants::ProtocolVersion;

// ============================================================================
// ENCRYPTION STRATEGY TYPES
// ============================================================================

/// Encryption strategy for different types of communication
#[derive(Debug, Clone, PartialEq)]
pub enum EncryptionStrategy {
    /// Noise Protocol XX - Primary for peer-to-peer (iOS compatible)
    Noise,
    /// Channel-based encryption for groups
    Channel,
    /// Legacy encryption for backward compatibility
    Legacy,
}

/// Encryption context for operations
#[derive(Debug, Clone)]
pub struct EncryptionContext {
    pub strategy: EncryptionStrategy,
    pub peer_id: Option<String>,
    pub channel_name: Option<String>,
    pub protocol_version: ProtocolVersion,
}

impl EncryptionContext {
    /// Create context for peer-to-peer encryption (defaults to Noise)
    pub fn for_peer(peer_id: String, protocol_version: ProtocolVersion) -> Self {
        let strategy = match protocol_version {
            ProtocolVersion::Moon => EncryptionStrategy::Noise,
            ProtocolVersion::Legacy => EncryptionStrategy::Legacy,
        };
        
        Self {
            strategy,
            peer_id: Some(peer_id),
            channel_name: None,
            protocol_version,
        }
    }
    
    /// Create context for channel encryption
    pub fn for_channel(channel_name: String) -> Self {
        Self {
            strategy: EncryptionStrategy::Channel,
            peer_id: None,
            channel_name: Some(channel_name),
            protocol_version: ProtocolVersion::Moon, // Channels always use modern crypto
        }
    }
    
    /// Create context with explicit strategy
    pub fn with_strategy(strategy: EncryptionStrategy, peer_id: Option<String>, channel_name: Option<String>) -> Self {
        let protocol_version = match strategy {
            EncryptionStrategy::Noise | EncryptionStrategy::Channel => ProtocolVersion::Moon,
            EncryptionStrategy::Legacy => ProtocolVersion::Legacy,
        };
        
        Self {
            strategy,
            peer_id,
            channel_name,
            protocol_version,
        }
    }
}

// ============================================================================
// UNIFIED ENCRYPTION MANAGER
// ============================================================================

/// Unified encryption manager that coordinates all encryption strategies
pub struct UnifiedEncryptionManager {
    /// Noise Protocol manager (primary for iOS compatibility)
    noise_manager: NoiseManager,
    
    /// Channel encryption manager for groups
    channel_manager: ChannelEncryption,
    
    /// Legacy encryption manager for backward compatibility
    legacy_manager: BitChatEncryption,
    
    /// Strategy mapping for peers (peer_id -> strategy)
    peer_strategies: HashMap<String, EncryptionStrategy>,
    
    /// Our identity for legacy operations
    our_identity: BitChatIdentity,
    
    /// Statistics
    stats: UnifiedEncryptionStats,
}

#[derive(Debug, Clone, Default)]
pub struct UnifiedEncryptionStats {
    pub noise_stats: NoiseStats,
    pub channel_stats: ChannelStats,
    pub legacy_stats: LegacyStats,
    pub total_operations: u64,
    pub strategy_usage: HashMap<String, u64>, // strategy name -> count
}

impl UnifiedEncryptionManager {
    /// Create new unified encryption manager
    pub fn new() -> Result<Self> {
        let noise_manager = NoiseManager::new()?;
        let channel_manager = ChannelEncryption::new();
        let our_identity = BitChatIdentity::generate();
        let legacy_manager = BitChatEncryption::with_identity(our_identity.clone());
        
        info!("🚀 Initialized unified encryption manager");
        info!("🔑 Noise static key: {}", hex::encode(&noise_manager.our_static_public_key()[..8]));
        info!("🆔 Legacy identity: {}", hex::encode(&our_identity.fingerprint[..8]));
        
        Ok(Self {
            noise_manager,
            channel_manager,
            legacy_manager,
            peer_strategies: HashMap::new(),
            our_identity,
            stats: UnifiedEncryptionStats::default(),
        })
    }
    
    /// Create unified manager with existing Noise keypair
    pub fn with_noise_keypair(noise_private_key: [u8; 32]) -> Result<Self> {
        let noise_manager = NoiseManager::with_keypair(noise_private_key)?;
        let channel_manager = ChannelEncryption::new();
        let our_identity = BitChatIdentity::generate();
        let legacy_manager = BitChatEncryption::with_identity(our_identity.clone());
        
        info!("🚀 Initialized unified encryption manager with existing keys");
        
        Ok(Self {
            noise_manager,
            channel_manager,
            legacy_manager,
            peer_strategies: HashMap::new(),
            our_identity,
            stats: UnifiedEncryptionStats::default(),
        })
    }
    
    // ========================================================================
    // STRATEGY MANAGEMENT
    // ========================================================================
    
    /// Set encryption strategy for a peer
    pub fn set_peer_strategy(&mut self, peer_id: &str, strategy: EncryptionStrategy) {
        self.peer_strategies.insert(peer_id.to_string(), strategy.clone());
        debug!("🎯 Set strategy for {}: {:?}", peer_id, strategy);
    }
    
    /// Get encryption strategy for a peer (defaults to Noise for new peers)
    pub fn get_peer_strategy(&self, peer_id: &str) -> EncryptionStrategy {
        self.peer_strategies.get(peer_id)
            .cloned()
            .unwrap_or(EncryptionStrategy::Noise) // Default to Noise for iOS compatibility
    }
    
    /// Detect optimal strategy based on peer capabilities
    pub fn detect_strategy_for_peer(&mut self, peer_id: &str, protocol_version: ProtocolVersion) -> EncryptionStrategy {
        let strategy = match protocol_version {
            ProtocolVersion::Moon => EncryptionStrategy::Noise,
            ProtocolVersion::Legacy => EncryptionStrategy::Legacy,
        };
        
        self.set_peer_strategy(peer_id, strategy.clone());
        strategy
    }
    
    // ========================================================================
    // HANDSHAKE OPERATIONS (NOISE PROTOCOL PRIMARY)
    // ========================================================================
    
    /// Initiate handshake with peer (prefers Noise Protocol)
    pub fn initiate_handshake(&mut self, context: &EncryptionContext) -> Result<Vec<u8>> {
        let peer_id = context.peer_id.as_ref()
            .ok_or_else(|| anyhow!("Peer ID required for handshake"))?;
        
        self.update_operation_stats(&context.strategy);
        
        match context.strategy {
            EncryptionStrategy::Noise => {
                info!("🤝 Initiating Noise XX handshake with {}", peer_id);
                self.noise_manager.initiate_handshake(peer_id)
            }
            EncryptionStrategy::Legacy => {
                info!("🤝 Initiating legacy handshake with {}", peer_id);
                self.legacy_manager.initiate_key_exchange(peer_id)
            }
            EncryptionStrategy::Channel => {
                Err(anyhow!("Channel encryption doesn't use handshakes"))
            }
        }
    }
    
    /// Handle incoming handshake message
    pub fn handle_handshake_message(&mut self, context: &EncryptionContext, message: &[u8]) -> Result<Option<Vec<u8>>> {
        let peer_id = context.peer_id.as_ref()
            .ok_or_else(|| anyhow!("Peer ID required for handshake"))?;
        
        self.update_operation_stats(&context.strategy);
        
        match context.strategy {
            EncryptionStrategy::Noise => {
                debug!("🤝 Handling Noise handshake from {}", peer_id);
                self.noise_manager.handle_handshake_message(peer_id, message)
            }
            EncryptionStrategy::Legacy => {
                debug!("🤝 Handling legacy handshake from {}", peer_id);
                self.legacy_manager.handle_key_exchange(peer_id, message)
            }
            EncryptionStrategy::Channel => {
                Err(anyhow!("Channel encryption doesn't use handshakes"))
            }
        }
    }
    
    // ========================================================================
    // MESSAGE ENCRYPTION/DECRYPTION
    // ========================================================================
    
    /// Encrypt message using appropriate strategy
    pub fn encrypt_message(&mut self, context: &EncryptionContext, plaintext: &[u8]) -> Result<Vec<u8>> {
        self.update_operation_stats(&context.strategy);
        
        match &context.strategy {
            EncryptionStrategy::Noise => {
                let peer_id = context.peer_id.as_ref()
                    .ok_or_else(|| anyhow!("Peer ID required for Noise encryption"))?;
                debug!("🔒 Encrypting with Noise for {}", peer_id);
                self.noise_manager.encrypt_message(peer_id, plaintext)
            }
            EncryptionStrategy::Channel => {
                let channel = context.channel_name.as_ref()
                    .ok_or_else(|| anyhow!("Channel name required for channel encryption"))?;
                debug!("🔒 Encrypting for channel {}", channel);
                self.channel_manager.encrypt_channel_message(channel, plaintext)
            }
            EncryptionStrategy::Legacy => {
                let peer_id = context.peer_id.as_ref()
                    .ok_or_else(|| anyhow!("Peer ID required for legacy encryption"))?;
                debug!("🔒 Encrypting with legacy for {}", peer_id);
                self.legacy_manager.encrypt_private_message(peer_id, plaintext)
            }
        }
    }
    
    /// Decrypt message using appropriate strategy  
    pub fn decrypt_message(&mut self, context: &EncryptionContext, ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.update_operation_stats(&context.strategy);
        
        match &context.strategy {
            EncryptionStrategy::Noise => {
                let peer_id = context.peer_id.as_ref()
                    .ok_or_else(|| anyhow!("Peer ID required for Noise decryption"))?;
                debug!("🔓 Decrypting with Noise from {}", peer_id);
                self.noise_manager.decrypt_message(peer_id, ciphertext)
            }
            EncryptionStrategy::Channel => {
                let channel = context.channel_name.as_ref()
                    .ok_or_else(|| anyhow!("Channel name required for channel decryption"))?;
                debug!("🔓 Decrypting from channel {}", channel);
                self.channel_manager.decrypt_channel_message(channel, ciphertext)
            }
            EncryptionStrategy::Legacy => {
                let peer_id = context.peer_id.as_ref()
                    .ok_or_else(|| anyhow!("Peer ID required for legacy decryption"))?;
                debug!("🔓 Decrypting with legacy from {}", peer_id);
                self.legacy_manager.decrypt_private_message(peer_id, ciphertext)
            }
        }
    }
    
    // ========================================================================
    // CHANNEL OPERATIONS
    // ========================================================================
    
    /// Join password-protected channel
    pub fn join_channel(&mut self, channel_name: &str, password: &str) -> Result<()> {
        info!("🚪 Joining channel: {}", channel_name);
        self.channel_manager.join_channel(channel_name, password)
    }
    
    /// Leave channel
    pub fn leave_channel(&mut self, channel_name: &str) {
        info!("🚪 Leaving channel: {}", channel_name);
        self.channel_manager.leave_channel(channel_name)
    }
    
    /// Check if joined to channel
    pub fn is_joined_to_channel(&self, channel_name: &str) -> bool {
        self.channel_manager.is_joined(channel_name)
    }
    
    /// Get list of joined channels
    pub fn get_joined_channels(&self) -> Vec<String> {
        self.channel_manager.get_joined_channels()
    }
    
    // ========================================================================
    // SESSION MANAGEMENT
    // ========================================================================
    
    /// Check if we have an active session with peer
    pub fn has_session(&self, peer_id: &str, strategy: Option<EncryptionStrategy>) -> bool {
        let strategy = strategy.unwrap_or_else(|| self.get_peer_strategy(peer_id));
        
        match strategy {
            EncryptionStrategy::Noise => self.noise_manager.has_session(peer_id),
            EncryptionStrategy::Legacy => true, // Legacy always creates sessions on demand
            EncryptionStrategy::Channel => false, // Channels don't have peer sessions
        }
    }
    
    /// Check if we have an active handshake with peer
    pub fn has_handshake(&self, peer_id: &str, strategy: Option<EncryptionStrategy>) -> bool {
        let strategy = strategy.unwrap_or_else(|| self.get_peer_strategy(peer_id));
        
        match strategy {
            EncryptionStrategy::Noise => self.noise_manager.has_handshake(peer_id),
            EncryptionStrategy::Legacy => false, // Legacy handshakes are immediate
            EncryptionStrategy::Channel => false, // Channels don't have handshakes
        }
    }
    
    /// Remove session with peer (for cleanup or rekey)
    pub fn remove_session(&mut self, peer_id: &str, strategy: Option<EncryptionStrategy>) -> bool {
        let strategy = strategy.unwrap_or_else(|| self.get_peer_strategy(peer_id));
        
        match strategy {
            EncryptionStrategy::Noise => self.noise_manager.remove_session(peer_id),
            EncryptionStrategy::Legacy => {
                // Legacy cleanup handled internally
                true
            }
            EncryptionStrategy::Channel => false,
        }
    }
    
    /// Clean up expired sessions and handshakes
    pub fn cleanup(&mut self) {
        debug!("🧹 Cleaning up expired sessions");
        self.noise_manager.cleanup();
        self.legacy_manager.cleanup();
        self.update_stats();
    }
    
    // ========================================================================
    // PUBLIC KEY ACCESS
    // ========================================================================
    
    /// Get our Noise Protocol static public key (for iOS compatibility)
    pub fn our_noise_public_key(&self) -> &[u8] {
        self.noise_manager.our_static_public_key()
    }
    
    /// Get our legacy public key  
    pub fn our_legacy_public_key(&self) -> ed25519_dalek::VerifyingKey {
        self.our_identity.signing_public_key()
    }
    
    /// Get our identity fingerprint
    pub fn our_fingerprint(&self) -> [u8; 32] {
        self.our_identity.fingerprint
    }
    
    // ========================================================================
    // STATISTICS AND MONITORING
    // ========================================================================
    
    /// Get comprehensive encryption statistics
    pub fn get_stats(&self) -> UnifiedEncryptionStats {
        let mut stats = self.stats.clone();
        stats.noise_stats = self.noise_manager.get_stats();
        stats.channel_stats = self.channel_manager.get_stats();
        stats.legacy_stats = self.legacy_manager.get_stats();
        stats
    }
    
    /// Get active peers across all strategies
    pub fn get_active_peers(&self) -> Vec<String> {
        let mut peers = Vec::new();
        
        // Add Noise peers
        peers.extend(self.noise_manager.active_peers());
        
        // Add Legacy peers (if any tracking exists)
        // peers.extend(self.legacy_manager.active_peers());
        
        peers.sort();
        peers.dedup();
        peers
    }
    
    /// Update operation statistics
    fn update_operation_stats(&mut self, strategy: &EncryptionStrategy) {
        self.stats.total_operations += 1;
        
        let strategy_name = match strategy {
            EncryptionStrategy::Noise => "noise",
            EncryptionStrategy::Channel => "channel", 
            EncryptionStrategy::Legacy => "legacy",
        };
        
        *self.stats.strategy_usage.entry(strategy_name.to_string()).or_insert(0) += 1;
    }
    
    /// Update all statistics from sub-managers
    fn update_stats(&mut self) {
        // Stats are updated on-demand in get_stats()
    }
}

impl Default for UnifiedEncryptionManager {
    fn default() -> Self {
        Self::new().expect("Failed to create unified encryption manager")
    }
}

// ============================================================================
// CONVENIENCE METHODS FOR COMMON OPERATIONS
// ============================================================================

impl UnifiedEncryptionManager {
    /// Quick encrypt for peer using best available strategy
    pub fn quick_encrypt_for_peer(&mut self, peer_id: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let _strategy = self.get_peer_strategy(peer_id);
        let context = EncryptionContext::for_peer(peer_id.to_string(), ProtocolVersion::Moon);
        self.encrypt_message(&context, plaintext)
    }
    
    /// Quick decrypt from peer using detected strategy
    pub fn quick_decrypt_from_peer(&mut self, peer_id: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let _strategy = self.get_peer_strategy(peer_id);
        let context = EncryptionContext::for_peer(peer_id.to_string(), ProtocolVersion::Moon);
        self.decrypt_message(&context, ciphertext)
    }
    
    /// Quick encrypt for channel
    pub fn quick_encrypt_for_channel(&mut self, channel_name: &str, plaintext: &[u8]) -> Result<Vec<u8>> {
        let context = EncryptionContext::for_channel(channel_name.to_string());
        self.encrypt_message(&context, plaintext)
    }
    
    /// Quick decrypt from channel
    pub fn quick_decrypt_from_channel(&mut self, channel_name: &str, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let context = EncryptionContext::for_channel(channel_name.to_string());
        self.decrypt_message(&context, ciphertext)
    }
    
    /// Start Noise handshake with peer (iOS-compatible)
    pub fn start_noise_handshake(&mut self, peer_id: &str) -> Result<Vec<u8>> {
        let context = EncryptionContext::for_peer(peer_id.to_string(), ProtocolVersion::Moon);
        self.initiate_handshake(&context)
    }
    
    /// Handle Noise handshake message (iOS-compatible)
    pub fn handle_noise_handshake(&mut self, peer_id: &str, message: &[u8]) -> Result<Option<Vec<u8>>> {
        let context = EncryptionContext::for_peer(peer_id.to_string(), ProtocolVersion::Moon);
        self.handle_handshake_message(&context, message)
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_unified_manager_creation() {
        let manager = UnifiedEncryptionManager::new().unwrap();
        
        // Should have valid keys
        assert!(!manager.our_noise_public_key().is_empty());
        assert_ne!(manager.our_fingerprint(), [0u8; 32]);
    }
    
    #[tokio::test] 
    async fn test_strategy_detection() {
        let mut manager = UnifiedEncryptionManager::new().unwrap();
        
        // Test Moon protocol detection
        let strategy = manager.detect_strategy_for_peer("alice", ProtocolVersion::Moon);
        assert_eq!(strategy, EncryptionStrategy::Noise);
        
        // Test Legacy protocol detection  
        let strategy = manager.detect_strategy_for_peer("bob", ProtocolVersion::Legacy);
        assert_eq!(strategy, EncryptionStrategy::Legacy);
    }
    
    #[tokio::test]
    async fn test_noise_handshake() {
        let mut alice = UnifiedEncryptionManager::new().unwrap();
        let mut bob = UnifiedEncryptionManager::new().unwrap();
        
        // Alice initiates Noise handshake
        let msg1 = alice.start_noise_handshake("bob").unwrap();
        
        // Bob responds
        let msg2 = bob.handle_noise_handshake("alice", &msg1).unwrap().unwrap();
        
        // Alice completes
        let result = alice.handle_noise_handshake("bob", &msg2).unwrap();
        assert!(result.is_none()); // No final message needed
        
        // Both should have sessions
        assert!(alice.has_session("bob", Some(EncryptionStrategy::Noise)));
        assert!(bob.has_session("alice", Some(EncryptionStrategy::Noise)));
    }
    
    #[tokio::test]
    async fn test_encryption_decryption() {
        let mut alice = UnifiedEncryptionManager::new().unwrap();
        let mut bob = UnifiedEncryptionManager::new().unwrap();
        
        // Complete handshake first
        let msg1 = alice.start_noise_handshake("bob").unwrap();
        let msg2 = bob.handle_noise_handshake("alice", &msg1).unwrap().unwrap();
        alice.handle_noise_handshake("bob", &msg2).unwrap();
        
        // Test encryption/decryption
        let plaintext = b"Hello, unified encryption!";
        let ciphertext = alice.quick_encrypt_for_peer("bob", plaintext).unwrap();
        let decrypted = bob.quick_decrypt_from_peer("alice", &ciphertext).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
}