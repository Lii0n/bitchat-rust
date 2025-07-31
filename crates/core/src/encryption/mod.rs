// ==============================================================================
// crates/core/src/encryption/mod.rs - BitChat Encryption Module
// ==============================================================================

//! Encryption and cryptographic operations for BitChat

// Include all encryption modules
pub mod legacy;
pub mod channels;
pub mod noise;
pub mod unified;

// Re-export types for backward compatibility
pub use legacy::{
    BitChatEncryption,
    BitChatIdentity,
    EncryptionSession,
    EncryptionStats,
};

pub use channels::{
    ChannelEncryption,
    ChannelStats,
    ChannelInfo,
};

// Re-export Noise Protocol types
pub use noise::{
    NoiseManager,
    NoiseSession,
    NoiseStats,
};

// Re-export unified encryption types (NEW PRIMARY INTERFACE)
pub use unified::{
    UnifiedEncryptionManager,
    UnifiedEncryptionStats,
    EncryptionStrategy,
    EncryptionContext,
};

// Use UnifiedEncryptionManager as the main manager (replaces BitChatEncryption)
pub type EncryptionManager = UnifiedEncryptionManager;