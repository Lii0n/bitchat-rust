// ==============================================================================
// crates/core/src/encryption/mod.rs - BitChat Encryption Module
// ==============================================================================

//! Encryption and cryptographic operations for BitChat

// Only include the modules that actually exist
pub mod legacy;
pub mod channels;

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

// For now, use BitChatEncryption as the main manager
// Later we can create a full EncryptionManager that combines both
pub type EncryptionManager = BitChatEncryption;