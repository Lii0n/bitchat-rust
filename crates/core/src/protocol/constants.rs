// ==============================================================================
// crates/core/src/protocol/constants.rs - Moon Protocol Message Types
// ==============================================================================

//! Moon Protocol message types and protocol-specific constants.
//! 
//! This extends the existing constants without duplicating Bluetooth constants.

// Re-export shared constants from bluetooth module for now
pub use crate::bluetooth::constants::protocol::PROTOCOL_VERSION;

// Moon protocol updates the version
pub const MOON_PROTOCOL_VERSION: u8 = 2;

// ==============================================================================
// MOON PROTOCOL MESSAGE TYPES
// ==============================================================================

/// Message types for Moon protocol v1.1 (Noise Protocol)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MoonMessageType {
    // Core mesh messages (keep same values as legacy for compatibility)
    Announce = 0x01,          // Peer announcement/discovery
    Leave = 0x02,             // Graceful disconnect
    
    // Noise Protocol handshake messages  
    NoiseHandshake1 = 0x10,   // First handshake message (→ e)
    NoiseHandshake2 = 0x11,   // Second handshake message (← e, ee, s, es)
    NoiseHandshake3 = 0x12,   // Third handshake message (→ s, se)
    
    // Encrypted communications
    PrivateMessage = 0x20,    // Noise-encrypted private message
    PublicMessage = 0x21,     // Unencrypted public broadcast
    
    // Store and forward
    CachedMessage = 0x30,     // Store-and-forward delivery
    MessageAck = 0x31,        // Message acknowledgment
    
    // Network management
    PeerQuery = 0x40,         // Request peer information
    PeerResponse = 0x41,      // Peer information response
    
    // Protocol negotiation
    VersionHello = 0x50,      // Protocol version negotiation
    VersionAck = 0x51,        // Version acknowledgment
}

/// Protocol versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtocolVersion {
    Legacy = 1,   // v1.0 - X25519 + AES-GCM
    Moon = 2,     // v1.1 - Noise Protocol
}

/// Message priority levels for rate limiting
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MessagePriority {
    High = 0,    // Handshakes, ACKs
    Normal = 1,  // Private messages, queries
    Low = 2,     // Public messages, announcements
}

/// Power management modes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerMode {
    Performance,  // Full features, high battery usage
    Balanced,     // Default mode, balanced performance/battery
    PowerSaver,   // Reduced features, longer battery life
    UltraLow,     // Emergency mode, minimal battery usage
}

// ==============================================================================
// NOISE PROTOCOL CONSTANTS
// ==============================================================================

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
pub const NOISE_MAX_HANDSHAKE_SIZE: usize = 1024;
pub const NOISE_TAG_SIZE: usize = 16;
pub const NOISE_MAX_MESSAGES_PER_SESSION: u64 = 10_000;
pub const NOISE_SESSION_TIMEOUT_SECS: u64 = 3600;

// ==============================================================================
// IMPLEMENTATIONS
// ==============================================================================

impl MoonMessageType {
    /// Check if message type is a handshake message
    pub fn is_handshake(&self) -> bool {
        matches!(self, 
            MoonMessageType::NoiseHandshake1 |
            MoonMessageType::NoiseHandshake2 |
            MoonMessageType::NoiseHandshake3
        )
    }
    
    /// Check if message type requires encryption
    pub fn requires_encryption(&self) -> bool {
        matches!(self, MoonMessageType::PrivateMessage)
    }
    
    /// Get message type priority for rate limiting
    pub fn priority(&self) -> MessagePriority {
        match self {
            MoonMessageType::NoiseHandshake1 |
            MoonMessageType::NoiseHandshake2 |
            MoonMessageType::NoiseHandshake3 |
            MoonMessageType::MessageAck => MessagePriority::High,
            
            MoonMessageType::PrivateMessage |
            MoonMessageType::PeerQuery |
            MoonMessageType::PeerResponse |
            MoonMessageType::CachedMessage => MessagePriority::Normal,
            
            MoonMessageType::PublicMessage |
            MoonMessageType::Announce |
            MoonMessageType::Leave |
            MoonMessageType::VersionHello |
            MoonMessageType::VersionAck => MessagePriority::Low,
        }
    }
}

impl TryFrom<u8> for MoonMessageType {
    type Error = anyhow::Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MoonMessageType::Announce),
            0x02 => Ok(MoonMessageType::Leave),
            0x10 => Ok(MoonMessageType::NoiseHandshake1),
            0x11 => Ok(MoonMessageType::NoiseHandshake2),
            0x12 => Ok(MoonMessageType::NoiseHandshake3),
            0x20 => Ok(MoonMessageType::PrivateMessage),
            0x21 => Ok(MoonMessageType::PublicMessage),
            0x30 => Ok(MoonMessageType::CachedMessage),
            0x31 => Ok(MoonMessageType::MessageAck),
            0x40 => Ok(MoonMessageType::PeerQuery),
            0x41 => Ok(MoonMessageType::PeerResponse),
            0x50 => Ok(MoonMessageType::VersionHello),
            0x51 => Ok(MoonMessageType::VersionAck),
            _ => Err(anyhow::anyhow!("Invalid Moon message type: {}", value)),
        }
    }
}

impl TryFrom<u8> for ProtocolVersion {
    type Error = anyhow::Error;
    
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(ProtocolVersion::Legacy),
            2 => Ok(ProtocolVersion::Moon),
            _ => Err(anyhow::anyhow!("Unsupported protocol version: {}", value)),
        }
    }
}

impl From<ProtocolVersion> for u8 {
    fn from(version: ProtocolVersion) -> Self {
        version as u8
    }
}

impl ProtocolVersion {
    /// Get all supported versions in preference order
    pub fn supported_versions() -> Vec<Self> {
        vec![Self::Moon, Self::Legacy]
    }
    
    /// Get preferred version
    pub fn preferred() -> Self {
        Self::Moon
    }
    
    /// Check if version supports Noise Protocol
    pub fn supports_noise(&self) -> bool {
        matches!(self, Self::Moon)
    }
    
    /// Check if version supports channels
    pub fn supports_channels(&self) -> bool {
        matches!(self, Self::Legacy) // Channels temporarily removed in Moon
    }
}