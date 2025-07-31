// ==============================================================================
// crates/core/src/protocol/mod.rs - BitChat Protocol Module
// ==============================================================================

//! BitChat Protocol Implementation
//! 
//! This module implements the complete BitChat binary protocol with support for:
//! - Moon Protocol v1.1 (Noise Protocol Framework)  
//! - Legacy Protocol v1.0 (X25519 + AES-GCM)
//! - Binary packet encoding/decoding

pub mod binary;
pub mod constants;
pub mod router;

// Re-export existing protocol types from binary module
pub use binary::{
    BitchatPacket,
    MessageType, 
    BinaryProtocol,
    peer_utils,
    // Add any other exports that exist in your binary.rs
};

// Re-export router types
pub use router::{
    PacketRouter,
    RoutingDecision,
    DropReason,
    RouteEntry,
    RoutingStats,
    decrement_packet_ttl,
    should_forward_packet,
};

// Re-export Moon protocol types from constants
pub use constants::{
    MoonMessageType,
    ProtocolVersion,
    MessagePriority,
    PowerMode,
    MOON_PROTOCOL_VERSION,
    NOISE_PATTERN,
    NOISE_MAX_HANDSHAKE_SIZE,
    NOISE_TAG_SIZE,
    NOISE_MAX_MESSAGES_PER_SESSION,
    NOISE_SESSION_TIMEOUT_SECS,
};

// Keep the existing PROTOCOL_VERSION from bluetooth constants
#[cfg(feature = "bluetooth")]
pub use crate::bluetooth::constants::protocol::PROTOCOL_VERSION;

#[cfg(not(feature = "bluetooth"))]
pub const PROTOCOL_VERSION: u8 = 2;

// ==============================================================================
// PROTOCOL ERRORS (only define once)
// ==============================================================================

/// Protocol-specific error types
#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("Invalid message type: {0}")]
    InvalidMessageType(u8),
    
    #[error("Unsupported protocol version: {0}")]
    UnsupportedProtocolVersion(u8),
    
    #[error("Invalid packet format: {0}")]
    InvalidPacketFormat(String),
    
    #[error("Session not found for peer: {0}")]
    SessionNotFound(String),
    
    #[error("Handshake timeout for peer: {0}")]
    HandshakeTimeout(String),
    
    #[error("Rate limit exceeded for peer: {0}")]
    RateLimitExceeded(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
}

pub type ProtocolResult<T> = Result<T, ProtocolError>;