//! Protocol handling for BitChat
//! 
//! This module contains the consolidated BitChat binary protocol implementation
//! with automatic fragmentation, message deduplication, and compression support.

pub mod binary;
pub mod router;

// Re-export main types for easy access from binary module
pub use binary::{
    // Core types
    BitchatPacket, 
    MessageType, 
    flags,
    
    // Protocol manager (note: this is BinaryProtocol, not BinaryProtocolManager)
    BinaryProtocol,
    
    // Fragmentation & deduplication
    FragmentationManager,
    FragmentationStats,
    ProcessedMessage,
    ProtocolStats,
    
    // Utilities
    peer_utils,
    
    // Constants
    PROTOCOL_VERSION,
    HEADER_SIZE,
    PEER_ID_SIZE,
    SIGNATURE_SIZE,
    MESSAGE_ID_SIZE,
    MAX_TTL,
    MAX_PAYLOAD_SIZE,
    FRAGMENT_SIZE,
    COMPRESSION_THRESHOLD,
    MAX_FRAGMENTS,
};

// For backward compatibility with existing code that expects BinaryProtocolManager
pub use BinaryProtocol as BinaryProtocolManager;