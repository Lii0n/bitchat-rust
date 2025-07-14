//! Protocol handling for BitChat
//! 
//! This module contains packet definitions, binary protocol management,
//! and peer utility functions for the BitChat protocol.

pub mod packet;
pub mod binary;
pub mod peer_utils;

// Re-export main types for easy access
pub use packet::{BitchatPacket, MessageType, flags};
pub use binary::BinaryProtocolManager;
pub use peer_utils::*;