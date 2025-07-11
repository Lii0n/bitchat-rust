//! BitChat Protocol Implementation
//! 
//! This module implements the universal binary protocol used by all BitChat platforms,
//! ensuring 100% compatibility between Rust, iOS, and Android implementations.

pub mod binary;
pub mod packet;
pub mod router;

// Re-export main types
pub use binary::BinaryProtocolManager;
pub use packet::{BitchatPacket, MessageType, flags, special_recipients, peer_utils, PROTOCOL_VERSION, MAX_TTL};
pub use router::{PacketRouter, PacketAction, MessageProcessor, DefaultMessageProcessor, process_packet_content};
