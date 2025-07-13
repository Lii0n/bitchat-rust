// crates/core/src/protocol/packet.rs
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Protocol version - must match all platforms
pub const PROTOCOL_VERSION: u8 = 1;
/// Maximum TTL for message routing
pub const MAX_TTL: u8 = 7;
/// Header size in bytes
pub const HEADER_SIZE: usize = 13;
/// Peer ID size in bytes
pub const PEER_ID_SIZE: usize = 8;
/// Signature size in bytes
pub const SIGNATURE_SIZE: usize = 64;

/// Message types - EXACT same as mobile versions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    Announce = 1,
    KeyExchange = 2,
    Leave = 3,
    Message = 4,
    FragmentStart = 5,
    FragmentContinue = 6,
    FragmentEnd = 7,
    ChannelAnnounce = 8,        // NEW: For channel discovery
    ChannelRetention = 9,       // NEW: For message retention settings
    DeliveryAck = 10,          // NEW: For delivery confirmations
    DeliveryStatusRequest = 11, // NEW: For requesting delivery status
    ReadReceipt = 12,          // NEW: For read receipts
    ChannelJoin = 13,          // NEW: For joining channels
    ChannelLeave = 14,         // NEW: For leaving channels
}

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        match value {
            1 => MessageType::Announce,
            2 => MessageType::KeyExchange,
            3 => MessageType::Leave,
            4 => MessageType::Message,
            5 => MessageType::FragmentStart,
            6 => MessageType::FragmentContinue,
            7 => MessageType::FragmentEnd,
            8 => MessageType::ChannelAnnounce,
            9 => MessageType::ChannelRetention,
            10 => MessageType::DeliveryAck,
            11 => MessageType::DeliveryStatusRequest,
            12 => MessageType::ReadReceipt,
            13 => MessageType::ChannelJoin,
            14 => MessageType::ChannelLeave,
            _ => MessageType::Message, // Default fallback
        }
    }
}

impl MessageType {
    /// Try to create MessageType from u8, returning error for invalid values
    pub fn try_from_u8(value: u8) -> anyhow::Result<Self> {
        match value {
            1 => Ok(MessageType::Announce),
            2 => Ok(MessageType::KeyExchange),
            3 => Ok(MessageType::Leave),
            4 => Ok(MessageType::Message),
            5 => Ok(MessageType::FragmentStart),
            6 => Ok(MessageType::FragmentContinue),
            7 => Ok(MessageType::FragmentEnd),
            8 => Ok(MessageType::ChannelAnnounce),
            9 => Ok(MessageType::ChannelRetention),
            10 => Ok(MessageType::DeliveryAck),
            11 => Ok(MessageType::DeliveryStatusRequest),
            12 => Ok(MessageType::ReadReceipt),
            13 => Ok(MessageType::ChannelJoin),
            14 => Ok(MessageType::ChannelLeave),
            _ => Err(anyhow::anyhow!("Invalid message type: {}", value)),
        }
    }
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Announce => write!(f, "ANNOUNCE"),
            MessageType::KeyExchange => write!(f, "KEY_EXCHANGE"),
            MessageType::Leave => write!(f, "LEAVE"),
            MessageType::Message => write!(f, "MESSAGE"),
            MessageType::FragmentStart => write!(f, "FRAGMENT_START"),
            MessageType::FragmentContinue => write!(f, "FRAGMENT_CONTINUE"),
            MessageType::FragmentEnd => write!(f, "FRAGMENT_END"),
            MessageType::ChannelAnnounce => write!(f, "CHANNEL_ANNOUNCE"),
            MessageType::ChannelRetention => write!(f, "CHANNEL_RETENTION"),
            MessageType::DeliveryAck => write!(f, "DELIVERY_ACK"),
            MessageType::DeliveryStatusRequest => write!(f, "DELIVERY_STATUS_REQUEST"),
            MessageType::ReadReceipt => write!(f, "READ_RECEIPT"),
            MessageType::ChannelJoin => write!(f, "CHANNEL_JOIN"),
            MessageType::ChannelLeave => write!(f, "CHANNEL_LEAVE"),
        }
    }
}

/// Packet flags - EXACT same as mobile versions
pub mod flags {
    pub const HAS_RECIPIENT: u8 = 0x01;
    pub const HAS_SIGNATURE: u8 = 0x02;
    pub const IS_COMPRESSED: u8 = 0x04;
}

/// Special recipient IDs
pub mod special_recipients {
    /// Broadcast to all peers (all 0xFF bytes)
    pub const BROADCAST: [u8; 8] = [0xFF; 8];
}

/// Universal BitChat packet structure
#[derive(Debug, Clone, PartialEq)]
pub struct BitchatPacket {
    /// Protocol version (always 1)
    pub version: u8,
    /// Message type
    pub message_type: MessageType,
    /// Time-to-live for routing
    pub ttl: u8,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
    /// Packet flags
    pub flags: u8,
    /// Sender's peer ID (8 bytes)
    pub sender_id: [u8; 8],
    /// Optional recipient ID (8 bytes, present if HAS_RECIPIENT flag set)
    pub recipient_id: Option<[u8; 8]>,
    /// Message payload
    pub payload: Vec<u8>,
    /// Optional signature (64 bytes, present if HAS_SIGNATURE flag set)
    pub signature: Option<[u8; 64]>,
}

impl BitchatPacket {
    /// Create a new packet with current timestamp
    pub fn new(
        message_type: MessageType,
        sender_id: [u8; 8],
        payload: Vec<u8>,
    ) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;

        Self {
            version: PROTOCOL_VERSION,
            message_type,
            ttl: MAX_TTL,
            timestamp,
            flags: 0,
            sender_id,
            recipient_id: None,
            payload,
            signature: None,
        }
    }

    /// Create a broadcast packet
    pub fn new_broadcast(
        message_type: MessageType,
        sender_id: [u8; 8],
        payload: Vec<u8>,
    ) -> Self {
        Self::new(message_type, sender_id, payload)
    }

    /// Create a direct message packet
    pub fn new_direct(
        message_type: MessageType,
        sender_id: [u8; 8],
        recipient_id: [u8; 8],
        payload: Vec<u8>,
    ) -> Self {
        let mut packet = Self::new(message_type, sender_id, payload);
        packet.recipient_id = Some(recipient_id);
        packet.flags |= flags::HAS_RECIPIENT;
        packet
    }

    /// Check if this is a broadcast packet
    pub fn is_broadcast(&self) -> bool {
        self.recipient_id.is_none()
    }

    /// Calculate the serialized size of this packet
    pub fn serialized_size(&self) -> usize {
        let mut size = HEADER_SIZE + PEER_ID_SIZE; // Header + sender ID
        
        // Add recipient ID if present
        if self.flags & flags::HAS_RECIPIENT != 0 {
            size += PEER_ID_SIZE;
        }
        
        // Add payload size
        size += self.payload.len();
        
        // Add signature if present
        if self.flags & flags::HAS_SIGNATURE != 0 {
            size += SIGNATURE_SIZE;
        }
        
        size
    }

    /// Generate a unique ID for this packet for duplicate detection
    pub fn packet_id(&self) -> String {
        // Use sender_id + timestamp + payload hash for uniqueness
        let payload_hash = {
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            
            let mut hasher = DefaultHasher::new();
            self.payload.hash(&mut hasher);
            hasher.finish()
        };
        
        format!("{:016x}_{:016x}_{:016x}", 
                u64::from_be_bytes(self.sender_id), 
                self.timestamp, 
                payload_hash)
    }
}

/// Utility functions for peer ID handling
pub mod peer_utils {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    use anyhow::Result;

    /// Generate peer ID from device name
    pub fn peer_id_from_device_name(device_name: &str) -> [u8; 8] {
        let mut hasher = DefaultHasher::new();
        device_name.hash(&mut hasher);
        let hash = hasher.finish();
        hash.to_be_bytes()
    }

    /// Get short peer ID for logging
    pub fn short_peer_id(peer_id: &[u8; 8]) -> String {
        format!("{:02x}{:02x}{:02x}{:02x}", peer_id[0], peer_id[1], peer_id[2], peer_id[3])
    }

    /// Convert peer ID to hex string
    pub fn peer_id_to_string(peer_id: &[u8; 8]) -> String {
        hex::encode(peer_id).to_uppercase()
    }

    /// Parse hex string to peer ID
    pub fn string_to_peer_id(hex_str: &str) -> Result<[u8; 8]> {
        let bytes = hex::decode(hex_str)?;
        if bytes.len() != 8 {
            return Err(anyhow::anyhow!("Peer ID must be exactly 8 bytes"));
        }
        let mut peer_id = [0u8; 8];
        peer_id.copy_from_slice(&bytes);
        Ok(peer_id)
    }
}