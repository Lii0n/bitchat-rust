//! BitChat Packet Definitions
//! 
//! Universal packet format compatible with iOS and Android

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};
use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

/// Protocol version - must match mobile versions
pub const PROTOCOL_VERSION: u8 = 1;

/// Maximum TTL for message routing
pub const MAX_TTL: u8 = 7;

/// Fixed header size in bytes
pub const HEADER_SIZE: usize = 13;

/// Fixed sender/recipient ID sizes
pub const PEER_ID_SIZE: usize = 8;
pub const SIGNATURE_SIZE: usize = 64;

/// Message types - EXACT same values as iOS/Android
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    Announce = 0x01,
    KeyExchange = 0x02,
    Leave = 0x03,
    Message = 0x04,
    FragmentStart = 0x05,
    FragmentContinue = 0x06,
    FragmentEnd = 0x07,
    ChannelAnnounce = 0x08,
    ChannelRetention = 0x09,
    DeliveryAck = 0x0A,
    DeliveryStatusRequest = 0x0B,
    ReadReceipt = 0x0C,
}

impl TryFrom<u8> for MessageType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(MessageType::Announce),
            0x02 => Ok(MessageType::KeyExchange),
            0x03 => Ok(MessageType::Leave),
            0x04 => Ok(MessageType::Message),
            0x05 => Ok(MessageType::FragmentStart),
            0x06 => Ok(MessageType::FragmentContinue),
            0x07 => Ok(MessageType::FragmentEnd),
            0x08 => Ok(MessageType::ChannelAnnounce),
            0x09 => Ok(MessageType::ChannelRetention),
            0x0A => Ok(MessageType::DeliveryAck),
            0x0B => Ok(MessageType::DeliveryStatusRequest),
            0x0C => Ok(MessageType::ReadReceipt),
            _ => Err(anyhow!("Unknown message type: 0x{:02X}", value)),
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
            .unwrap_or_default()
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

    /// Create a broadcast message (to all peers)
    pub fn new_broadcast(
        message_type: MessageType,
        sender_id: [u8; 8],
        payload: Vec<u8>,
    ) -> Self {
        Self::new(message_type, sender_id, payload)
    }

    /// Create a direct message (to specific peer)
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

    /// Check if this packet is a broadcast
    pub fn is_broadcast(&self) -> bool {
        match self.recipient_id {
            None => true,
            Some(recipient) => recipient == special_recipients::BROADCAST,
        }
    }

    /// Check if this packet is for a specific recipient
    pub fn is_for_recipient(&self, peer_id: &[u8; 8]) -> bool {
        match self.recipient_id {
            None => true, // Broadcast
            Some(recipient) => {
                recipient == special_recipients::BROADCAST || recipient == *peer_id
            }
        }
    }

    /// Set signature on this packet
    pub fn with_signature(mut self, signature: [u8; 64]) -> Self {
        self.signature = Some(signature);
        self.flags |= flags::HAS_SIGNATURE;
        self
    }

    /// Mark packet as compressed
    pub fn with_compression(mut self) -> Self {
        self.flags |= flags::IS_COMPRESSED;
        self
    }

    /// Decrement TTL for routing
    pub fn decrement_ttl(&mut self) -> bool {
        if self.ttl > 0 {
            self.ttl -= 1;
            true
        } else {
            false
        }
    }

    /// Get total packet size when serialized
    pub fn serialized_size(&self) -> usize {
        let mut size = HEADER_SIZE + PEER_ID_SIZE; // Header + sender ID

        if self.flags & flags::HAS_RECIPIENT != 0 {
            size += PEER_ID_SIZE;
        }

        size += self.payload.len();

        if self.flags & flags::HAS_SIGNATURE != 0 {
            size += SIGNATURE_SIZE;
        }

        size
    }

    /// Get unique packet ID for deduplication
    pub fn packet_id(&self) -> String {
        // Combine sender ID, timestamp, and message type for unique ID
        format!("{}-{}-{:02X}", 
                hex::encode(&self.sender_id), 
                self.timestamp, 
                self.message_type as u8)
    }

    /// Check if packet is expired (older than TTL timeout)
    pub fn is_expired(&self, max_age_ms: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        now.saturating_sub(self.timestamp) > max_age_ms
    }
}

/// Utility functions for peer ID generation and manipulation
pub mod peer_utils {
    use rand::Rng;
    use anyhow::Result;

    /// Generate a random 8-byte peer ID
    pub fn generate_peer_id() -> [u8; 8] {
        let mut rng = rand::thread_rng();
        let mut peer_id = [0u8; 8];
        rng.fill(&mut peer_id);
        peer_id
    }

    /// Convert peer ID to hex string for display
    pub fn peer_id_to_string(peer_id: &[u8; 8]) -> String {
        hex::encode(peer_id).to_uppercase()
    }

    /// Convert hex string to peer ID
    pub fn string_to_peer_id(s: &str) -> Result<[u8; 8]> {
        let bytes = hex::decode(s)?;
        if bytes.len() != 8 {
            return Err(anyhow::anyhow!("Invalid peer ID length: expected 8 bytes, got {}", bytes.len()));
        }
        let mut peer_id = [0u8; 8];
        peer_id.copy_from_slice(&bytes);
        Ok(peer_id)
    }

    /// Get short display ID (first 8 hex chars)
    pub fn short_peer_id(peer_id: &[u8; 8]) -> String {
        peer_id_to_string(peer_id)[..8].to_string()
    }

    /// Generate peer ID from device name (for compatibility)
    pub fn peer_id_from_device_name(device_name: &str) -> [u8; 8] {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        device_name.hash(&mut hasher);
        let hash = hasher.finish();
        
        // Convert u64 hash to 8 bytes
        let bytes = hash.to_be_bytes();
        bytes
    }
}
