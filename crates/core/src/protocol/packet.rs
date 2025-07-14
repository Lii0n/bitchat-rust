//! Packet definition for BitChat protocol

use serde::{Deserialize, Serialize};

// Protocol constants
pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 13;  
pub const PEER_ID_SIZE: usize = 8;
pub const SIGNATURE_SIZE: usize = 64;
pub const MAX_TTL: u8 = 7;

// Flag constants
pub mod flags {
    /// Indicates packet has a recipient ID field
    pub const HAS_RECIPIENT: u8 = 0x01;
    
    /// Indicates packet has a signature field
    pub const HAS_SIGNATURE: u8 = 0x02;
    
    /// Indicates payload is compressed with LZ4 (ADD THIS)
    pub const IS_COMPRESSED: u8 = 0x04;
    
    // Keep any other existing flags you have
}

/// Message types for BitChat protocol
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
    ChannelAnnounce = 8,
    ChannelRetention = 9,
    DeliveryAck = 10,
    DeliveryStatusRequest = 11,
    ReadReceipt = 12,
    ChannelJoin = 13,
    ChannelLeave = 14,
}

impl MessageType {
    /// Try to convert from u8
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

impl From<u8> for MessageType {
    fn from(value: u8) -> Self {
        Self::try_from_u8(value).unwrap_or(MessageType::Message)
    }
}

/// Main packet structure for BitChat
#[derive(Debug, Clone)]
pub struct BitchatPacket {
    pub version: u8,
    pub message_type: MessageType,
    pub ttl: u8,
    pub timestamp: u64,
    pub flags: u8,
    pub sender_id: [u8; 8],
    pub recipient_id: Option<[u8; 8]>,
    pub payload: Vec<u8>,
    pub signature: Option<Vec<u8>>, // Changed from [u8; 64] to Vec<u8> for Serde compatibility
}

// Manual Serialize/Deserialize implementation
impl serde::Serialize for BitchatPacket {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("BitchatPacket", 9)?;
        state.serialize_field("version", &self.version)?;
        state.serialize_field("message_type", &self.message_type)?;
        state.serialize_field("ttl", &self.ttl)?;
        state.serialize_field("timestamp", &self.timestamp)?;
        state.serialize_field("flags", &self.flags)?;
        state.serialize_field("sender_id", &self.sender_id.as_slice())?;
        let recipient_slice: Option<&[u8]> = self.recipient_id.as_ref().map(|id| id.as_slice());
        state.serialize_field("recipient_id", &recipient_slice)?;
        state.serialize_field("payload", &self.payload)?;
        state.serialize_field("signature", &self.signature)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for BitchatPacket {
    fn deserialize<D>(deserializer: D) -> Result<BitchatPacket, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::{self, MapAccess, Visitor};
        use std::fmt;

        struct BitchatPacketVisitor;

        impl<'de> Visitor<'de> for BitchatPacketVisitor {
            type Value = BitchatPacket;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("struct BitchatPacket")
            }

            fn visit_map<V>(self, mut map: V) -> Result<BitchatPacket, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut version = None;
                let mut message_type = None;
                let mut ttl = None;
                let mut timestamp = None;
                let mut flags = None;
                let mut sender_id = None;
                let mut recipient_id = None;
                let mut payload = None;
                let mut signature = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "version" => version = Some(map.next_value()?),
                        "message_type" => message_type = Some(map.next_value()?),
                        "ttl" => ttl = Some(map.next_value()?),
                        "timestamp" => timestamp = Some(map.next_value()?),
                        "flags" => flags = Some(map.next_value()?),
                        "sender_id" => {
                            let bytes: Vec<u8> = map.next_value()?;
                            if bytes.len() != 8 {
                                return Err(de::Error::custom("sender_id must be 8 bytes"));
                            }
                            let mut array = [0u8; 8];
                            array.copy_from_slice(&bytes);
                            sender_id = Some(array);
                        }
                        "recipient_id" => {
                            let bytes_opt: Option<Vec<u8>> = map.next_value()?;
                            recipient_id = if let Some(bytes) = bytes_opt {
                                if bytes.len() != 8 {
                                    return Err(de::Error::custom("recipient_id must be 8 bytes"));
                                }
                                let mut array = [0u8; 8];
                                array.copy_from_slice(&bytes);
                                Some(Some(array))
                            } else {
                                Some(None)
                            };
                        }
                        "payload" => payload = Some(map.next_value()?),
                        "signature" => signature = Some(map.next_value()?),
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }

                Ok(BitchatPacket {
                    version: version.ok_or_else(|| de::Error::missing_field("version"))?,
                    message_type: message_type.ok_or_else(|| de::Error::missing_field("message_type"))?,
                    ttl: ttl.ok_or_else(|| de::Error::missing_field("ttl"))?,
                    timestamp: timestamp.ok_or_else(|| de::Error::missing_field("timestamp"))?,
                    flags: flags.ok_or_else(|| de::Error::missing_field("flags"))?,
                    sender_id: sender_id.ok_or_else(|| de::Error::missing_field("sender_id"))?,
                    recipient_id: recipient_id.ok_or_else(|| de::Error::missing_field("recipient_id"))?,
                    payload: payload.ok_or_else(|| de::Error::missing_field("payload"))?,
                    signature: signature.ok_or_else(|| de::Error::missing_field("signature"))?,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &["version", "message_type", "ttl", "timestamp", "flags", "sender_id", "recipient_id", "payload", "signature"];
        deserializer.deserialize_struct("BitchatPacket", FIELDS, BitchatPacketVisitor)
    }
}

impl BitchatPacket {
    /// Create a new broadcast packet
    pub fn new_broadcast(
        message_type: MessageType,
        sender_id: [u8; 8],
        payload: Vec<u8>,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type,
            ttl: MAX_TTL,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            flags: 0,
            sender_id,
            recipient_id: None,
            payload,
            signature: None,
        }
    }

    /// Create a new private packet
    pub fn new_private(
        message_type: MessageType,
        sender_id: [u8; 8],
        recipient_id: [u8; 8],
        payload: Vec<u8>,
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type,
            ttl: MAX_TTL,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            flags: flags::HAS_RECIPIENT,
            sender_id,
            recipient_id: Some(recipient_id),
            payload,
            signature: None,
        }
    }

    /// Calculate the serialized size of this packet
    pub fn serialized_size(&self) -> usize {
        let mut size = HEADER_SIZE + PEER_ID_SIZE; // Header + sender_id
        
        if self.flags & flags::HAS_RECIPIENT != 0 {
            size += PEER_ID_SIZE;
        }
        
        size += self.payload.len();
        
        if self.flags & flags::HAS_SIGNATURE != 0 {
            size += SIGNATURE_SIZE;
        }
        
        size
    }

    /// Check if packet has a recipient
    pub fn has_recipient(&self) -> bool {
        self.flags & flags::HAS_RECIPIENT != 0
    }

    /// Check if packet has a signature
    pub fn has_signature(&self) -> bool {
        self.flags & flags::HAS_SIGNATURE != 0
    }

    /// Set signature (converts [u8; 64] to Vec<u8>)
    pub fn set_signature(&mut self, signature: [u8; 64]) {
        self.signature = Some(signature.to_vec());
        self.flags |= flags::HAS_SIGNATURE;
    }

    /// Get signature as [u8; 64] if available
    pub fn get_signature(&self) -> Option<[u8; 64]> {
        self.signature.as_ref().and_then(|sig| {
            if sig.len() == 64 {
                let mut array = [0u8; 64];
                array.copy_from_slice(sig);
                Some(array)
            } else {
                None
            }
        })
    }

    /// Check if packet is encrypted
    pub fn is_compressed(&self) -> bool {
        self.flags & flags::IS_COMPRESSED != 0
    }
}

// Legacy Packet struct for compatibility (if needed)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub sender_id: String,
    pub recipient_id: Option<String>,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
    pub timestamp: u64,
}

impl From<BitchatPacket> for Packet {
    fn from(packet: BitchatPacket) -> Self {
        Self {
            sender_id: hex::encode(packet.sender_id),
            recipient_id: packet.recipient_id.map(|id| hex::encode(id)),
            message_type: packet.message_type,
            payload: packet.payload,
            timestamp: packet.timestamp,
        }
    }
}