//! Binary Protocol Manager - handles encoding/decoding of packets

use super::packet::{BitchatPacket, MessageType, flags, HEADER_SIZE, PEER_ID_SIZE, SIGNATURE_SIZE, PROTOCOL_VERSION, MAX_TTL};
use crate::protocol::peer_utils;
use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, BytesMut};
use tracing::{debug, warn};

/// Binary Protocol Manager - handles encoding/decoding
pub struct BinaryProtocolManager;

impl BinaryProtocolManager {
    /// Encode a packet to binary format (EXACT same as mobile)
    pub fn encode(packet: &BitchatPacket) -> Result<Vec<u8>> {
        let total_size = packet.serialized_size();
        let mut buffer = BytesMut::with_capacity(total_size);

        // Header (15 bytes: version(1) + type(1) + ttl(1) + timestamp(8) + flags(1) + payload_len(2))
        buffer.put_u8(packet.version);
        buffer.put_u8(packet.message_type as u8);
        buffer.put_u8(packet.ttl);
        buffer.put_u64(packet.timestamp); // Big-endian
        buffer.put_u8(packet.flags);
        buffer.put_u16(packet.payload.len() as u16); // Big-endian

        // Sender ID (8 bytes)
        buffer.put_slice(&packet.sender_id);

        // Optional recipient ID (8 bytes)
        if packet.flags & flags::HAS_RECIPIENT != 0 {
            if let Some(recipient_id) = packet.recipient_id {
                buffer.put_slice(&recipient_id);
            } else {
                return Err(anyhow!("HAS_RECIPIENT flag set but no recipient_id provided"));
            }
        }

        // Payload (variable length)
        buffer.put_slice(&packet.payload);

        // Optional signature (64 bytes)
        if packet.flags & flags::HAS_SIGNATURE != 0 {
            if let Some(ref signature) = packet.signature {
                buffer.put_slice(signature);
            } else {
                return Err(anyhow!("HAS_SIGNATURE flag set but no signature provided"));
            }
        }

        debug!(
            "Encoded packet: type={:?}, size={} bytes, TTL={}", 
            packet.message_type, 
            total_size, 
            packet.ttl
        );

        Ok(buffer.to_vec())
    }

    /// Decode binary data to packet (EXACT same as mobile)
    pub fn decode(data: &[u8]) -> Result<BitchatPacket> {
        if data.len() < HEADER_SIZE + PEER_ID_SIZE {
            return Err(anyhow!("Packet too short: {} bytes", data.len()));
        }

        let mut buffer = data;

        // Parse header (15 bytes)
        let version = buffer.get_u8();
        let message_type = MessageType::try_from_u8(buffer.get_u8())?;
        let ttl = buffer.get_u8();
        let timestamp = buffer.get_u64(); // Big-endian
        let flags = buffer.get_u8();
        let payload_length = buffer.get_u16() as usize; // Big-endian

        // Validate version
        if version != PROTOCOL_VERSION {
            return Err(anyhow!("Unsupported protocol version: {}", version));
        }

        // Parse sender ID (8 bytes)
        if buffer.remaining() < PEER_ID_SIZE {
            return Err(anyhow!("Not enough data for sender ID"));
        }
        let mut sender_id = [0u8; 8];
        buffer.copy_to_slice(&mut sender_id);

        // Parse optional recipient ID (8 bytes)
        let recipient_id = if flags & flags::HAS_RECIPIENT != 0 {
            if buffer.remaining() < PEER_ID_SIZE {
                return Err(anyhow!("Not enough data for recipient ID"));
            }
            let mut recipient = [0u8; 8];
            buffer.copy_to_slice(&mut recipient);
            Some(recipient)
        } else {
            None
        };

        // Parse payload
        if buffer.remaining() < payload_length {
            return Err(anyhow!("Not enough data for payload"));
        }
        let payload = buffer[..payload_length].to_vec();
        buffer.advance(payload_length);

        // Parse optional signature (64 bytes)
        let signature = if flags & flags::HAS_SIGNATURE != 0 {
            if buffer.remaining() < SIGNATURE_SIZE {
                return Err(anyhow!("Not enough data for signature"));
            }
            let mut sig = vec![0u8; SIGNATURE_SIZE];
            buffer.copy_to_slice(&mut sig);
            Some(sig)
        } else {
            None
        };

        Ok(BitchatPacket {
            version,
            message_type,
            ttl,
            timestamp,
            flags,
            sender_id,
            recipient_id,
            payload,
            signature,
        })
    }

    /// Create a CHANNEL_JOIN packet
    pub fn create_channel_join_packet(
        sender_id: [u8; 8],
        channel: &str,
    ) -> Result<BitchatPacket> {
        let payload = channel.as_bytes().to_vec();
        Ok(BitchatPacket::new_broadcast(
            MessageType::ChannelJoin,
            sender_id,
            payload,
        ))
    }

    /// Create a CHANNEL_LEAVE packet
    pub fn create_channel_leave_packet(
        sender_id: [u8; 8],
        channel: &str,
    ) -> Result<BitchatPacket> {
        let payload = channel.as_bytes().to_vec();
        Ok(BitchatPacket::new_broadcast(
            MessageType::ChannelLeave,
            sender_id,
            payload,
        ))
    }

    /// Create a MESSAGE packet
    pub fn create_message_packet(
        sender_id: [u8; 8],
        recipient_id: Option<[u8; 8]>,
        content: &str,
    ) -> Result<BitchatPacket> {
        let payload = content.as_bytes().to_vec();
        if let Some(recipient) = recipient_id {
            Ok(BitchatPacket::new_private(
                MessageType::Message,
                sender_id,
                recipient,
                payload,
            ))
        } else {
            Ok(BitchatPacket::new_broadcast(
                MessageType::Message,
                sender_id,
                payload,
            ))
        }
    }

    /// Create an ANNOUNCE packet
    pub fn create_announce_packet(
        sender_id: [u8; 8],
        nickname: &str,
    ) -> Result<BitchatPacket> {
        let payload = nickname.as_bytes().to_vec();
        Ok(BitchatPacket::new_broadcast(
            MessageType::Announce,
            sender_id,
            payload,
        ))
    }

    /// Create a KEY_EXCHANGE packet
    pub fn create_key_exchange_packet(
        sender_id: [u8; 8],
        recipient_id: [u8; 8],
        key_data: &[u8],
    ) -> Result<BitchatPacket> {
        Ok(BitchatPacket::new_private(
            MessageType::KeyExchange,
            sender_id,
            recipient_id,
            key_data.to_vec(),
        ))
    }

    /// Create a LEAVE packet
    pub fn create_leave_packet(
        sender_id: [u8; 8],
    ) -> Result<BitchatPacket> {
        Ok(BitchatPacket::new_broadcast(
            MessageType::Leave,
            sender_id,
            vec![],
        ))
    }

    /// Create a CHANNEL_ANNOUNCE packet
    pub fn create_channel_announce_packet(
        sender_id: [u8; 8],
        channel: &str,
        announcement: &str,
    ) -> Result<BitchatPacket> {
        let payload = format!("{}|{}", channel, announcement).into_bytes();
        Ok(BitchatPacket::new_broadcast(
            MessageType::ChannelAnnounce,
            sender_id,
            payload,
        ))
    }

    /// Validate packet structure
    pub fn validate_packet(packet: &BitchatPacket) -> Result<()> {
        // Check version
        if packet.version != PROTOCOL_VERSION {
            return Err(anyhow!("Invalid protocol version: {}", packet.version));
        }

        // Check TTL
        if packet.ttl == 0 || packet.ttl > MAX_TTL {
            return Err(anyhow!("Invalid TTL: {}", packet.ttl));
        }

        // Check flags consistency
        if packet.has_recipient() && packet.recipient_id.is_none() {
            return Err(anyhow!("HAS_RECIPIENT flag set but no recipient provided"));
        }

        if packet.has_signature() && packet.signature.is_none() {
            return Err(anyhow!("HAS_SIGNATURE flag set but no signature provided"));
        }

        // Check sender ID is not all zeros
        if !peer_utils::is_valid_peer_id(&packet.sender_id) {
            return Err(anyhow!("Invalid sender peer ID"));
        }

        Ok(())
    }

    /// Get packet size without encoding
    pub fn calculate_packet_size(packet: &BitchatPacket) -> usize {
        packet.serialized_size()
    }
}