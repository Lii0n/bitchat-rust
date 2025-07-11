//! Binary Protocol Manager - handles encoding/decoding of packets

use super::packet::{BitchatPacket, MessageType, flags, HEADER_SIZE, PEER_ID_SIZE, SIGNATURE_SIZE, PROTOCOL_VERSION, MAX_TTL};
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

        // Header (13 bytes)
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
            if let Some(signature) = packet.signature {
                buffer.put_slice(&signature);
            } else {
                return Err(anyhow!("HAS_SIGNATURE flag set but no signature provided"));
            }
        }

        debug!(
            "Encoded packet: type={}, size={} bytes, TTL={}", 
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

        // Parse header (13 bytes)
        let version = buffer.get_u8();
        let message_type = MessageType::try_from(buffer.get_u8())?;
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
            let mut recipient_id = [0u8; 8];
            buffer.copy_to_slice(&mut recipient_id);
            Some(recipient_id)
        } else {
            None
        };

        // Parse payload
        if buffer.remaining() < payload_length {
            return Err(anyhow!(
                "Not enough data for payload: expected {}, got {}",
                payload_length,
                buffer.remaining()
            ));
        }
        let payload = buffer[..payload_length].to_vec();
        buffer.advance(payload_length);

        // Parse optional signature (64 bytes)
        let signature = if flags & flags::HAS_SIGNATURE != 0 {
            if buffer.remaining() < SIGNATURE_SIZE {
                return Err(anyhow!("Not enough data for signature"));
            }
            let mut signature = [0u8; 64];
            buffer.copy_to_slice(&mut signature);
            Some(signature)
        } else {
            None
        };

        let packet = BitchatPacket {
            version,
            message_type,
            ttl,
            timestamp,
            flags,
            sender_id,
            recipient_id,
            payload,
            signature,
        };

        debug!(
            "Decoded packet: type={}, size={} bytes, TTL={}, sender={}", 
            packet.message_type, 
            data.len(), 
            packet.ttl,
            super::packet::peer_utils::short_peer_id(&packet.sender_id)
        );

        Ok(packet)
    }

    /// Create an ANNOUNCE packet (used for peer discovery)
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

    /// Create a MESSAGE packet (chat message)
    pub fn create_message_packet(
        sender_id: [u8; 8],
        recipient_id: Option<[u8; 8]>,
        content: &str,
    ) -> Result<BitchatPacket> {
        let payload = content.as_bytes().to_vec();
        
        match recipient_id {
            Some(recipient) => Ok(BitchatPacket::new_direct(
                MessageType::Message,
                sender_id,
                recipient,
                payload,
            )),
            None => Ok(BitchatPacket::new_broadcast(
                MessageType::Message,
                sender_id,
                payload,
            )),
        }
    }

    /// Create a LEAVE packet (peer leaving)
    pub fn create_leave_packet(sender_id: [u8; 8]) -> Result<BitchatPacket> {
        Ok(BitchatPacket::new_broadcast(
            MessageType::Leave,
            sender_id,
            Vec::new(),
        ))
    }

    /// Create a KEY_EXCHANGE packet (for encryption setup)
    pub fn create_key_exchange_packet(
        sender_id: [u8; 8],
        recipient_id: [u8; 8],
        public_key: &[u8],
    ) -> Result<BitchatPacket> {
        Ok(BitchatPacket::new_direct(
            MessageType::KeyExchange,
            sender_id,
            recipient_id,
            public_key.to_vec(),
        ))
    }

    /// Validate packet integrity
    pub fn validate_packet(packet: &BitchatPacket) -> Result<()> {
        // Check version
        if packet.version != PROTOCOL_VERSION {
            return Err(anyhow!("Invalid protocol version: {}", packet.version));
        }

        // Check TTL
        if packet.ttl > MAX_TTL {
            return Err(anyhow!("Invalid TTL: {}", packet.ttl));
        }

        // Check flags consistency
        if packet.flags & flags::HAS_RECIPIENT != 0 && packet.recipient_id.is_none() {
            return Err(anyhow!("HAS_RECIPIENT flag set but no recipient_id"));
        }

        if packet.flags & flags::HAS_SIGNATURE != 0 && packet.signature.is_none() {
            return Err(anyhow!("HAS_SIGNATURE flag set but no signature"));
        }

        // Check payload size (reasonable limits)
        if packet.payload.len() > 65535 {
            return Err(anyhow!("Payload too large: {} bytes", packet.payload.len()));
        }

        // Check timestamp (not too far in the future)
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        
        if packet.timestamp > now + 300000 { // 5 minutes in the future
            warn!("Packet timestamp is too far in the future: {}", packet.timestamp);
        }

        Ok(())
    }

    /// Get packet summary for logging
    pub fn packet_summary(packet: &BitchatPacket) -> String {
        let sender = super::packet::peer_utils::short_peer_id(&packet.sender_id);
        let recipient = packet.recipient_id
            .map(|r| super::packet::peer_utils::short_peer_id(&r))
            .unwrap_or_else(|| "BROADCAST".to_string());
        
        format!(
            "{}({} -> {}, TTL:{}, {}b)", 
            packet.message_type,
            sender,
            recipient,
            packet.ttl,
            packet.payload.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::packet::peer_utils;

    #[test]
    fn test_packet_encode_decode_roundtrip() {
        let sender_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let payload = b"Hello, BitChat!".to_vec();
        
        let original = BitchatPacket::new(
            MessageType::Message,
            sender_id,
            payload,
        );

        let encoded = BinaryProtocolManager::encode(&original).unwrap();
        let decoded = BinaryProtocolManager::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
    }

    #[test]
    fn test_packet_with_recipient() {
        let sender_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let recipient_id = [8, 7, 6, 5, 4, 3, 2, 1];
        let payload = b"Direct message".to_vec();
        
        let original = BitchatPacket::new_direct(
            MessageType::Message,
            sender_id,
            recipient_id,
            payload,
        );

        let encoded = BinaryProtocolManager::encode(&original).unwrap();
        let decoded = BinaryProtocolManager::decode(&encoded).unwrap();

        assert_eq!(original, decoded);
        assert_eq!(decoded.recipient_id, Some(recipient_id));
    }

    #[test]
    fn test_announce_packet() {
        let sender_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let nickname = "TestUser";
        
        let packet = BinaryProtocolManager::create_announce_packet(
            sender_id,
            nickname,
        ).unwrap();

        assert_eq!(packet.message_type, MessageType::Announce);
        assert_eq!(packet.payload, nickname.as_bytes());
        assert!(packet.is_broadcast());
    }

    #[test]
    fn test_packet_validation() {
        let sender_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let payload = b"Test".to_vec();
        
        let packet = BitchatPacket::new(
            MessageType::Message,
            sender_id,
            payload,
        );

        assert!(BinaryProtocolManager::validate_packet(&packet).is_ok());
    }

    #[test]
    fn test_peer_id_utils() {
        let peer_id = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let hex_string = peer_utils::peer_id_to_string(&peer_id);
        assert_eq!(hex_string, "0123456789ABCDEF");
        
        let parsed = peer_utils::string_to_peer_id(&hex_string).unwrap();
        assert_eq!(parsed, peer_id);
        
        let short_id = peer_utils::short_peer_id(&peer_id);
        assert_eq!(short_id, "01234567");
    }
}
