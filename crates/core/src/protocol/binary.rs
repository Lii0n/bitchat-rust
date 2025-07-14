//! Binary Protocol Manager - handles encoding/decoding of packets
//! Compatible with BitChat iOS/Android implementation

use super::packet::{BitchatPacket, MessageType, flags, PEER_ID_SIZE, SIGNATURE_SIZE, PROTOCOL_VERSION, MAX_TTL};
use crate::protocol::peer_utils;
use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, BytesMut};
use tracing::{debug, warn};
use lz4;

// FIXED: Header size is 13 bytes, not 15
const HEADER_SIZE: usize = 13;

/// Compression utilities for message optimization
pub struct CompressionUtil;

impl CompressionUtil {
    /// Check if data should be compressed (>100 bytes)
    pub fn should_compress(data: &[u8]) -> bool {
        data.len() > 100
    }
    
    /// Compress data using LZ4
    pub fn compress(data: &[u8]) -> Option<Vec<u8>> {
        match lz4::block::compress(data, None, true) {
            Ok(compressed) => {
                // Only use compression if it actually saves space
                if compressed.len() < data.len() {
                    Some(compressed)
                } else {
                    None
                }
            },
            Err(e) => {
                tracing::warn!("LZ4 compression failed: {}", e);
                None
            }
        }
    }
    
    /// Decompress LZ4 data
    pub fn decompress(compressed: &[u8], original_size: usize) -> Option<Vec<u8>> {
        match lz4::block::decompress(compressed, Some(original_size as i32)) {
            Ok(decompressed) => {
                if decompressed.len() == original_size {
                    Some(decompressed)
                } else {
                    tracing::warn!(
                        "LZ4 decompression size mismatch: expected {}, got {}", 
                        original_size, 
                        decompressed.len()
                    );
                    None
                }
            },
            Err(e) => {
                tracing::warn!("LZ4 decompression failed: {}", e);
                None
            }
        }
    }
}

/// Binary Protocol Manager - handles encoding/decoding
pub struct BinaryProtocolManager;

impl BinaryProtocolManager {
    /// Encode a packet to binary format (EXACT same as mobile)
    pub fn encode(packet: &BitchatPacket) -> Result<Vec<u8>> {
        // Try compression first
        let mut payload = packet.payload.clone();
        let mut original_payload_size: Option<u16> = None;
        let mut is_compressed = false;
        
        if CompressionUtil::should_compress(&payload) {
            if let Some(compressed_payload) = CompressionUtil::compress(&payload) {
                // Only use compression if it actually reduces size
                if compressed_payload.len() < payload.len() {
                    original_payload_size = Some(payload.len() as u16);
                    payload = compressed_payload;
                    is_compressed = true;
                }
            }
        }
        
        // Calculate total size
        let payload_data_size = payload.len() + if is_compressed { 2 } else { 0 }; // +2 for original size
        let recipient_size = if packet.recipient_id.is_some() { PEER_ID_SIZE } else { 0 };
        let signature_size = if packet.signature.is_some() { SIGNATURE_SIZE } else { 0 };
        let total_size = HEADER_SIZE + PEER_ID_SIZE + recipient_size + payload_data_size + signature_size;
        
        let mut buffer = BytesMut::with_capacity(total_size);

        // Header (13 bytes: version(1) + type(1) + ttl(1) + timestamp(8) + flags(1) + payload_len(2))
        buffer.put_u8(packet.version);
        buffer.put_u8(packet.message_type as u8);
        buffer.put_u8(packet.ttl);
        buffer.put_u64(packet.timestamp); // Big-endian
        
        // Flags byte
        let mut flags_byte = packet.flags;
        if is_compressed {
            flags_byte |= flags::IS_COMPRESSED;
        }
        buffer.put_u8(flags_byte);
        
        // Payload length (includes original size if compressed)
        buffer.put_u16(payload_data_size as u16); // Big-endian

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

        // Payload with compression handling
        if is_compressed {
            if let Some(original_size) = original_payload_size {
                // Prepend original size (2 bytes, big-endian)
                buffer.put_u16(original_size);
            }
        }
        buffer.put_slice(&payload);

        // Optional signature (64 bytes)
        if packet.flags & flags::HAS_SIGNATURE != 0 {
            if let Some(ref signature) = packet.signature {
                if signature.len() != SIGNATURE_SIZE {
                    return Err(anyhow!("Invalid signature size: {} bytes", signature.len()));
                }
                buffer.put_slice(signature);
            } else {
                return Err(anyhow!("HAS_SIGNATURE flag set but no signature provided"));
            }
        }

        debug!(
            "Encoded packet: type={:?}, size={} bytes, TTL={}, compressed={}", 
            packet.message_type, 
            total_size, 
            packet.ttl,
            is_compressed
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
        let message_type = MessageType::try_from_u8(buffer.get_u8())?;
        let ttl = buffer.get_u8();
        let timestamp = buffer.get_u64(); // Big-endian
        let flags_byte = buffer.get_u8();
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
        let recipient_id = if flags_byte & flags::HAS_RECIPIENT != 0 {
            if buffer.remaining() < PEER_ID_SIZE {
                return Err(anyhow!("Not enough data for recipient ID"));
            }
            let mut recipient = [0u8; 8];
            buffer.copy_to_slice(&mut recipient);
            Some(recipient)
        } else {
            None
        };

        // Parse payload with compression handling
        if buffer.remaining() < payload_length {
            return Err(anyhow!("Not enough data for payload"));
        }
        
        let mut payload_data = buffer[..payload_length].to_vec();
        buffer.advance(payload_length);
        
        // Handle decompression if needed
        let payload = if flags_byte & flags::IS_COMPRESSED != 0 {
            if payload_data.len() < 2 {
                return Err(anyhow!("Compressed payload too short for size header"));
            }
            
            // Extract original size (first 2 bytes)
            let original_size = u16::from_be_bytes([payload_data[0], payload_data[1]]) as usize;
            let compressed_data = &payload_data[2..];
            
            match CompressionUtil::decompress(compressed_data, original_size) {
                Some(decompressed) => {
                    if decompressed.len() != original_size {
                        warn!("Decompressed size mismatch: expected {}, got {}", 
                              original_size, decompressed.len());
                    }
                    decompressed
                },
                None => {
                    warn!("Failed to decompress payload, using as-is");
                    payload_data[2..].to_vec() // Skip size header, use raw data
                }
            }
        } else {
            payload_data
        };

        // Parse optional signature (64 bytes)
        let signature = if flags_byte & flags::HAS_SIGNATURE != 0 {
            if buffer.remaining() < SIGNATURE_SIZE {
                return Err(anyhow!("Not enough data for signature"));
            }
            let mut sig = vec![0u8; SIGNATURE_SIZE];
            buffer.copy_to_slice(&mut sig);
            Some(sig)
        } else {
            None
        };

        // Remove compression flag from stored flags (it's a transport flag)
        let stored_flags = flags_byte & !flags::IS_COMPRESSED;

        Ok(BitchatPacket {
            version,
            message_type,
            ttl,
            timestamp,
            flags: stored_flags,
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

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encode_decode_roundtrip() {
        let packet = BitchatPacket::new_broadcast(
            MessageType::Message,
            [1, 2, 3, 4, 5, 6, 7, 8],
            b"Hello, world!".to_vec(),
        );
        
        let encoded = BinaryProtocolManager::encode(&packet).unwrap();
        let decoded = BinaryProtocolManager::decode(&encoded).unwrap();
        
        assert_eq!(packet.version, decoded.version);
        assert_eq!(packet.message_type, decoded.message_type);
        assert_eq!(packet.sender_id, decoded.sender_id);
        assert_eq!(packet.payload, decoded.payload);
    }
    
    #[test]
    fn test_header_size() {
        let packet = BitchatPacket::new_broadcast(
            MessageType::Announce,
            [0; 8],
            vec![],
        );
        
        let encoded = BinaryProtocolManager::encode(&packet).unwrap();
        // Header (13) + Sender ID (8) + Empty payload (0) = 21 bytes minimum
        assert!(encoded.len() >= 21);
    }
}