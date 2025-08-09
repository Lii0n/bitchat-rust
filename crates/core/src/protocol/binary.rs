//! BitChat Binary Protocol - Consolidated Implementation
//! 
//! This module provides a streamlined, efficient implementation of the BitChat
//! binary protocol as specified in the whitepaper. All protocol-related
//! functionality is consolidated into this single module.
//! 
//! Features:
//! - Message deduplication via unique IDs
//! - Automatic fragmentation for large messages  
//! - End-to-end encryption (X25519 + AES-256-GCM)
//! - Channel encryption (Argon2id + AES-256-GCM)
//! - Digital signatures (Ed25519)
//! - LZ4 compression

use serde::{Deserialize, Serialize};
// Clean up warnings
use anyhow::{Result, anyhow};
use bytes::{Buf, BufMut, BytesMut};
use tracing::{debug, warn};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

// Import encryption types from the encryption module
use crate::encryption::{BitChatEncryption, BitChatIdentity, EncryptionStats};

// ============================================================================
// PROTOCOL CONSTANTS
// ============================================================================

pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 17;  // version(1) + type(1) + ttl(1) + timestamp(8) + flags(1) + payload_len(2) + msg_id(4)
pub const PEER_ID_SIZE: usize = 8;
pub const SIGNATURE_SIZE: usize = 64;
pub const MESSAGE_ID_SIZE: usize = 4;
pub const MAX_TTL: u8 = 7;
pub const MAX_PAYLOAD_SIZE: usize = 400; // Conservative BLE MTU for fragmentation
pub const FRAGMENT_SIZE: usize = 350; // Size per fragment (leaves room for headers)
pub const COMPRESSION_THRESHOLD: usize = 100; // Compress payloads > 100 bytes
pub const MAX_FRAGMENTS: u8 = 255; // Maximum fragments per message

// ============================================================================
// PROTOCOL FLAGS
// ============================================================================

pub mod flags {
    /// Packet has a recipient ID field (private message)
    pub const HAS_RECIPIENT: u8 = 0x01;
    /// Packet has a signature field for authentication
    pub const HAS_SIGNATURE: u8 = 0x02;
    /// Payload is compressed with LZ4
    pub const IS_COMPRESSED: u8 = 0x04;
    /// Message requires delivery confirmation
    pub const NEEDS_ACK: u8 = 0x08;
    /// This is a fragment of a larger message
    pub const IS_FRAGMENT: u8 = 0x10;
    /// Last fragment in a fragmented message
    pub const IS_LAST_FRAGMENT: u8 = 0x20;
}

// ============================================================================
// MESSAGE TYPES
// ============================================================================

/// All supported message types in the BitChat protocol
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum MessageType {
    // Core protocol messages
    Announce = 1,           // Peer presence announcement
    KeyExchange = 2,        // Cryptographic key exchange
    Leave = 3,              // Peer departure notification
    Message = 4,            // Text/data message
    DirectMessage = 17,     // Direct peer-to-peer message
    
    // Fragmentation support
    FragmentStart = 5,      // First fragment of large message
    FragmentContinue = 6,   // Middle fragment
    FragmentEnd = 7,        // Final fragment
    
    // Channel management
    ChannelAnnounce = 8,    // Channel discovery/advertisement
    ChannelJoin = 9,        // Join a channel
    ChannelLeave = 10,      // Leave a channel
    ChannelRetention = 11,  // Channel retention policy update
    
    // Delivery tracking
    DeliveryAck = 12,       // Message delivery acknowledgment
    DeliveryStatusRequest = 13, // Request delivery status
    ReadReceipt = 14,       // Message read confirmation
    
    // Network diagnostics
    Ping = 15,              // Connectivity test request
    Pong = 16,              // Connectivity test response
}

impl MessageType {
    pub fn try_from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(MessageType::Announce),
            2 => Ok(MessageType::KeyExchange),
            3 => Ok(MessageType::Leave),
            4 => Ok(MessageType::Message),
            5 => Ok(MessageType::FragmentStart),
            6 => Ok(MessageType::FragmentContinue),
            7 => Ok(MessageType::FragmentEnd),
            8 => Ok(MessageType::ChannelAnnounce),
            9 => Ok(MessageType::ChannelJoin),
            10 => Ok(MessageType::ChannelLeave),
            11 => Ok(MessageType::ChannelRetention),
            12 => Ok(MessageType::DeliveryAck),
            13 => Ok(MessageType::DeliveryStatusRequest),
            14 => Ok(MessageType::ReadReceipt),
            15 => Ok(MessageType::Ping),
            16 => Ok(MessageType::Pong),
            17 => Ok(MessageType::DirectMessage),
            _ => Err(anyhow!("Invalid message type: {}", value)),
        }
    }
}

// ============================================================================
// PACKET STRUCTURE
// ============================================================================

/// Main packet structure for BitChat protocol
/// 
/// Binary format:
/// - Header (17 bytes): version + type + ttl + timestamp + flags + payload_len + message_id
/// - Sender ID (8 bytes): Unique peer identifier
/// - Recipient ID (8 bytes, optional): Target peer for private messages
/// - Fragment Info (2 bytes, optional): fragment_index(1) + total_fragments(1)
/// - Payload (variable): Message content (optionally compressed)
/// - Signature (64 bytes, optional): Ed25519 signature for authentication
#[derive(Debug, Clone)]
pub struct BitchatPacket {
    pub version: u8,
    pub message_type: MessageType,
    pub ttl: u8,
    pub timestamp: u64,
    pub flags: u8,
    pub message_id: u32,  // Unique message identifier for deduplication
    pub sender_id: [u8; 8],
    pub recipient_id: Option<[u8; 8]>,
    pub fragment_index: Option<u8>,      // Which fragment (0-based)
    pub total_fragments: Option<u8>,     // Total number of fragments
    pub payload: Vec<u8>,
    pub signature: Option<[u8; 64]>,
}

impl BitchatPacket {
    /// Create a new broadcast packet (public message)
    pub fn new_broadcast(message_type: MessageType, sender_id: [u8; 8], payload: Vec<u8>) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type,
            ttl: MAX_TTL,
            timestamp: current_timestamp(),
            flags: 0,
            message_id: generate_message_id(),
            sender_id,
            recipient_id: None,
            fragment_index: None,
            total_fragments: None,
            payload,
            signature: None,
        }
    }
    
    /// Create a new private packet (directed message)
    pub fn new_private(
        message_type: MessageType, 
        sender_id: [u8; 8], 
        recipient_id: [u8; 8], 
        payload: Vec<u8>
    ) -> Self {
        Self {
            version: PROTOCOL_VERSION,
            message_type,
            ttl: MAX_TTL,
            timestamp: current_timestamp(),
            flags: flags::HAS_RECIPIENT,
            message_id: generate_message_id(),
            sender_id,
            recipient_id: Some(recipient_id),
            fragment_index: None,
            total_fragments: None,
            payload,
            signature: None,
        }
    }
    
    /// Create a fragment packet
    pub fn new_fragment(
        message_type: MessageType,
        sender_id: [u8; 8],
        recipient_id: Option<[u8; 8]>,
        message_id: u32,
        fragment_index: u8,
        total_fragments: u8,
        payload: Vec<u8>
    ) -> Self {
        let mut flags = flags::IS_FRAGMENT;
        if recipient_id.is_some() {
            flags |= flags::HAS_RECIPIENT;
        }
        if fragment_index == total_fragments - 1 {
            flags |= flags::IS_LAST_FRAGMENT;
        }
        
        Self {
            version: PROTOCOL_VERSION,
            message_type,
            ttl: MAX_TTL,
            timestamp: current_timestamp(),
            flags,
            message_id,
            sender_id,
            recipient_id,
            fragment_index: Some(fragment_index),
            total_fragments: Some(total_fragments),
            payload,
            signature: None,
        }
    }
    
    /// Add signature to packet
    pub fn with_signature(mut self, signature: [u8; 64]) -> Self {
        self.signature = Some(signature);
        self.flags |= flags::HAS_SIGNATURE;
        self
    }
    
    /// Mark packet as requiring acknowledgment
    pub fn with_ack_required(mut self) -> Self {
        self.flags |= flags::NEEDS_ACK;
        self
    }
    
    /// Check if packet has recipient
    pub fn has_recipient(&self) -> bool {
        self.flags & flags::HAS_RECIPIENT != 0
    }
    
    /// Check if packet has signature
    pub fn has_signature(&self) -> bool {
        self.flags & flags::HAS_SIGNATURE != 0
    }
    
    /// Check if packet is compressed
    pub fn is_compressed(&self) -> bool {
        self.flags & flags::IS_COMPRESSED != 0
    }
    
    /// Check if packet needs acknowledgment
    pub fn needs_ack(&self) -> bool {
        self.flags & flags::NEEDS_ACK != 0
    }
    
    /// Check if packet is a fragment
    pub fn is_fragment(&self) -> bool {
        self.flags & flags::IS_FRAGMENT != 0
    }
    
    /// Check if this is the last fragment
    pub fn is_last_fragment(&self) -> bool {
        self.flags & flags::IS_LAST_FRAGMENT != 0
    }
    
    /// Get fragment info
    pub fn fragment_info(&self) -> Option<(u8, u8)> {
        if self.is_fragment() {
            Some((self.fragment_index?, self.total_fragments?))
        } else {
            None
        }
    }
    
    /// Get unique message identifier for deduplication
    pub fn message_id(&self) -> u32 {
        self.message_id
    }
    
    /// Decrement TTL for message forwarding
    pub fn decrement_ttl(&mut self) -> bool {
        if self.ttl > 0 {
            self.ttl -= 1;
            true
        } else {
            false
        }
    }
    
    /// Calculate serialized size
    pub fn serialized_size(&self) -> usize {
        let mut size = HEADER_SIZE + PEER_ID_SIZE; // Basic header + sender ID
        
        if self.has_recipient() {
            size += PEER_ID_SIZE;
        }
        
        if self.is_fragment() {
            size += 2; // fragment_index + total_fragments
        }
        
        size += self.payload.len();
        
        if self.has_signature() {
            size += SIGNATURE_SIZE;
        }
        
        size
    }
    
    /// Validate packet structure
    pub fn validate(&self) -> Result<()> {
        if self.version != PROTOCOL_VERSION {
            return Err(anyhow!("Invalid protocol version: {}", self.version));
        }
        
        if self.ttl > MAX_TTL {
            return Err(anyhow!("Invalid TTL: {}", self.ttl));
        }
        
        if self.has_recipient() && self.recipient_id.is_none() {
            return Err(anyhow!("HAS_RECIPIENT flag set but no recipient provided"));
        }
        
        if self.has_signature() && self.signature.is_none() {
            return Err(anyhow!("HAS_SIGNATURE flag set but no signature provided"));
        }
        
        if self.payload.len() > MAX_PAYLOAD_SIZE && !self.is_fragment() {
            return Err(anyhow!("Payload too large for single packet: {} bytes (use fragmentation)", self.payload.len()));
        }
        
        if self.is_fragment() {
            if self.fragment_index.is_none() || self.total_fragments.is_none() {
                return Err(anyhow!("Fragment packet missing fragment info"));
            }
            
            let (frag_idx, total_frags) = (self.fragment_index.unwrap(), self.total_fragments.unwrap());
            if frag_idx >= total_frags {
                return Err(anyhow!("Invalid fragment index: {} >= {}", frag_idx, total_frags));
            }
        }
        
        Ok(())
    }
}

// ============================================================================
// COMPRESSION UTILITIES
// ============================================================================

pub struct CompressionUtil;

impl CompressionUtil {
    /// Check if payload should be compressed
    pub fn should_compress(data: &[u8]) -> bool {
        data.len() > COMPRESSION_THRESHOLD
    }
    
    /// Compress data using LZ4
    pub fn compress(data: &[u8]) -> Option<Vec<u8>> {
        // Use the lz4 crate
        match lz4::block::compress(data, None, true) {
            Ok(compressed) if compressed.len() < data.len() => Some(compressed),
            _ => None,
        }
    }
    
    /// Decompress LZ4 data
    pub fn decompress(compressed: &[u8], original_size: usize) -> Option<Vec<u8>> {
        match lz4::block::decompress(compressed, Some(original_size as i32)) {
            Ok(decompressed) if decompressed.len() == original_size => Some(decompressed),
            _ => None,
        }
    }
}

// ============================================================================
// MESSAGE FRAGMENTATION & DEDUPLICATION
// ============================================================================

/// Manages message fragmentation and reassembly
pub struct FragmentationManager {
    pending_fragments: HashMap<u32, FragmentAssembly>,
    pub seen_messages: HashSet<u32>,
    cleanup_interval: Duration,
    last_cleanup: Instant,
}

#[derive(Debug)]
pub struct FragmentAssembly {
    sender_id: [u8; 8],
    recipient_id: Option<[u8; 8]>,
    message_type: MessageType,
    total_fragments: u8,
    received_fragments: HashMap<u8, Vec<u8>>,
    timestamp: Instant,
}

impl FragmentationManager {
    /// Create a new fragmentation manager
    pub fn new() -> Self {
        Self {
            pending_fragments: HashMap::new(),
            seen_messages: HashSet::new(),
            cleanup_interval: Duration::from_secs(300), // 5 minutes
            last_cleanup: Instant::now(),
        }
    }
    
    /// Fragment a large message into multiple packets
    pub fn fragment_message(
        message_type: MessageType,
        sender_id: [u8; 8],
        recipient_id: Option<[u8; 8]>,
        payload: Vec<u8>
    ) -> Result<Vec<BitchatPacket>> {
        if payload.len() <= MAX_PAYLOAD_SIZE {
            // No fragmentation needed
            let packet = match recipient_id {
                Some(recipient) => BitchatPacket::new_private(message_type, sender_id, recipient, payload),
                None => BitchatPacket::new_broadcast(message_type, sender_id, payload),
            };
            return Ok(vec![packet]);
        }
        
        let message_id = generate_message_id();
        let total_fragments = ((payload.len() + FRAGMENT_SIZE - 1) / FRAGMENT_SIZE) as u8;
        
        if total_fragments > MAX_FRAGMENTS {
            return Err(anyhow!("Message too large: {} fragments required (max {})", total_fragments, MAX_FRAGMENTS));
        }
        
        let mut fragments = Vec::new();
        
        for (i, chunk) in payload.chunks(FRAGMENT_SIZE).enumerate() {
            let fragment = BitchatPacket::new_fragment(
                message_type,
                sender_id,
                recipient_id,
                message_id,
                i as u8,
                total_fragments,
                chunk.to_vec(),
            );
            fragments.push(fragment);
        }
        
        debug!("Fragmented message {} into {} packets", message_id, total_fragments);
        Ok(fragments)
    }
    
    /// Process an incoming packet and check for deduplication/reassembly
    pub fn process_packet(&mut self, packet: BitchatPacket) -> Result<Option<BitchatPacket>> {
        // Check for message deduplication
        if self.is_duplicate(&packet) {
            debug!("Dropping duplicate message ID: {}", packet.message_id);
            return Ok(None);
        }
        
        // Mark message as seen
        self.mark_as_seen(packet.message_id);
        
        // Handle fragments
        if packet.is_fragment() {
            self.handle_fragment(packet)
        } else {
            Ok(Some(packet))
        }
    }
    
    /// Handle a fragment packet
    fn handle_fragment(&mut self, packet: BitchatPacket) -> Result<Option<BitchatPacket>> {
        let message_id = packet.message_id;
        let (fragment_index, total_fragments) = packet.fragment_info()
            .ok_or_else(|| anyhow!("Fragment packet missing fragment info"))?;
        
        // Get or create fragment assembly
        let assembly = self.pending_fragments.entry(message_id).or_insert_with(|| {
            FragmentAssembly {
                sender_id: packet.sender_id,
                recipient_id: packet.recipient_id,
                message_type: packet.message_type,
                total_fragments,
                received_fragments: HashMap::new(),
                timestamp: Instant::now(),
            }
        });
        
        // Validate fragment consistency
        if assembly.sender_id != packet.sender_id {
            return Err(anyhow!("Fragment sender mismatch"));
        }
        if assembly.total_fragments != total_fragments {
            return Err(anyhow!("Fragment count mismatch"));
        }
        
        // Store fragment
        assembly.received_fragments.insert(fragment_index, packet.payload);
        
        debug!("Received fragment {}/{} for message {}", 
               fragment_index + 1, total_fragments, message_id);
        
        // Check if all fragments received
        if assembly.received_fragments.len() == total_fragments as usize {
            let complete_packet = self.reassemble_message(message_id)?;
            debug!("Reassembled complete message {}", message_id);
            Ok(Some(complete_packet))
        } else {
            Ok(None) // Still waiting for more fragments
        }
    }
    
    /// Reassemble a complete message from fragments
    fn reassemble_message(&mut self, message_id: u32) -> Result<BitchatPacket> {
        let assembly = self.pending_fragments.remove(&message_id)
            .ok_or_else(|| anyhow!("Fragment assembly not found"))?;
        
        // Reassemble payload in correct order
        let mut complete_payload = Vec::new();
        for i in 0..assembly.total_fragments {
            let fragment_data = assembly.received_fragments.get(&i)
                .ok_or_else(|| anyhow!("Missing fragment {}", i))?;
            complete_payload.extend_from_slice(fragment_data);
        }
        
        // Create reassembled packet
        let packet = match assembly.recipient_id {
            Some(recipient) => BitchatPacket::new_private(
                assembly.message_type, 
                assembly.sender_id, 
                recipient, 
                complete_payload
            ),
            None => BitchatPacket::new_broadcast(
                assembly.message_type, 
                assembly.sender_id, 
                complete_payload
            ),
        };
        
        Ok(packet)
    }
    
    /// Check if message has been seen before (deduplication)
    pub fn is_duplicate(&self, packet: &BitchatPacket) -> bool {
        self.seen_messages.contains(&packet.message_id)
    }
    
    /// Mark message as seen
    fn mark_as_seen(&mut self, message_id: u32) {
        self.seen_messages.insert(message_id);
    }
    
    /// Clean up old fragments and seen messages
    pub fn cleanup(&mut self) {
        let now = Instant::now();
        
        if now.duration_since(self.last_cleanup) < self.cleanup_interval {
            return;
        }
        
        let timeout = Duration::from_secs(600); // 10 minutes
        
        // Remove old fragment assemblies
        self.pending_fragments.retain(|_, assembly| {
            now.duration_since(assembly.timestamp) < timeout
        });
        
        // Clear seen messages (keep recent ones)
        if self.seen_messages.len() > 10000 {
            self.seen_messages.clear();
            debug!("Cleared message deduplication cache");
        }
        
        self.last_cleanup = now;
    }
    
    /// Get statistics
    pub fn stats(&self) -> FragmentationStats {
        FragmentationStats {
            pending_assemblies: self.pending_fragments.len(),
            seen_messages: self.seen_messages.len(),
        }
    }
}

#[derive(Debug)]
pub struct FragmentationStats {
    pub pending_assemblies: usize,
    pub seen_messages: usize,
}

// ============================================================================
// BINARY PROTOCOL MANAGER
// ============================================================================

/// Handles encoding and decoding of BitChat packets with automatic fragmentation and encryption
pub struct BinaryProtocol {
    fragmentation_manager: FragmentationManager,
    encryption: BitChatEncryption,
}

impl BinaryProtocol {
    /// Create a new protocol manager
    pub fn new() -> Self {
        Self {
            fragmentation_manager: FragmentationManager::new(),
            encryption: BitChatEncryption::new(),
        }
    }
    
    /// Create protocol manager with existing identity
    pub fn with_identity(identity: BitChatIdentity) -> Self {
        Self {
            fragmentation_manager: FragmentationManager::new(),
            encryption: BitChatEncryption::with_identity(identity),
        }
    }
    
    /// Get our public key for announcements
    pub fn our_public_key(&self) -> [u8; 32] {
        self.encryption.our_public_key().to_bytes()
    }
    
    /// Get our signing public key
    pub fn our_signing_key(&self) -> [u8; 32] {
        self.encryption.our_signing_key().to_bytes()
    }
    
    /// Get our fingerprint
    pub fn our_fingerprint(&self) -> [u8; 32] {
        self.encryption.our_fingerprint()
    }
    
    /// Initiate key exchange with a peer
    pub fn initiate_key_exchange(&mut self, peer_id: &str) -> Result<Vec<Vec<u8>>> {
        let key_exchange_data = self.encryption.initiate_key_exchange(peer_id)?;
        
        // Create and fragment key exchange packet
        let sender_id = peer_id_to_bytes(peer_id);
        let recipient_id = peer_id_to_bytes(peer_id); // We know the target
        
        self.encode_message(
            MessageType::KeyExchange,
            sender_id,
            Some(recipient_id),
            key_exchange_data,
        )
    }
    
    /// Handle incoming key exchange packet
    pub fn handle_key_exchange(&mut self, peer_id: &str, packet: &BitchatPacket) -> Result<Option<Vec<Vec<u8>>>> {
        let response_data = self.encryption.handle_key_exchange(peer_id, &packet.payload)?;
        
        if let Some(response) = response_data {
            let sender_id = self.our_peer_id_bytes();
            let recipient_id = peer_id_to_bytes(peer_id);
            
            let packets = self.encode_message(
                MessageType::KeyExchange,
                sender_id,
                Some(recipient_id),
                response,
            )?;
            Ok(Some(packets))
        } else {
            Ok(None)
        }
    }
    
    /// Join a password-protected channel
    pub fn join_channel(&mut self, channel_name: &str, password: Option<&str>) -> Result<()> {
        if let Some(pwd) = password {
            self.encryption.join_channel(channel_name, pwd)?;
        }
        Ok(())
    }
    
    /// Leave a channel
    pub fn leave_channel(&mut self, channel_name: &str) {
        self.encryption.leave_channel(channel_name);
    }
    
    /// Encode message with automatic fragmentation if needed
    pub fn encode_message(
        &self,
        message_type: MessageType,
        sender_id: [u8; 8],
        recipient_id: Option<[u8; 8]>,
        payload: Vec<u8>
    ) -> Result<Vec<Vec<u8>>> {
        // Fragment the message if needed
        let packets = FragmentationManager::fragment_message(
            message_type, sender_id, recipient_id, payload
        )?;
        
        // Encode each packet
        let mut encoded_packets = Vec::new();
        for packet in packets {
            let encoded = Self::encode(&packet)?;
            encoded_packets.push(encoded);
        }
        
        Ok(encoded_packets)
    }
    
    /// Process incoming packet data with deduplication, reassembly, and decryption
    pub fn process_incoming(&mut self, data: &[u8]) -> Result<Option<ProcessedMessage>> {
        // Decode the packet
        let packet = Self::decode(data)?;
        
        // Process through fragmentation manager for deduplication/reassembly
        let complete_packet = match self.fragmentation_manager.process_packet(packet)? {
            Some(packet) => packet,
            None => return Ok(None), // Fragment or duplicate
        };
        
        // Decrypt if needed
        let decrypted_payload = self.decrypt_packet_payload(&complete_packet)?;
        
        // Periodic cleanup
        self.fragmentation_manager.cleanup();
        self.encryption.cleanup();
        
        Ok(Some(ProcessedMessage {
            packet: complete_packet,
            decrypted_payload,
        }))
    }
    
    /// Decrypt packet payload based on message type
    fn decrypt_packet_payload(&mut self, packet: &BitchatPacket) -> Result<Vec<u8>> {
        match packet.message_type {
            MessageType::Message if packet.recipient_id.is_some() => {
                // Private message - decrypt
                let sender_peer_id = bytes_to_peer_id(&packet.sender_id);
                match self.encryption.decrypt_private_message(&sender_peer_id, &packet.payload) {
                    Ok(decrypted) => Ok(decrypted),
                    Err(_) => {
                        // Decryption failed, might be unencrypted or we don't have session
                        debug!("Failed to decrypt private message from {}", sender_peer_id);
                        Ok(packet.payload.clone())
                    }
                }
            },
            MessageType::DirectMessage => {
                // Direct message - decrypt if encrypted
                let sender_peer_id = bytes_to_peer_id(&packet.sender_id);
                match self.encryption.decrypt_private_message(&sender_peer_id, &packet.payload) {
                    Ok(decrypted) => Ok(decrypted),
                    Err(_) => {
                        // Decryption failed, might be unencrypted or we don't have session
                        debug!("Failed to decrypt direct message from {}, using plaintext", sender_peer_id);
                        Ok(packet.payload.clone())
                    }
                }
            },
            MessageType::ChannelAnnounce | MessageType::ChannelJoin | MessageType::ChannelLeave => {
                // Try to decrypt as channel message
                if let Ok(potential_channel) = String::from_utf8(packet.payload.clone()) {
                    if let Some(channel_name) = potential_channel.split('|').next() {
                        match self.encryption.decrypt_channel_message(channel_name, &packet.payload) {
                            Ok(decrypted) => Ok(decrypted),
                            Err(_) => Ok(packet.payload.clone()), // Not encrypted or no key
                        }
                    } else {
                        Ok(packet.payload.clone())
                    }
                } else {
                    Ok(packet.payload.clone())
                }
            },
            _ => Ok(packet.payload.clone()), // No decryption needed
        }
    }
    
    /// Get our peer ID as bytes
    fn our_peer_id_bytes(&self) -> [u8; 8] {
        // Use first 8 bytes of our fingerprint as peer ID
        let fingerprint = self.encryption.our_fingerprint();
        let mut peer_id = [0u8; 8];
        peer_id.copy_from_slice(&fingerprint[..8]);
        peer_id
    }
    
    /// Check if a message ID has been seen before
    pub fn is_duplicate_message(&self, message_id: u32) -> bool {
        self.fragmentation_manager.seen_messages.contains(&message_id)
    }
    
    /// Get fragmentation statistics
    pub fn get_stats(&self) -> ProtocolStats {
        let frag_stats = self.fragmentation_manager.stats();
        let enc_stats = self.encryption.get_stats();
        
        ProtocolStats {
            fragmentation: frag_stats,
            encryption: enc_stats,
        }
    }
    
    /// Encode packet to binary format
    pub fn encode(packet: &BitchatPacket) -> Result<Vec<u8>> {
        packet.validate()?;
        
        // Try compression first
        let (payload, is_compressed, original_size) = Self::handle_compression(&packet.payload);
        
        // Calculate sizes
        let payload_size = payload.len() + if is_compressed { 2 } else { 0 }; // +2 for original size
        let recipient_size = if packet.has_recipient() { PEER_ID_SIZE } else { 0 };
        let fragment_size = if packet.is_fragment() { 2 } else { 0 }; // fragment_index + total_fragments
        let signature_size = if packet.has_signature() { SIGNATURE_SIZE } else { 0 };
        let total_size = HEADER_SIZE + PEER_ID_SIZE + recipient_size + fragment_size + payload_size + signature_size;
        
        let mut buffer = BytesMut::with_capacity(total_size);
        
        // Encode header (17 bytes)
        buffer.put_u8(packet.version);
        buffer.put_u8(packet.message_type as u8);
        buffer.put_u8(packet.ttl);
        buffer.put_u64(packet.timestamp);
        
        // Encode flags with compression bit
        let mut flags = packet.flags;
        if is_compressed {
            flags |= flags::IS_COMPRESSED;
        }
        buffer.put_u8(flags);
        buffer.put_u16(payload_size as u16);
        buffer.put_u32(packet.message_id);  // Message ID for deduplication
        
        // Encode sender ID
        buffer.put_slice(&packet.sender_id);
        
        // Encode optional recipient ID
        if let Some(recipient_id) = packet.recipient_id {
            buffer.put_slice(&recipient_id);
        }
        
        // Encode optional fragment info
        if packet.is_fragment() {
            buffer.put_u8(packet.fragment_index.unwrap());
            buffer.put_u8(packet.total_fragments.unwrap());
        }
        
        // Encode payload with compression handling
        if is_compressed {
            buffer.put_u16(original_size as u16); // Original size header
        }
        buffer.put_slice(&payload);
        
        // Encode optional signature
        if let Some(signature) = packet.signature {
            buffer.put_slice(&signature);
        }
        
        debug!(
            "Encoded packet: type={:?}, size={} bytes, TTL={}, compressed={}", 
            packet.message_type, total_size, packet.ttl, is_compressed
        );
        
        Ok(buffer.to_vec())
    }
    
    /// Decode binary data to packet
    pub fn decode(data: &[u8]) -> Result<BitchatPacket> {
        if data.len() < HEADER_SIZE + PEER_ID_SIZE {
            return Err(anyhow!("Packet too short: {} bytes", data.len()));
        }
        
        let mut cursor = std::io::Cursor::new(data);
        
        // Decode header (17 bytes)
        let version = cursor.get_u8();
        let message_type = MessageType::try_from_u8(cursor.get_u8())?;
        let ttl = cursor.get_u8();
        let timestamp = cursor.get_u64();
        let flags = cursor.get_u8();
        let payload_length = cursor.get_u16() as usize;
        let message_id = cursor.get_u32();  // Message ID for deduplication
        
        if version != PROTOCOL_VERSION {
            return Err(anyhow!("Unsupported protocol version: {}", version));
        }
        
        // Decode sender ID
        let mut sender_id = [0u8; 8];
        cursor.copy_to_slice(&mut sender_id);
        
        // Decode optional recipient ID
        let recipient_id = if flags & flags::HAS_RECIPIENT != 0 {
            let mut recipient = [0u8; 8];
            cursor.copy_to_slice(&mut recipient);
            Some(recipient)
        } else {
            None
        };
        
        // Decode optional fragment info
        let (fragment_index, total_fragments) = if flags & flags::IS_FRAGMENT != 0 {
            let frag_idx = cursor.get_u8();
            let total_frags = cursor.get_u8();
            (Some(frag_idx), Some(total_frags))
        } else {
            (None, None)
        };
        
        // Decode payload with compression handling
        if cursor.remaining() < payload_length {
            return Err(anyhow!("Not enough data for payload"));
        }
        
        let payload_data = &data[cursor.position() as usize..cursor.position() as usize + payload_length];
        cursor.advance(payload_length);
        
        let payload = if flags & flags::IS_COMPRESSED != 0 {
            Self::handle_decompression(payload_data)?
        } else {
            payload_data.to_vec()
        };
        
        // Decode optional signature
        let signature = if flags & flags::HAS_SIGNATURE != 0 {
            if cursor.remaining() < SIGNATURE_SIZE {
                return Err(anyhow!("Not enough data for signature"));
            }
            let mut sig = [0u8; 64];
            cursor.copy_to_slice(&mut sig);
            Some(sig)
        } else {
            None
        };
        
        // Remove transport flags from stored flags
        let stored_flags = flags & !(flags::IS_COMPRESSED);
        
        Ok(BitchatPacket {
            version,
            message_type,
            ttl,
            timestamp,
            flags: stored_flags,
            message_id,
            sender_id,
            recipient_id,
            fragment_index,
            total_fragments,
            payload,
            signature,
        })
    }
    
    /// Handle payload compression
    fn handle_compression(payload: &[u8]) -> (Vec<u8>, bool, usize) {
        if CompressionUtil::should_compress(payload) {
            if let Some(compressed) = CompressionUtil::compress(payload) {
                if compressed.len() < payload.len() {
                    return (compressed, true, payload.len());
                }
            }
        }
        (payload.to_vec(), false, 0)
    }
    
    /// Handle payload decompression
    fn handle_decompression(payload_data: &[u8]) -> Result<Vec<u8>> {
        if payload_data.len() < 2 {
            return Err(anyhow!("Compressed payload too short"));
        }
        
        let original_size = u16::from_be_bytes([payload_data[0], payload_data[1]]) as usize;
        let compressed_data = &payload_data[2..];
        
        match CompressionUtil::decompress(compressed_data, original_size) {
            Some(decompressed) => Ok(decompressed),
            None => {
                warn!("Decompression failed, using raw data");
                Ok(compressed_data.to_vec())
            }
        }
    }
}

/// Result of processing an incoming message
#[derive(Debug)]
pub struct ProcessedMessage {
    pub packet: BitchatPacket,
    pub decrypted_payload: Vec<u8>,
}

/// Combined protocol statistics  
#[derive(Debug)]
pub struct ProtocolStats {
    pub fragmentation: FragmentationStats,
    pub encryption: EncryptionStats,
}

// ============================================================================
// PACKET FACTORY METHODS
// ============================================================================

impl BinaryProtocol {
    /// Create an ANNOUNCE packet
    pub fn create_announce(sender_id: [u8; 8], nickname: &str) -> BitchatPacket {
        BitchatPacket::new_broadcast(
            MessageType::Announce,
            sender_id,
            nickname.as_bytes().to_vec(),
        )
    }
    
    /// Create a MESSAGE packet
    pub fn create_message(
        sender_id: [u8; 8], 
        recipient_id: Option<[u8; 8]>, 
        content: &str
    ) -> BitchatPacket {
        match recipient_id {
            Some(recipient) => BitchatPacket::new_private(
                MessageType::Message,
                sender_id,
                recipient,
                content.as_bytes().to_vec(),
            ),
            None => BitchatPacket::new_broadcast(
                MessageType::Message,
                sender_id,
                content.as_bytes().to_vec(),
            ),
        }
    }
    
    /// Create a KEY_EXCHANGE packet
    pub fn create_key_exchange(
        sender_id: [u8; 8], 
        recipient_id: [u8; 8], 
        key_data: &[u8]
    ) -> BitchatPacket {
        BitchatPacket::new_private(
            MessageType::KeyExchange,
            sender_id,
            recipient_id,
            key_data.to_vec(),
        )
    }
    
    /// Create a CHANNEL_JOIN packet
    pub fn create_channel_join(sender_id: [u8; 8], channel: &str) -> BitchatPacket {
        BitchatPacket::new_broadcast(
            MessageType::ChannelJoin,
            sender_id,
            channel.as_bytes().to_vec(),
        )
    }
    
    /// Create a CHANNEL_LEAVE packet
    pub fn create_channel_leave(sender_id: [u8; 8], channel: &str) -> BitchatPacket {
        BitchatPacket::new_broadcast(
            MessageType::ChannelLeave,
            sender_id,
            channel.as_bytes().to_vec(),
        )
    }
    
    /// Create a LEAVE packet
    pub fn create_leave(sender_id: [u8; 8]) -> BitchatPacket {
        BitchatPacket::new_broadcast(
            MessageType::Leave,
            sender_id,
            vec![],
        )
    }
    
    /// Create a DELIVERY_ACK packet
    pub fn create_delivery_ack(sender_id: [u8; 8], message_id: u32) -> BitchatPacket {
        let payload = message_id.to_be_bytes().to_vec();
        BitchatPacket::new_broadcast(
            MessageType::DeliveryAck,
            sender_id,
            payload,
        )
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// Get current timestamp in milliseconds
fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Generate a unique message ID
fn generate_message_id() -> u32 {
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(1);
    
    let timestamp = (current_timestamp() & 0xFFFF) as u32; // Lower 16 bits of timestamp
    let counter = COUNTER.fetch_add(1, Ordering::Relaxed) & 0xFFFF; // Lower 16 bits of counter
    
    (timestamp << 16) | counter
}

/// Convert peer ID string to bytes
fn peer_id_to_bytes(peer_id: &str) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    if peer_id.len() >= 16 {
        if let Ok(decoded) = hex::decode(&peer_id[..16]) {
            if decoded.len() == 8 {
                bytes.copy_from_slice(&decoded);
            }
        }
    }
    bytes
}

/// Convert peer ID bytes to string
fn bytes_to_peer_id(bytes: &[u8; 8]) -> String {
    hex::encode(bytes).to_uppercase()
}

/// Peer ID utilities - Add these functions to the existing peer_utils module
pub mod peer_utils {
    use rand::Rng;
    use std::hash::{Hash, Hasher};
    use std::collections::hash_map::DefaultHasher;
    
    /// Generate a random 8-byte peer ID
    pub fn generate_peer_id() -> [u8; 8] {
        rand::thread_rng().gen()
    }
    
    
    /// Convert peer ID to hex string
    pub fn peer_id_to_string(peer_id: &[u8; 8]) -> String {
        hex::encode(peer_id).to_uppercase()
    }
    
    /// Parse hex string to peer ID
    pub fn string_to_peer_id(s: &str) -> Option<[u8; 8]> {
        if s.len() == 16 {
            hex::decode(s).ok()?.try_into().ok()
        } else {
            None
        }
    }
    
    /// Generate peer ID from device name
    pub fn peer_id_from_device_name(device_name: &str) -> [u8; 8] {
        let mut hasher = DefaultHasher::new();
        device_name.hash(&mut hasher);
        let hash = hasher.finish();
        
        let mut peer_id = [0u8; 8];
        peer_id.copy_from_slice(&hash.to_be_bytes());
        peer_id
    }
    
    /// Generate a compatible peer ID string (for iOS/Android compatibility)
    pub fn generate_compatible_peer_id() -> String {
        let peer_id = generate_peer_id();
        peer_id_to_string(&peer_id)
    }
    
    /// Generate peer ID from device info (deterministic)
    pub fn peer_id_from_device_info(device_info: &str) -> String {
        let peer_bytes = peer_id_from_device_name(device_info);
        peer_id_to_string(&peer_bytes)
    }
    
    /// Check if peer ID string is valid
    pub fn is_valid_peer_id_string(peer_id: &str) -> bool {
        peer_id.len() == 16 && 
        peer_id.chars().all(|c| c.is_ascii_hexdigit())
    }
    
    /// Convert peer ID string to bytes with error handling
    pub fn peer_id_string_to_bytes(peer_id: &str) -> Result<[u8; 8], String> {
        if !is_valid_peer_id_string(peer_id) {
            return Err(format!("Invalid peer ID format: {}", peer_id));
        }
        
        let decoded = hex::decode(peer_id)
            .map_err(|e| format!("Failed to decode peer ID: {}", e))?;
        
        if decoded.len() != 8 {
            return Err(format!("Peer ID must be 8 bytes, got {}", decoded.len()));
        }
        
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&decoded);
        Ok(bytes)
    }
    
    /// Determine if we should initiate connection based on peer ID comparison
    pub fn should_initiate_connection(my_peer_id: &str, remote_peer_id: &str) -> bool {
        my_peer_id < remote_peer_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_packet_encode_decode_roundtrip() {
        let packet = BitchatPacket::new_broadcast(
            MessageType::Message,
            [1, 2, 3, 4, 5, 6, 7, 8],
            b"Hello, BitChat!".to_vec(),
        );
        
        let encoded = BinaryProtocol::encode(&packet).unwrap();
        let decoded = BinaryProtocol::decode(&encoded).unwrap();
        
        assert_eq!(packet.version, decoded.version);
        assert_eq!(packet.message_type, decoded.message_type);
        assert_eq!(packet.sender_id, decoded.sender_id);
        assert_eq!(packet.message_id, decoded.message_id);
        assert_eq!(packet.payload, decoded.payload);
    }
    
    #[test]
    fn test_message_fragmentation() {
        let sender_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let large_message = "A".repeat(1000); // Larger than FRAGMENT_SIZE
        
        let fragments = FragmentationManager::fragment_message(
            MessageType::Message,
            sender_id,
            None,
            large_message.as_bytes().to_vec(),
        ).unwrap();
        
        assert!(fragments.len() > 1);
        assert!(fragments.iter().all(|f| f.is_fragment()));
        
        // All fragments should have the same message ID
        let message_id = fragments[0].message_id;
        assert!(fragments.iter().all(|f| f.message_id == message_id));
    }
}