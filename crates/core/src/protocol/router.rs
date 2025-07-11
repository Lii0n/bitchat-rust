use super::{BitchatPacket, MessageType};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Packet processing actions
#[derive(Debug, Clone)]
pub enum PacketAction {
    /// Process the packet locally
    Process,
    /// Relay the packet to other peers
    Relay,
    /// Drop the packet (duplicate or expired)
    Drop,
}

/// Packet router handles message routing and duplicate detection
pub struct PacketRouter {
    /// Our peer ID
    my_peer_id: [u8; 8],
    /// Recently seen packets (packet_id -> timestamp)
    seen_packets: HashMap<String, u64>,
    /// Maximum age for seen packets (in seconds)
    max_packet_age: u64,
}

impl PacketRouter {
    pub fn new(my_peer_id: [u8; 8]) -> Self {
        Self {
            my_peer_id,
            seen_packets: HashMap::new(),
            max_packet_age: 300, // 5 minutes
        }
    }

    /// Process an incoming packet and determine action
    pub fn process_packet(&mut self, packet: &BitchatPacket) -> PacketAction {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Clean up old packets periodically
        self.cleanup_old_packets(now);

        // Check if we've seen this packet before
        let packet_id = packet.packet_id();
        if self.seen_packets.contains_key(&packet_id) {
            return PacketAction::Drop;
        }

        // Mark packet as seen
        self.seen_packets.insert(packet_id, now);

        // Check if packet is for us or broadcast
        if packet.is_broadcast() || packet.recipient_id == Some(self.my_peer_id) {
            // For broadcast or directed to us, process locally
            if packet.ttl > 1 {
                // Still has hops left, can be relayed too
                PacketAction::Process
            } else {
                // Last hop, just process
                PacketAction::Process
            }
        } else if packet.ttl > 1 {
            // Not for us, but still has hops - relay it
            PacketAction::Relay
        } else {
            // Not for us and no hops left - drop
            PacketAction::Drop
        }
    }

    /// Create a relay packet with decremented TTL
    pub fn create_relay_packet(&self, original: &BitchatPacket) -> Option<BitchatPacket> {
        if original.ttl <= 1 {
            return None;
        }

        let mut relay_packet = original.clone();
        relay_packet.ttl -= 1;
        Some(relay_packet)
    }

    /// Clean up old packets from the seen list
    fn cleanup_old_packets(&mut self, now: u64) {
        self.seen_packets.retain(|_, &mut timestamp| {
            now - timestamp < self.max_packet_age
        });
    }

    /// Check if a packet was recently seen
    pub fn has_seen_packet(&self, packet_id: &str) -> bool {
        self.seen_packets.contains_key(packet_id)
    }

    /// Get the number of tracked packets
    pub fn tracked_packet_count(&self) -> usize {
        self.seen_packets.len()
    }
}

/// Trait for processing different message types
pub trait MessageProcessor {
    fn handle_announce(&self, packet: &BitchatPacket, nickname: &str);
    fn handle_message(&self, packet: &BitchatPacket, content: &str);
    fn handle_leave(&self, packet: &BitchatPacket);
}

/// Default message processor that just logs
pub struct DefaultMessageProcessor;

impl MessageProcessor for DefaultMessageProcessor {
    fn handle_announce(&self, packet: &BitchatPacket, nickname: &str) {
        tracing::info!("ANNOUNCE from {}: {}", 
                      hex::encode(&packet.sender_id[..4]), nickname);
    }
    
    fn handle_message(&self, packet: &BitchatPacket, content: &str) {
        tracing::info!("MESSAGE from {}: {}", 
                      hex::encode(&packet.sender_id[..4]), content);
    }
    
    fn handle_leave(&self, packet: &BitchatPacket) {
        tracing::info!("LEAVE from {}", 
                      hex::encode(&packet.sender_id[..4]));
    }
}

/// Process packet content based on message type
pub fn process_packet_content(packet: &BitchatPacket, processor: &dyn MessageProcessor) {
    match packet.message_type {
        MessageType::Announce => {
            if let Ok(nickname) = String::from_utf8(packet.payload.clone()) {
                processor.handle_announce(packet, &nickname);
            }
        }
        MessageType::Message => {
            if let Ok(content) = String::from_utf8(packet.payload.clone()) {
                processor.handle_message(packet, &content);
            }
        }
        MessageType::Leave => {
            processor.handle_leave(packet);
        }
        MessageType::KeyExchange => {
            tracing::debug!("KEY_EXCHANGE packet from {}", 
                          hex::encode(&packet.sender_id[..4]));
        }
        MessageType::DeliveryAck => {
            tracing::debug!("DELIVERY_ACK packet from {}", 
                          hex::encode(&packet.sender_id[..4]));
        }
        _ => {
            tracing::debug!("Other packet type {:?} from {}", 
                          packet.message_type,
                          hex::encode(&packet.sender_id[..4]));
        }
    }
}