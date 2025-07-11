use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub packet_type: PacketType,
    pub sender_id: Uuid,
    pub message_id: Uuid,
    pub ttl: u8,
    pub payload: Vec<u8>, // Changed from Bytes to Vec<u8>
    pub signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PacketType {
    Hello,
    Message,
    PrivateMessage,
    ChannelJoin,
    ChannelLeave,
    Ack,
    Ping,
    Pong,
}

pub struct BitchatProtocol;

impl BitchatProtocol {
    pub fn serialize_packet(packet: &Packet) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(packet)
    }

    pub fn deserialize_packet(data: &[u8]) -> Result<Packet, serde_json::Error> {
        serde_json::from_slice(data)
    }

    pub fn create_hello_packet(sender_id: Uuid) -> Packet {
        Packet {
            packet_type: PacketType::Hello,
            sender_id,
            message_id: Uuid::new_v4(),
            ttl: 7,
            payload: Vec::new(),
            signature: None,
        }
    }

    pub fn create_message_packet(sender_id: Uuid, content: String) -> Packet {
        let payload = content.into_bytes();
        Packet {
            packet_type: PacketType::Message,
            sender_id,
            message_id: Uuid::new_v4(),
            ttl: 7,
            payload,
            signature: None,
        }
    }
}
