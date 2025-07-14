//! Packet definition for SecureMesh protocol

use serde::{Deserialize, Serialize};

/// Message packet for SecureMesh protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Packet {
    pub sender_id: String,
    pub recipient_id: Option<String>,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Announce,
    Message,
    KeyExchange,
    Ack,
}