//! Message types and handling for BitChat

use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Represents a message in the BitChat system
#[derive(Debug, Clone)]
pub struct Message {
    pub id: Uuid,
    pub content: String,
    pub sender_id: String,
    pub channel: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub message_type: MessageKind,
}

/// Different kinds of messages
#[derive(Debug, Clone, PartialEq)]
pub enum MessageKind {
    Text,
    Announce,
    System,
    ChannelJoin,
    ChannelLeave,
}

impl Message {
    /// Create a new text message
    pub fn new_text(content: String, sender_id: String, channel: Option<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            content,
            sender_id,
            channel,
            timestamp: Utc::now(),
            message_type: MessageKind::Text,
        }
    }
    
    /// Create a new announcement message
    pub fn new_announce(nickname: String, sender_id: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            content: nickname,
            sender_id,
            channel: None,
            timestamp: Utc::now(),
            message_type: MessageKind::Announce,
        }
    }
    
    /// Create a system message
    pub fn new_system(content: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            content,
            sender_id: "system".to_string(),
            channel: None,
            timestamp: Utc::now(),
            message_type: MessageKind::System,
        }
    }
}