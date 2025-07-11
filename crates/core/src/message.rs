use serde::{Deserialize, Serialize};
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub id: Uuid,
    pub content: String,
    pub sender: String,
    pub channel: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub message_type: MessageType,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessageType {
    Public,
    Private,
    System,
    ChannelJoin,
    ChannelLeave,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub name: String,
    pub password_protected: bool,
    pub owner: Option<String>,
    pub created_at: DateTime<Utc>,
    pub members: Vec<String>,
}

impl Message {
    pub fn new_public(content: String, sender: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            content,
            sender,
            channel: None,
            timestamp: Utc::now(),
            message_type: MessageType::Public,
            encrypted: false,
        }
    }

    pub fn new_private(content: String, sender: String, recipient: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            content,
            sender,
            channel: Some(recipient),
            timestamp: Utc::now(),
            message_type: MessageType::Private,
            encrypted: true,
        }
    }

    pub fn new_channel(content: String, sender: String, channel: String) -> Self {
        Self {
            id: Uuid::new_v4(),
            content,
            sender,
            channel: Some(channel),
            timestamp: Utc::now(),
            message_type: MessageType::Public,
            encrypted: false,
        }
    }
}
