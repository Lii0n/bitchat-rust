//! Message storage and management for BitChat
//! 
//! Provides persistent message storage using SQLite with support for:
//! - Direct messages between peers
//! - Channel messages
//! - Message history and search
//! - Encryption status tracking
//! - Message delivery status

use anyhow::{Result, anyhow};
use chrono::{DateTime, Utc};
use rusqlite::{Connection, params, Row};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tracing::{info, warn, debug};

/// Message types in the BitChat system
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Direct message between two peers
    Direct,
    /// Message in a channel
    Channel,
    /// System message (join/leave notifications, etc.)
    System,
    /// Ping/Pong connectivity test
    Ping,
}

/// Message delivery status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DeliveryStatus {
    /// Message is queued for sending
    Pending,
    /// Message has been sent via GATT
    Sent,
    /// Message delivery confirmed by recipient
    Delivered,
    /// Message has been read by recipient
    Read,
    /// Message delivery failed
    Failed,
}

/// A stored message in the BitChat system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    /// Unique message ID
    pub id: i64,
    /// Message type (direct, channel, system)
    pub message_type: MessageType,
    /// Sender peer ID (hex string)
    pub sender_id: String,
    /// Recipient peer ID for direct messages (hex string)
    pub recipient_id: Option<String>,
    /// Channel name for channel messages
    pub channel: Option<String>,
    /// Message content
    pub content: String,
    /// Message timestamp (when created)
    pub timestamp: DateTime<Utc>,
    /// Whether message was encrypted
    pub encrypted: bool,
    /// Delivery status
    pub delivery_status: DeliveryStatus,
    /// Protocol version used
    pub protocol_version: u8,
    /// Message ID from BitChat protocol (for deduplication)
    pub protocol_message_id: Option<u32>,
}

/// Message storage and management system
pub struct MessageManager {
    /// SQLite database connection
    connection: Arc<Mutex<Connection>>,
    /// Database file path
    db_path: PathBuf,
}

impl MessageManager {
    /// Create a new message manager with database at the specified path
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let db_path = db_path.as_ref().to_path_buf();
        
        // Ensure parent directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        // Open/create SQLite database
        let connection = Connection::open(&db_path)?;
        let manager = Self {
            connection: Arc::new(Mutex::new(connection)),
            db_path: db_path.clone(),
        };
        
        // Initialize database schema
        manager.initialize_database()?;
        
        info!("📦 Message storage initialized at: {:?}", db_path);
        Ok(manager)
    }
    
    /// Create message manager with default path in user data directory
    pub fn with_default_path() -> Result<Self> {
        let data_dir = dirs::data_dir()
            .ok_or_else(|| anyhow!("Cannot determine user data directory"))?
            .join("BitChat");
        
        let db_path = data_dir.join("messages.db");
        Self::new(db_path)
    }
    
    /// Initialize database schema
    fn initialize_database(&self) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        
        // Create messages table
        conn.execute(
            "CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message_type TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                recipient_id TEXT,
                channel TEXT,
                content TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                encrypted BOOLEAN NOT NULL DEFAULT 0,
                delivery_status TEXT NOT NULL DEFAULT 'pending',
                protocol_version INTEGER NOT NULL DEFAULT 1,
                protocol_message_id INTEGER,
                UNIQUE(protocol_message_id, sender_id) ON CONFLICT IGNORE
            )",
            [],
        )?;
        
        // Create indexes for better query performance
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient_id)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_timestamp ON messages(timestamp DESC)",
            [],
        )?;
        
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_protocol_id ON messages(protocol_message_id, sender_id)",
            [],
        )?;
        
        debug!("✅ Database schema initialized");
        Ok(())
    }
    
    /// Store a new message
    pub fn store_message(&self, message: StoredMessage) -> Result<i64> {
        let conn = self.connection.lock().unwrap();
        
        let message_type_str = match message.message_type {
            MessageType::Direct => "direct",
            MessageType::Channel => "channel",
            MessageType::System => "system",
            MessageType::Ping => "ping",
        };
        
        let delivery_status_str = match message.delivery_status {
            DeliveryStatus::Pending => "pending",
            DeliveryStatus::Sent => "sent",
            DeliveryStatus::Delivered => "delivered",
            DeliveryStatus::Read => "read",
            DeliveryStatus::Failed => "failed",
        };
        
        let mut stmt = conn.prepare("
            INSERT INTO messages (
                message_type, sender_id, recipient_id, channel, content, 
                timestamp, encrypted, delivery_status, protocol_version, protocol_message_id
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
        ")?;
        
        let message_id = stmt.insert(params![
            message_type_str,
            message.sender_id,
            message.recipient_id,
            message.channel,
            message.content,
            message.timestamp,
            message.encrypted,
            delivery_status_str,
            message.protocol_version,
            message.protocol_message_id,
        ])?;
        
        debug!("💾 Stored message ID {} from {}", message_id, message.sender_id);
        Ok(message_id)
    }
    
    /// Store a simple text message (convenience method)
    pub fn store_simple_message(&self, sender: &str, content: &str) -> Result<i64> {
        let message = StoredMessage {
            id: 0, // Will be assigned by database
            message_type: MessageType::Direct,
            sender_id: sender.to_string(),
            recipient_id: None,
            channel: None,
            content: content.to_string(),
            timestamp: Utc::now(),
            encrypted: false,
            delivery_status: DeliveryStatus::Pending,
            protocol_version: 1,
            protocol_message_id: None,
        };
        
        self.store_message(message)
    }
    
    /// Get all messages (latest first)
    pub fn get_messages(&self) -> Result<Vec<StoredMessage>> {
        self.get_messages_with_limit(None)
    }
    
    /// Get messages with optional limit
    pub fn get_messages_with_limit(&self, limit: Option<usize>) -> Result<Vec<StoredMessage>> {
        let conn = self.connection.lock().unwrap();
        
        let query = if let Some(limit) = limit {
            format!("SELECT * FROM messages ORDER BY timestamp DESC LIMIT {}", limit)
        } else {
            "SELECT * FROM messages ORDER BY timestamp DESC".to_string()
        };
        
        let mut stmt = conn.prepare(&query)?;
        let message_iter = stmt.query_map([], |row| {
            Ok(self.row_to_message(row)?)
        })?;
        
        let mut messages = Vec::new();
        for message in message_iter {
            messages.push(message?);
        }
        
        debug!("📖 Retrieved {} messages", messages.len());
        Ok(messages)
    }
    
    /// Get messages for a specific channel
    pub fn get_channel_messages(&self, channel: &str, limit: Option<usize>) -> Result<Vec<StoredMessage>> {
        let conn = self.connection.lock().unwrap();
        
        let query = if let Some(limit) = limit {
            format!("SELECT * FROM messages WHERE channel = ?1 ORDER BY timestamp DESC LIMIT {}", limit)
        } else {
            "SELECT * FROM messages WHERE channel = ?1 ORDER BY timestamp DESC".to_string()
        };
        
        let mut stmt = conn.prepare(&query)?;
        let message_iter = stmt.query_map(params![channel], |row| {
            Ok(self.row_to_message(row)?)
        })?;
        
        let mut messages = Vec::new();
        for message in message_iter {
            messages.push(message?);
        }
        
        debug!("📖 Retrieved {} messages for channel {}", messages.len(), channel);
        Ok(messages)
    }
    
    /// Get direct messages between two peers
    pub fn get_direct_messages(&self, peer1: &str, peer2: &str, limit: Option<usize>) -> Result<Vec<StoredMessage>> {
        let conn = self.connection.lock().unwrap();
        
        let query = if let Some(limit) = limit {
            format!("SELECT * FROM messages WHERE 
                message_type = 'direct' AND 
                ((sender_id = ?1 AND recipient_id = ?2) OR (sender_id = ?2 AND recipient_id = ?1))
                ORDER BY timestamp DESC LIMIT {}", limit)
        } else {
            "SELECT * FROM messages WHERE 
                message_type = 'direct' AND 
                ((sender_id = ?1 AND recipient_id = ?2) OR (sender_id = ?2 AND recipient_id = ?1))
                ORDER BY timestamp DESC".to_string()
        };
        
        let mut stmt = conn.prepare(&query)?;
        let message_iter = stmt.query_map(params![peer1, peer2], |row| {
            Ok(self.row_to_message(row)?)
        })?;
        
        let mut messages = Vec::new();
        for message in message_iter {
            messages.push(message?);
        }
        
        debug!("📖 Retrieved {} direct messages between {} and {}", messages.len(), peer1, peer2);
        Ok(messages)
    }
    
    /// Search messages by content
    pub fn search_messages(&self, query: &str, limit: Option<usize>) -> Result<Vec<StoredMessage>> {
        let conn = self.connection.lock().unwrap();
        
        let sql_query = if let Some(limit) = limit {
            format!("SELECT * FROM messages WHERE content LIKE ?1 ORDER BY timestamp DESC LIMIT {}", limit)
        } else {
            "SELECT * FROM messages WHERE content LIKE ?1 ORDER BY timestamp DESC".to_string()
        };
        
        let search_pattern = format!("%{}%", query);
        let mut stmt = conn.prepare(&sql_query)?;
        let message_iter = stmt.query_map(params![search_pattern], |row| {
            Ok(self.row_to_message(row)?)
        })?;
        
        let mut messages = Vec::new();
        for message in message_iter {
            messages.push(message?);
        }
        
        debug!("🔍 Found {} messages matching '{}'", messages.len(), query);
        Ok(messages)
    }
    
    /// Update message delivery status
    pub fn update_delivery_status(&self, message_id: i64, status: DeliveryStatus) -> Result<()> {
        let conn = self.connection.lock().unwrap();
        
        let status_str = match status {
            DeliveryStatus::Pending => "pending",
            DeliveryStatus::Sent => "sent",
            DeliveryStatus::Delivered => "delivered",
            DeliveryStatus::Read => "read",
            DeliveryStatus::Failed => "failed",
        };
        
        conn.execute(
            "UPDATE messages SET delivery_status = ?1 WHERE id = ?2",
            params![status_str, message_id],
        )?;
        
        debug!("📊 Updated message {} delivery status to {:?}", message_id, status);
        Ok(())
    }
    
    /// Get message statistics
    pub fn get_message_stats(&self) -> Result<MessageStats> {
        let conn = self.connection.lock().unwrap();
        
        // Total messages
        let total_messages: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages",
            [],
            |row| row.get(0)
        )?;
        
        // Messages by type
        let direct_messages: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE message_type = 'direct'",
            [],
            |row| row.get(0)
        )?;
        
        let channel_messages: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE message_type = 'channel'",
            [],
            |row| row.get(0)
        )?;
        
        // Encrypted messages
        let encrypted_messages: i64 = conn.query_row(
            "SELECT COUNT(*) FROM messages WHERE encrypted = 1",
            [],
            |row| row.get(0)
        )?;
        
        // Unique peers
        let unique_peers: i64 = conn.query_row(
            "SELECT COUNT(DISTINCT sender_id) FROM messages",
            [],
            |row| row.get(0)
        )?;
        
        Ok(MessageStats {
            total_messages: total_messages as usize,
            direct_messages: direct_messages as usize,
            channel_messages: channel_messages as usize,
            encrypted_messages: encrypted_messages as usize,
            unique_peers: unique_peers as usize,
        })
    }
    
    /// Delete messages older than the specified duration
    pub fn cleanup_old_messages(&self, older_than_days: u32) -> Result<usize> {
        let conn = self.connection.lock().unwrap();
        
        let cutoff_date = Utc::now() - chrono::Duration::days(older_than_days as i64);
        
        let deleted_count = conn.execute(
            "DELETE FROM messages WHERE timestamp < ?1",
            params![cutoff_date],
        )?;
        
        info!("🧹 Cleaned up {} messages older than {} days", deleted_count, older_than_days);
        Ok(deleted_count)
    }
    
    /// Convert database row to StoredMessage
    fn row_to_message(&self, row: &Row) -> Result<StoredMessage, rusqlite::Error> {
        let message_type_str: String = row.get("message_type")?;
        let message_type = match message_type_str.as_str() {
            "direct" => MessageType::Direct,
            "channel" => MessageType::Channel,
            "system" => MessageType::System,
            "ping" => MessageType::Ping,
            _ => MessageType::Direct, // Default fallback
        };
        
        let delivery_status_str: String = row.get("delivery_status")?;
        let delivery_status = match delivery_status_str.as_str() {
            "pending" => DeliveryStatus::Pending,
            "sent" => DeliveryStatus::Sent,
            "delivered" => DeliveryStatus::Delivered,
            "read" => DeliveryStatus::Read,
            "failed" => DeliveryStatus::Failed,
            _ => DeliveryStatus::Pending, // Default fallback
        };
        
        Ok(StoredMessage {
            id: row.get("id")?,
            message_type,
            sender_id: row.get("sender_id")?,
            recipient_id: row.get("recipient_id")?,
            channel: row.get("channel")?,
            content: row.get("content")?,
            timestamp: row.get("timestamp")?,
            encrypted: row.get("encrypted")?,
            delivery_status,
            protocol_version: row.get("protocol_version")?,
            protocol_message_id: row.get("protocol_message_id")?,
        })
    }
    
    /// Get database file path
    pub fn database_path(&self) -> &Path {
        &self.db_path
    }
}

/// Message storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageStats {
    pub total_messages: usize,
    pub direct_messages: usize,
    pub channel_messages: usize,
    pub encrypted_messages: usize,
    pub unique_peers: usize,
}