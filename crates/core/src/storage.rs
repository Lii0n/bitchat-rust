use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredMessage {
    pub id: String,
    pub sender_id: String,
    pub content: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub channel: Option<String>,
}

#[derive(Debug)]
pub struct Storage {
    data_dir: PathBuf,
    messages_file: PathBuf,
    peers_file: PathBuf,
}

impl Storage {
    pub fn new(data_dir: &str) -> Result<Self> {
        let data_dir = PathBuf::from(data_dir);
        let messages_file = data_dir.join("messages.json");
        let peers_file = data_dir.join("peers.json");

        // Create data directory if it doesn't exist
        std::fs::create_dir_all(&data_dir)?;

        Ok(Self {
            data_dir,
            messages_file,
            peers_file,
        })
    }

    pub fn store_message(&self, message: StoredMessage) -> Result<()> {
        let mut messages = self.load_messages().unwrap_or_default();
        messages.insert(message.id.clone(), message);
        self.save_messages(&messages)
    }

    pub fn load_messages(&self) -> Result<HashMap<String, StoredMessage>> {
        if !self.messages_file.exists() {
            return Ok(HashMap::new());
        }

        let content = std::fs::read_to_string(&self.messages_file)?;
        let messages: HashMap<String, StoredMessage> = serde_json::from_str(&content)?;
        Ok(messages)
    }

    fn save_messages(&self, messages: &HashMap<String, StoredMessage>) -> Result<()> {
        let content = serde_json::to_string_pretty(messages)?;
        std::fs::write(&self.messages_file, content)?;
        Ok(())
    }

    pub fn get_messages_for_channel(&self, channel: Option<&str>) -> Result<Vec<StoredMessage>> {
        let messages = self.load_messages()?;
        let filtered: Vec<StoredMessage> = messages
            .values()
            .filter(|msg| msg.channel.as_deref() == channel)
            .cloned()
            .collect();
        Ok(filtered)
    }

    pub fn clear_messages(&self) -> Result<()> {
        if self.messages_file.exists() {
            std::fs::remove_file(&self.messages_file)?;
        }
        Ok(())
    }

    pub fn store_peer_info(&self, peer_id: &str, nickname: &str) -> Result<()> {
        let mut peers = self.load_peer_info().unwrap_or_default();
        peers.insert(peer_id.to_string(), nickname.to_string());
        self.save_peer_info(&peers)
    }

    pub fn load_peer_info(&self) -> Result<HashMap<String, String>> {
        if !self.peers_file.exists() {
            return Ok(HashMap::new());
        }

        let content = std::fs::read_to_string(&self.peers_file)?;
        let peers: HashMap<String, String> = serde_json::from_str(&content)?;
        Ok(peers)
    }

    fn save_peer_info(&self, peers: &HashMap<String, String>) -> Result<()> {
        let content = serde_json::to_string_pretty(peers)?;
        std::fs::write(&self.peers_file, content)?;
        Ok(())
    }

    pub fn get_data_dir(&self) -> &Path {
        &self.data_dir
    }
}
