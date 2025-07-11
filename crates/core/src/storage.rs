use anyhow::Result;
use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use crate::{Message, Peer, Channel};

pub struct Storage {
    data_dir: PathBuf,
}

impl Storage {
    pub fn new<P: AsRef<Path>>(data_dir: P) -> Result<Self> {
        let data_dir = data_dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&data_dir)?;
        
        Ok(Self { data_dir })
    }

    pub fn save_message(&self, message: &Message) -> Result<()> {
        let messages_dir = self.data_dir.join("messages");
        std::fs::create_dir_all(&messages_dir)?;
        
        let file_path = messages_dir.join(format!("{}.json", message.id));
        let json = serde_json::to_string_pretty(message)?;
        std::fs::write(file_path, json)?;
        
        Ok(())
    }

    pub fn load_messages(&self) -> Result<Vec<Message>> {
        let messages_dir = self.data_dir.join("messages");
        if !messages_dir.exists() {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        for entry in std::fs::read_dir(messages_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                let content = std::fs::read_to_string(entry.path())?;
                if let Ok(message) = serde_json::from_str::<Message>(&content) {
                    messages.push(message);
                }
            }
        }

        messages.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        Ok(messages)
    }

    pub fn save_peer(&self, peer: &Peer) -> Result<()> {
        let peers_dir = self.data_dir.join("peers");
        std::fs::create_dir_all(&peers_dir)?;
        
        let file_path = peers_dir.join(format!("{}.json", peer.id));
        let json = serde_json::to_string_pretty(peer)?;
        std::fs::write(file_path, json)?;
        
        Ok(())
    }

    pub fn clear_all_data(&self) -> Result<()> {
        if self.data_dir.exists() {
            std::fs::remove_dir_all(&self.data_dir)?;
            std::fs::create_dir_all(&self.data_dir)?;
        }
        Ok(())
    }
}
