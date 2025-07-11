use anyhow::Result;
use std::path::{Path, PathBuf};
use std::fs;
use crate::{Message, Peer};

/// Storage manager for BitChat data
pub struct Storage {
    pub data_dir: PathBuf,
}

impl Storage {
    pub fn new(data_dir: &Path) -> Result<Self> {
        // Create data directory if it doesn't exist
        if !data_dir.exists() {
            fs::create_dir_all(data_dir)?;
        }

        Ok(Self {
            data_dir: data_dir.to_path_buf(),
        })
    }

    /// Save a message to storage
    pub fn save_message(&self, message: &Message) -> Result<()> {
        let messages_dir = self.data_dir.join("messages");
        if !messages_dir.exists() {
            fs::create_dir_all(&messages_dir)?;
        }

        let message_file = messages_dir.join(format!("{}.json", message.id));
        let json = serde_json::to_string_pretty(message)?;
        fs::write(message_file, json)?;

        Ok(())
    }

    /// Load all messages from storage
    pub fn load_messages(&self) -> Result<Vec<Message>> {
        let messages_dir = self.data_dir.join("messages");
        if !messages_dir.exists() {
            return Ok(Vec::new());
        }

        let mut messages = Vec::new();
        for entry in fs::read_dir(&messages_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(entry.path())?;
                if let Ok(message) = serde_json::from_str::<Message>(&content) {
                    messages.push(message);
                }
            }
        }

        // Sort by timestamp
        messages.sort_by_key(|m| m.timestamp);
        Ok(messages)
    }

    /// Save peer information
    pub fn save_peer(&self, peer: &Peer) -> Result<()> {
        let peers_dir = self.data_dir.join("peers");
        if !peers_dir.exists() {
            fs::create_dir_all(&peers_dir)?;
        }

        let peer_file = peers_dir.join(format!("{}.json", peer.id));
        let json = serde_json::to_string_pretty(peer)?;
        fs::write(peer_file, json)?;

        Ok(())
    }

    /// Load all known peers
    pub fn load_peers(&self) -> Result<Vec<Peer>> {
        let peers_dir = self.data_dir.join("peers");
        if !peers_dir.exists() {
            return Ok(Vec::new());
        }

        let mut peers = Vec::new();
        for entry in fs::read_dir(&peers_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                let content = fs::read_to_string(entry.path())?;
                if let Ok(peer) = serde_json::from_str::<Peer>(&content) {
                    peers.push(peer);
                }
            }
        }

        Ok(peers)
    }

    /// Clear all stored data
    pub fn clear_all(&self) -> Result<()> {
        if self.data_dir.exists() {
            fs::remove_dir_all(&self.data_dir)?;
            fs::create_dir_all(&self.data_dir)?;
        }
        Ok(())
    }

    /// Get storage statistics
    pub fn get_stats(&self) -> Result<StorageStats> {
        let messages_count = self.count_files_in_dir("messages")?;
        let peers_count = self.count_files_in_dir("peers")?;
        
        Ok(StorageStats {
            messages_count,
            peers_count,
            data_dir_size: self.calculate_dir_size(&self.data_dir)?,
        })
    }

    fn count_files_in_dir(&self, subdir: &str) -> Result<usize> {
        let dir = self.data_dir.join(subdir);
        if !dir.exists() {
            return Ok(0);
        }

        let mut count = 0;
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            if entry.path().is_file() {
                count += 1;
            }
        }
        Ok(count)
    }

    fn calculate_dir_size(&self, dir: &Path) -> Result<u64> {
        let mut size = 0;
        if !dir.exists() {
            return Ok(0);
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                size += entry.metadata()?.len();
            } else if path.is_dir() {
                size += self.calculate_dir_size(&path)?;
            }
        }
        Ok(size)
    }
}

/// Storage statistics
#[derive(Debug)]
pub struct StorageStats {
    pub messages_count: usize,
    pub peers_count: usize,
    pub data_dir_size: u64,
}