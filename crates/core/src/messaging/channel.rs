//! Channel management for SecureMesh

use std::collections::HashSet;

/// Channel manager handles chat channels
pub struct ChannelManager {
    joined_channels: HashSet<String>,
    current_channel: Option<String>,
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {
            joined_channels: HashSet::new(),
            current_channel: None,
        }
    }
    
    pub fn join_channel(&mut self, channel: &str) -> bool {
        let was_new = self.joined_channels.insert(channel.to_string());
        self.current_channel = Some(channel.to_string());
        was_new
    }
    
    pub fn leave_channel(&mut self, channel: &str) -> bool {
        let was_present = self.joined_channels.remove(channel);
        if self.current_channel.as_deref() == Some(channel) {
            self.current_channel = None;
        }
        was_present
    }
    
    pub fn get_joined_channels(&self) -> Vec<String> {
        self.joined_channels.iter().cloned().collect()
    }
    
    pub fn get_current_channel(&self) -> Option<&String> {
        self.current_channel.as_ref()
    }

    pub fn normalize_channel_name(channel: &str) -> String {
        if channel.starts_with('#') {
            channel.to_lowercase()
        } else {
            format!("#{}", channel.to_lowercase())
        }
    }
}