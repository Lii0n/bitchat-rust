//! Channel management for BitChat
//! 
//! Consolidated channel management implementation

use std::collections::{HashMap, HashSet};
use anyhow::Result;

/// Channel management for BitChat
#[derive(Debug)]
pub struct ChannelManager {
    /// Channels we've joined
    joined_channels: HashSet<String>,
    /// Current active channel
    current_channel: Option<String>,
    /// Channel metadata
    channel_info: HashMap<String, ChannelInfo>,
}

#[derive(Debug, Clone)]
pub struct ChannelInfo {
    pub name: String,
    pub password_protected: bool,
    pub creator: Option<String>,
    pub member_count: usize,
}

impl ChannelManager {
    pub fn new() -> Self {
        Self {
            joined_channels: HashSet::new(),
            current_channel: None,
            channel_info: HashMap::new(),
        }
    }

    /// Join a channel
    pub fn join_channel(&mut self, channel: &str) -> Result<bool> {
        let channel = self.normalize_channel_name(channel);
        
        if self.joined_channels.contains(&channel) {
            self.current_channel = Some(channel.clone());
            return Ok(false); // Already joined
        }

        self.joined_channels.insert(channel.clone());
        self.current_channel = Some(channel.clone());
        
        // Add basic channel info
        self.channel_info.insert(channel.clone(), ChannelInfo {
            name: channel.clone(),
            password_protected: false,
            creator: None,
            member_count: 1,
        });
        
        Ok(true)
    }

    /// Leave a channel
    pub fn leave_channel(&mut self, channel: &str) -> Result<bool> {
        let channel = self.normalize_channel_name(channel);
        
        if !self.joined_channels.contains(&channel) {
            return Ok(false); // Not joined
        }

        self.joined_channels.remove(&channel);
        self.channel_info.remove(&channel);
        
        // If this was our current channel, clear it
        if self.current_channel.as_ref() == Some(&channel) {
            self.current_channel = None;
        }
        
        Ok(true)
    }

    /// Check if we're in a channel
    pub fn is_joined(&self, channel: &str) -> bool {
        let channel = self.normalize_channel_name(channel);
        self.joined_channels.contains(&channel)
    }

    /// Get list of joined channels
    pub fn get_joined_channels(&self) -> Vec<String> {
        self.joined_channels.iter().cloned().collect()
    }

    /// Get current active channel
    pub fn get_current_channel(&self) -> Option<&String> {
        self.current_channel.as_ref()
    }

    /// Set current active channel
    pub fn set_current_channel(&mut self, channel: Option<String>) {
        self.current_channel = channel;
    }

    /// Normalize channel name (ensure it starts with #)
    fn normalize_channel_name(&self, channel: &str) -> String {
        if channel.starts_with('#') {
            channel.to_string()
        } else {
            format!("#{}", channel)
        }
    }

    /// Update channel info
    pub fn update_channel_info(&mut self, channel: &str, info: ChannelInfo) {
        let channel = self.normalize_channel_name(channel);
        self.channel_info.insert(channel, info);
    }

    /// Get channel info
    pub fn get_channel_info(&self, channel: &str) -> Option<&ChannelInfo> {
        let channel = self.normalize_channel_name(channel);
        self.channel_info.get(&channel)
    }
}