//! Command handling for BitChat operations
//! 
//! This module provides command processing functionality for the BitChat CLI
//! and other interfaces that need to handle user commands.

use anyhow::Result;
use std::collections::HashMap;

// Import required types from the core library
use crate::{
    BitchatCore, 
    BinaryProtocolManager, 
    BitchatPacket,
    ChannelManager,
    Config,
    CryptoManager,
    Storage,
    PeerManager,
    PacketRouter,
};

#[cfg(feature = "bluetooth")]
use crate::{BluetoothManager, BluetoothConfig, BluetoothEvent};

use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use serde::{Serialize, Deserialize};

/// Command processing results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommandResult {
    Success(String),
    Error(String),
    Exit,
}

/// Available commands in BitChat
#[derive(Debug, Clone)]
pub enum BitchatCommand {
    // Channel commands
    JoinChannel(String),
    LeaveChannel(String),
    ListChannels,
    SetChannel(String),
    SendChannelMessage(String, String), // channel, message
    
    // Peer commands
    ListPeers,
    SendDirectMessage(String, String), // peer_id, message
    
    // System commands
    Status,
    Help,
    Quit,
    
    // Protocol commands
    Announce(String), // nickname
    Ping(String),     // peer_id
}

impl BitchatCommand {
    /// Parse a command string into a BitchatCommand
    pub fn parse(input: &str) -> Result<Self> {
        let parts: Vec<&str> = input.trim().split_whitespace().collect();
        if parts.is_empty() {
            return Err(anyhow::anyhow!("Empty command"));
        }

        match parts[0] {
            "/join" | "/j" => {
                if parts.len() < 2 {
                    return Err(anyhow::anyhow!("Usage: /join <channel>"));
                }
                Ok(BitchatCommand::JoinChannel(parts[1].to_string()))
            },
            "/leave" | "/l" => {
                if parts.len() < 2 {
                    return Err(anyhow::anyhow!("Usage: /leave <channel>"));
                }
                Ok(BitchatCommand::LeaveChannel(parts[1].to_string()))
            },
            "/channels" | "/ch" => Ok(BitchatCommand::ListChannels),
            "/set" => {
                if parts.len() < 2 {
                    return Err(anyhow::anyhow!("Usage: /set <channel>"));
                }
                Ok(BitchatCommand::SetChannel(parts[1].to_string()))
            },
            "/peers" | "/p" => Ok(BitchatCommand::ListPeers),
            "/msg" | "/m" => {
                if parts.len() < 3 {
                    return Err(anyhow::anyhow!("Usage: /msg <peer_id> <message>"));
                }
                let peer_id = parts[1].to_string();
                let message = parts[2..].join(" ");
                Ok(BitchatCommand::SendDirectMessage(peer_id, message))
            },
            "/status" | "/s" => Ok(BitchatCommand::Status),
            "/help" | "/h" | "/?" => Ok(BitchatCommand::Help),
            "/quit" | "/exit" | "/q" => Ok(BitchatCommand::Quit),
            "/announce" | "/a" => {
                if parts.len() < 2 {
                    return Err(anyhow::anyhow!("Usage: /announce <nickname>"));
                }
                Ok(BitchatCommand::Announce(parts[1].to_string()))
            },
            "/ping" => {
                if parts.len() < 2 {
                    return Err(anyhow::anyhow!("Usage: /ping <peer_id>"));
                }
                Ok(BitchatCommand::Ping(parts[1].to_string()))
            },
            _ => {
                // If it doesn't start with /, treat as channel message
                if !input.starts_with('/') {
                    // This would need current channel context
                    return Err(anyhow::anyhow!("Not in a channel. Use /join <channel> first."));
                }
                Err(anyhow::anyhow!("Unknown command: {}", parts[0]))
            }
        }
    }

    /// Get help text for all commands
    pub fn help_text() -> String {
        r#"
BitChat Commands:

Channel Commands:
  /join <channel>     Join a channel
  /leave <channel>    Leave a channel  
  /channels           List all joined channels
  /set <channel>      Set current active channel

Messaging:
  <message>           Send message to current channel
  /msg <peer> <text>  Send direct message to peer

Peer Management:
  /peers              List connected peers
  /announce <nick>    Announce yourself with nickname
  /ping <peer>        Ping a specific peer

System:
  /status             Show system status
  /help               Show this help
  /quit               Exit BitChat

Examples:
  /join #general
  /set #general
  Hello everyone!
  /msg alice123 Hi Alice!
        "#.to_string()
    }
}

/// Command processor that handles BitChat commands
pub struct CommandProcessor {
    core: Arc<BitchatCore>,
    current_channel: Option<String>,
}

impl CommandProcessor {
    pub fn new(core: Arc<BitchatCore>) -> Self {
        Self {
            core,
            current_channel: None,
        }
    }

    /// Process a command and return the result
    pub async fn process_command(&mut self, input: &str) -> CommandResult {
        // Handle non-command messages (send to current channel)
        if !input.starts_with('/') {
            if let Some(ref channel) = self.current_channel {
                match self.core.send_channel_message(channel, input).await {
                    Ok(_) => CommandResult::Success(format!("[{}] You: {}", channel, input)),
                    Err(e) => CommandResult::Error(format!("Failed to send message: {}", e)),
                }
            } else {
                CommandResult::Error("No active channel. Use /join <channel> first.".to_string())
            }
        } else {
            // Parse and execute command
            match BitchatCommand::parse(input) {
                Ok(command) => self.execute_command(command).await,
                Err(e) => CommandResult::Error(format!("Invalid command: {}", e)),
            }
        }
    }

    /// Execute a parsed command
    async fn execute_command(&mut self, command: BitchatCommand) -> CommandResult {
        match command {
            BitchatCommand::JoinChannel(channel) => {
                match self.core.join_channel(&channel).await {
                    Ok(msg) => {
                        self.current_channel = Some(channel.clone());
                        CommandResult::Success(msg)
                    },
                    Err(e) => CommandResult::Error(format!("Failed to join channel: {}", e)),
                }
            },
            
            BitchatCommand::LeaveChannel(channel) => {
                match self.core.leave_channel(&channel).await {
                    Ok(msg) => {
                        if self.current_channel.as_ref() == Some(&channel) {
                            self.current_channel = None;
                        }
                        CommandResult::Success(msg)
                    },
                    Err(e) => CommandResult::Error(format!("Failed to leave channel: {}", e)),
                }
            },
            
            BitchatCommand::ListChannels => {
                match self.core.list_channels().await {
                    Ok(list) => CommandResult::Success(list),
                    Err(e) => CommandResult::Error(format!("Failed to list channels: {}", e)),
                }
            },
            
            BitchatCommand::SetChannel(channel) => {
                // Check if we're in this channel
                match self.core.list_channels().await {
                    Ok(list) => {
                        if list.contains(&channel) {
                            self.current_channel = Some(channel.clone());
                            CommandResult::Success(format!("Active channel set to {}", channel))
                        } else {
                            CommandResult::Error(format!("Not in channel {}. Use /join first.", channel))
                        }
                    },
                    Err(e) => CommandResult::Error(format!("Failed to check channels: {}", e)),
                }
            },
            
            BitchatCommand::SendChannelMessage(channel, message) => {
                match self.core.send_channel_message(&channel, &message).await {
                    Ok(_) => CommandResult::Success(format!("[{}] You: {}", channel, message)),
                    Err(e) => CommandResult::Error(format!("Failed to send message: {}", e)),
                }
            },
            
            BitchatCommand::ListPeers => {
                // This would need to be implemented in BitchatCore
                CommandResult::Success("Peer listing not yet implemented".to_string())
            },
            
            BitchatCommand::SendDirectMessage(_peer_id, _message) => {
                // This would need to be implemented in BitchatCore
                CommandResult::Success("Direct messaging not yet implemented".to_string())
            },
            
            BitchatCommand::Status => {
                let status = format!(
                    "BitChat Status:\n  Device: {}\n  Current Channel: {}\n  Peer ID: {}",
                    self.core.config.device_name,
                    self.current_channel.as_deref().unwrap_or("None"),
                    hex::encode(self.core.my_peer_id)
                );
                CommandResult::Success(status)
            },
            
            BitchatCommand::Help => {
                CommandResult::Success(BitchatCommand::help_text())
            },
            
            BitchatCommand::Quit => CommandResult::Exit,
            
            BitchatCommand::Announce(_nickname) => {
                // This would need to be implemented in BitchatCore
                CommandResult::Success("Announce not yet implemented".to_string())
            },
            
            BitchatCommand::Ping(_peer_id) => {
                // This would need to be implemented in BitchatCore
                CommandResult::Success("Ping not yet implemented".to_string())
            },
        }
    }

    /// Get the current active channel
    pub fn current_channel(&self) -> Option<&String> {
        self.current_channel.as_ref()
    }

    /// Set the current active channel
    pub fn set_current_channel(&mut self, channel: Option<String>) {
        self.current_channel = channel;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_parsing() {
        // Test join command
        let cmd = BitchatCommand::parse("/join #general").unwrap();
        matches!(cmd, BitchatCommand::JoinChannel(ch) if ch == "#general");

        // Test leave command
        let cmd = BitchatCommand::parse("/leave #general").unwrap();
        matches!(cmd, BitchatCommand::LeaveChannel(ch) if ch == "#general");

        // Test help command
        let cmd = BitchatCommand::parse("/help").unwrap();
        matches!(cmd, BitchatCommand::Help);

        // Test quit command variants
        assert!(matches!(BitchatCommand::parse("/quit").unwrap(), BitchatCommand::Quit));
        assert!(matches!(BitchatCommand::parse("/exit").unwrap(), BitchatCommand::Quit));
        assert!(matches!(BitchatCommand::parse("/q").unwrap(), BitchatCommand::Quit));

        // Test invalid commands
        assert!(BitchatCommand::parse("/invalid").is_err());
        assert!(BitchatCommand::parse("").is_err());
    }

    #[test]
    fn test_help_text() {
        let help = BitchatCommand::help_text();
        assert!(help.contains("Channel Commands"));
        assert!(help.contains("/join"));
        assert!(help.contains("/help"));
    }
}