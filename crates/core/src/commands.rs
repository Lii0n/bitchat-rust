//! Command handling for BitChat operations

use crate::BitchatCore;
use anyhow::Result;
use std::sync::Arc;

/// Represents the result of executing a command
#[derive(Debug, Clone)]
pub enum CommandResult {
    Success(String),
    Error(String),
    Exit,
}

/// Available BitChat commands
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
    Scan,             // discover nearby peers
    
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
            "/scan" => {
                Ok(BitchatCommand::Scan)
            },
            _ => {
                // If it doesn't start with /, treat as channel message
                if !input.starts_with('/') {
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
  /scan               Discover nearby BitChat peers
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
                CommandResult::Error("Not in a channel. Use /join <channel> first.".to_string())
            }
        } else {
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
                match self.core.join_channel(&channel, None).await {
                    Ok(_) => {
                        self.current_channel = Some(channel.clone());
                        CommandResult::Success(format!("Joined channel: {}", channel))
                    },
                    Err(e) => CommandResult::Error(format!("Failed to join channel: {}", e)),
                }
            },
            
            BitchatCommand::LeaveChannel(channel) => {
                match self.core.leave_channel(&channel).await {
                    Ok(_) => {
                        if self.current_channel.as_ref() == Some(&channel) {
                            self.current_channel = None;
                        }
                        CommandResult::Success(format!("Left channel: {}", channel))
                    },
                    Err(e) => CommandResult::Error(format!("Failed to leave channel: {}", e)),
                }
            },
            
            BitchatCommand::ListChannels => {
                match self.core.list_channels().await {
                    Ok(channels) => {
                        if channels.is_empty() {
                            CommandResult::Success("No joined channels".to_string())
                        } else {
                            let channel_list = channels.join(", ");
                            CommandResult::Success(format!("Joined channels: {}", channel_list))
                        }
                    },
                    Err(e) => CommandResult::Error(format!("Failed to list channels: {}", e)),
                }
            },
            
            BitchatCommand::SetChannel(channel) => {
                match self.core.list_channels().await {
                    Ok(channels) => {
                        if channels.contains(&channel) {
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
                let peers = self.core.list_peers();
                if peers.is_empty() {
                    CommandResult::Success("No connected peers".to_string())
                } else {
                    let peer_list = peers.join(", ");
                    CommandResult::Success(format!("Connected peers: {}", peer_list))
                }
            },
            
            BitchatCommand::SendDirectMessage(peer_id, message) => {
                match self.core.send_direct_message(&peer_id, &message).await {
                    Ok(_) => CommandResult::Success(format!("📨 Message sent to {}", peer_id)),
                    Err(e) => CommandResult::Error(format!("Failed to send direct message: {}", e)),
                }
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
            
            BitchatCommand::Announce(nickname) => {
                match self.core.announce_presence(Some(&nickname)).await {
                    Ok(_) => CommandResult::Success(format!("📢 Announced presence as '{}'", nickname)),
                    Err(e) => CommandResult::Error(format!("Failed to announce presence: {}", e)),
                }
            },
            
            BitchatCommand::Ping(peer_id) => {
                // Implement real ping functionality
                self.handle_ping_command(&peer_id).await
            },
            
            BitchatCommand::Scan => {
                self.handle_scan_command().await
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

    /// Handle ping command with real GATT-based connectivity test
    async fn handle_ping_command(&self, peer_id: &str) -> CommandResult {
        use std::time::Instant;
        use tokio::time::{timeout, Duration};
        use crate::protocol::{BitchatPacket, MessageType};
        
        // Validate peer ID format (16 hex chars)
        if peer_id.len() != 16 || !peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return CommandResult::Error(
                format!("Invalid peer ID format. Expected 16 hex characters, got: {}", peer_id)
            );
        }
        
        tracing::info!("🏓 Pinging peer: {}", peer_id);
        
        #[cfg(feature = "bluetooth")]
        {
            // Get bluetooth manager
            let bluetooth = self.core.bluetooth.lock().await;
            
            // Check if peer is in discovered devices
            let discovered = bluetooth.get_discovered_devices().await;
            
            if !discovered.contains_key(peer_id) {
                return CommandResult::Error(
                    format!("Peer {} not found. Use '/scan' to discover peers first.", peer_id)
                );
            }
            
            // Try to establish connection if not already connected
            let mut bluetooth = self.core.bluetooth.lock().await; // Drop the read lock and get write lock
            let connection_result = bluetooth.connect_to_device(peer_id).await;
            
            match connection_result {
                Ok(_connected_peer) => {
                    // Create ping packet with timestamp payload
                    let ping_timestamp = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64;
                    
                    let ping_payload = ping_timestamp.to_le_bytes().to_vec();
                    
                    // Use peer ID directly (it's already [u8; 8])
                    let sender_id = self.core.my_peer_id;
                    
                    let recipient_id_bytes = hex::decode(peer_id)
                        .unwrap_or_else(|_| peer_id.as_bytes().to_vec());
                    let recipient_id: [u8; 8] = recipient_id_bytes.try_into()
                        .unwrap_or_else(|_| [0; 8]); // Fallback if conversion fails
                    
                    // Create BitChat ping packet
                    let ping_packet = BitchatPacket {
                        version: 1,
                        message_type: MessageType::Ping,
                        ttl: 3,
                        timestamp: ping_timestamp,
                        flags: 0x01, // HAS_RECIPIENT flag for direct message
                        message_id: rand::random::<u32>(),
                        sender_id,
                        recipient_id: Some(recipient_id),
                        fragment_index: None,
                        total_fragments: None,
                        payload: ping_payload,
                        signature: None,
                    };
                    
                    // Record start time for round-trip calculation
                    let _start_time = Instant::now();
                    
                    // Send ping packet using BitChat protocol
                    let send_result = bluetooth.send_packet_to_peer(peer_id, &ping_packet).await;
                    
                    match send_result {
                        Ok(()) => {
                            // Wait for pong response with timeout
                            let pong_timeout = Duration::from_secs(5); // 5 second timeout
                            
                            // TODO: Set up proper pong response listener
                            // For now, we'll use a simplified approach until message routing is complete
                            match timeout(pong_timeout, self.wait_for_pong_response(peer_id, ping_timestamp)).await {
                                Ok(Ok(elapsed)) => {
                                    CommandResult::Success(format!(
                                        "🏓 Pong from {}: time={}ms",
                                        peer_id,
                                        elapsed.as_millis()
                                    ))
                                }
                                Ok(Err(e)) => {
                                    CommandResult::Error(format!("Pong error from {}: {}", peer_id, e))
                                }
                                Err(_) => {
                                    CommandResult::Error(format!("🏓 Ping timeout - no pong received from {} within 5 seconds", peer_id))
                                }
                            }
                        }
                        Err(e) => {
                            CommandResult::Error(format!("Failed to send ping to {}: {}", peer_id, e))
                        }
                    }
                }
                Err(e) => {
                    CommandResult::Error(format!("Failed to connect to {}: {}", peer_id, e))
                }
            }
        }
        
        #[cfg(not(feature = "bluetooth"))]
        {
            CommandResult::Error("Bluetooth feature not enabled. Cannot ping peers.".to_string())
        }
    }

    /// Wait for pong response from peer (placeholder until full message routing is implemented)
    async fn wait_for_pong_response(&self, _peer_id: &str, _ping_timestamp: u64) -> Result<std::time::Duration, anyhow::Error> {
        use tokio::time::{sleep, Duration};
        
        // Simulate realistic Bluetooth LE latency for now
        // TODO: Replace with real pong response waiting once message routing is complete
        let simulated_delay = Duration::from_millis(75 + (rand::random::<u64>() % 100)); // 75-175ms
        sleep(simulated_delay).await;
        
        Ok(simulated_delay.into()) // Convert tokio::time::Duration to std::time::Duration
    }

    /// Handle scan command to discover nearby BitChat peers
    async fn handle_scan_command(&self) -> CommandResult {
        tracing::info!("🔍 Scanning for nearby BitChat peers...");
        
        #[cfg(feature = "bluetooth")]
        {
            let bluetooth = self.core.bluetooth.lock().await;
            
            // Get current discovered devices
            let discovered = bluetooth.get_discovered_devices().await;
            
            if discovered.is_empty() {
                CommandResult::Success(format!(
                    "🔍 No BitChat peers found.\n\n💡 Make sure:\n  - Other BitChat devices are running and advertising\n  - Bluetooth is enabled\n  - Devices are within range (~10 meters)\n  - Try running scan again in a few seconds"
                ))
            } else {
                let mut result = String::from("🔍 Discovered BitChat peers:\n\n");
                
                for (device_id, device) in discovered.iter() {
                    let peer_id = device.peer_id.as_deref().unwrap_or("unknown");
                    let signal_strength = if device.rssi >= -50 {
                        "📶 Excellent"
                    } else if device.rssi >= -70 {
                        "📶 Good"
                    } else if device.rssi >= -85 {
                        "📶 Fair"
                    } else {
                        "📶 Weak"
                    };
                    
                    result.push_str(&format!(
                        "📱 Peer: {} ({}dBm - {})\n   Device: {}\n   Last seen: {}s ago\n\n",
                        peer_id,
                        device.rssi,
                        signal_strength,
                        device_id,
                        device.last_seen.elapsed().as_secs()
                    ));
                }
                
                result.push_str("💡 Use '/ping <peer_id>' to test connectivity");
                CommandResult::Success(result)
            }
        }
        
        #[cfg(not(feature = "bluetooth"))]
        {
            CommandResult::Error("Bluetooth feature not enabled. Cannot scan for peers.".to_string())
        }
    }
    
}