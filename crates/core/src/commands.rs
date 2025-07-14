use crate::{BitchatCore, BinaryProtocolManager, MessageType};
use anyhow::Result;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub enum CommandResult {
    Success { message: String },
    Error { message: String },
}

#[derive(Clone)]
pub struct CommandProcessor {
    core: Arc<BitchatCore>,
}

impl CommandProcessor {
    pub fn new(core: Arc<BitchatCore>) -> Self {
        Self { core }
    }

    pub async fn process_command(&self, input: &str) -> Result<CommandResult> {
        let input = input.trim();

        if input.starts_with('/') {
            self.process_slash_command(input).await
        } else {
            // Regular message
            self.send_public_message(input).await?;
            Ok(CommandResult::Success {
                message: format!("Sent: {}", input),
            })
        }
    }

    async fn process_slash_command(&self, input: &str) -> Result<CommandResult> {
        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let command = parts[0];
        let args = if parts.len() > 1 { parts[1] } else { "" };

        match command {
            "/nick" | "/nickname" => {
                if args.is_empty() {
                    return Ok(CommandResult::Error {
                        message: "Usage: /nick <nickname>".to_string(),
                    });
                }
                self.set_nickname(args).await
            }
            "/send" => {
                if args.is_empty() {
                    return Ok(CommandResult::Error {
                        message: "Usage: /send <message>".to_string(),
                    });
                }
                self.send_public_message(args).await?;
                Ok(CommandResult::Success {
                    message: format!("Sent: {}", args),
                })
            }
            "/msg" | "/pm" => {
                let msg_parts: Vec<&str> = args.splitn(2, ' ').collect();
                if msg_parts.len() < 2 {
                    return Ok(CommandResult::Error {
                        message: "Usage: /msg <peer_id> <message>".to_string(),
                    });
                }
                self.send_private_message(msg_parts[0], msg_parts[1]).await
            }
            "/join" | "/j" => {
                if args.is_empty() {
                    return Ok(CommandResult::Error {
                        message: "Usage: /join <channel>".to_string(),
                    });
                }
                self.join_channel(args).await
            }
            "/leave" | "/part" => {
                if args.is_empty() {
                    return Ok(CommandResult::Error {
                        message: "Usage: /leave <channel>".to_string(),
                    });
                }
                self.leave_channel(args).await
            }
            "/peers" | "/who" => {
                self.list_peers().await
            }
            "/help" => {
                Ok(CommandResult::Success {
                    message: self.get_help_text(),
                })
            }
            _ => Ok(CommandResult::Error {
                message: format!("Unknown command: {}. Type /help for available commands.", command),
            }),
        }
    }

    async fn send_public_message(&self, content: &str) -> Result<()> {
        #[cfg(feature = "bluetooth")]
        {
            self.core.send_message(content).await?;
        }
        Ok(())
    }

    async fn send_private_message(&self, recipient: &str, content: &str) -> Result<CommandResult> {
        // Parse recipient peer ID
        let recipient_bytes = hex::decode(recipient).map_err(|_| {
            anyhow::anyhow!("Invalid recipient peer ID format")
        })?;
        
        if recipient_bytes.len() != 8 {
            return Ok(CommandResult::Error {
                message: "Recipient peer ID must be 8 bytes (16 hex characters)".to_string(),
            });
        }

        let mut recipient_id = [0u8; 8];
        recipient_id.copy_from_slice(&recipient_bytes);

        let packet = BinaryProtocolManager::create_message_packet(
            self.core.get_peer_id(),
            Some(recipient_id),
            content,
        )?;

        #[cfg(feature = "bluetooth")]
        {
            let data = BinaryProtocolManager::encode(&packet)?;
            let bluetooth = self.core.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
        }

        Ok(CommandResult::Success {
            message: format!("Private message sent to {}", recipient),
        })
    }

    async fn join_channel(&self, channel: &str) -> Result<CommandResult> {
        let channel_name = if channel.starts_with('#') {
            channel.to_string()
        } else {
            format!("#{}", channel)
        };

        // Add to local channel manager
        {
            let mut channel_manager = self.core.channel_manager.lock().await;
            channel_manager.join_channel(&channel_name, hex::encode(self.core.get_peer_id()))?;
        }

        // Broadcast channel join
        let packet = crate::protocol::BitchatPacket::new_broadcast(
            MessageType::ChannelJoin,
            self.core.get_peer_id(),
            channel_name.as_bytes().to_vec(),
        );

        #[cfg(feature = "bluetooth")]
        {
            let data = BinaryProtocolManager::encode(&packet)?;
            let bluetooth = self.core.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
        }

        Ok(CommandResult::Success {
            message: format!("Joined channel {}", channel_name),
        })
    }

    async fn leave_channel(&self, channel: &str) -> Result<CommandResult> {
        let channel_name = if channel.starts_with('#') {
            channel.to_string()
        } else {
            format!("#{}", channel)
        };

        // Remove from local channel manager
        {
            let mut channel_manager = self.core.channel_manager.lock().await;
            channel_manager.leave_channel(&channel_name, &hex::encode(self.core.get_peer_id()))?;
        }

        // Broadcast channel leave
        let packet = crate::protocol::BitchatPacket::new_broadcast(
            MessageType::ChannelLeave,
            self.core.get_peer_id(),
            channel_name.as_bytes().to_vec(),
        );

        #[cfg(feature = "bluetooth")]
        {
            let data = BinaryProtocolManager::encode(&packet)?;
            let bluetooth = self.core.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
        }

        Ok(CommandResult::Success {
            message: format!("Left channel {}", channel_name),
        })
    }

    async fn set_nickname(&self, nickname: &str) -> Result<CommandResult> {
        // Store nickname locally
        self.core.storage.store_peer_info(&hex::encode(self.core.get_peer_id()), nickname)?;

        // Broadcast announce
        let packet = BinaryProtocolManager::create_announce_packet(
            self.core.get_peer_id(),
            nickname,
        )?;

        #[cfg(feature = "bluetooth")]
        {
            let data = BinaryProtocolManager::encode(&packet)?;
            let bluetooth = self.core.bluetooth.lock().await;
            bluetooth.broadcast_message(&data).await?;
        }

        Ok(CommandResult::Success {
            message: format!("Nickname set to {}", nickname),
        })
    }

    async fn list_peers(&self) -> Result<CommandResult> {
        #[cfg(feature = "bluetooth")]
        {
            let bluetooth = self.core.bluetooth.lock().await;
            let peers = bluetooth.get_connected_peers().await;

            if peers.is_empty() {
                Ok(CommandResult::Success {
                    message: "No connected peers".to_string(),
                })
            } else {
                let mut message = format!("Connected peers ({}):\n", peers.len());
                for peer in peers {
                    message.push_str(&format!("  {} (RSSI: {}dBm)\n", peer.peer_id, peer.rssi));
                }
                Ok(CommandResult::Success { message })
            }
        }

        #[cfg(not(feature = "bluetooth"))]
        {
            Ok(CommandResult::Error {
                message: "Bluetooth not available".to_string(),
            })
        }
    }

    fn get_help_text(&self) -> String {
        r#"BitChat Commands:
  /nick <nickname>      - Set your nickname
  /send <message>       - Send a public message
  /msg <peer_id> <msg>  - Send a private message
  /join <channel>       - Join a channel
  /leave <channel>      - Leave a channel
  /peers                - List connected peers
  /help                 - Show this help

You can also type messages directly without /send."#.to_string()
    }
}

// Make CommandProcessor implement the delegate trait
#[cfg(feature = "bluetooth")]
impl crate::BitchatBluetoothDelegate for CommandProcessor {
    fn on_device_discovered(&self, device_id: &str, device_name: Option<&str>, rssi: i8) {
        println!("📡 Discovered: {} ({:?}) RSSI: {}dBm", device_id, device_name, rssi);
    }

    fn on_device_connected(&self, device_id: &str, peer_id: &str) {
        println!("🔗 Connected: {} (peer: {})", device_id, peer_id);
    }

    fn on_device_disconnected(&self, device_id: &str, peer_id: &str) {
        println!("❌ Disconnected: {} (peer: {})", device_id, peer_id);
    }

    fn on_message_received(&self, from_peer: &str, data: &[u8]) {
        if let Ok(packet) = BinaryProtocolManager::decode(data) {
            match packet.message_type {
                MessageType::Message => {
                    if let Ok(content) = String::from_utf8(packet.payload) {
                        println!("💬 {}: {}", from_peer, content);
                    }
                }
                MessageType::Announce => {
                    if let Ok(nickname) = String::from_utf8(packet.payload) {
                        println!("👋 {} announced as: {}", from_peer, nickname);
                    }
                }
                MessageType::ChannelJoin => {
                    if let Ok(channel) = String::from_utf8(packet.payload) {
                        println!("📥 {} joined channel {}", from_peer, channel);
                    }
                }
                MessageType::ChannelLeave => {
                    if let Ok(channel) = String::from_utf8(packet.payload) {
                        println!("📤 {} left channel {}", from_peer, channel);
                    }
                }
                _ => {
                    println!("📦 Received {:?} from {}", packet.message_type, from_peer);
                }
            }
        }
    }

    fn on_error(&self, message: &str) {
        eprintln!("❌ Bluetooth error: {}", message);
    }
}