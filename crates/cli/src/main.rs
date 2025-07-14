//! BitChat CLI Application

use anyhow::Result;
use std::io::{self, Write};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::Mutex;
use bitchat_core::{
    BitchatCore, Config, CommandProcessor, BitchatCommand, CommandResult,
};

/// Print help information
fn print_help() {
    println!("📚 BitChat Commands:");
    println!("  /join <channel> [password]  - Join a channel");
    println!("  /leave <channel>            - Leave a channel");
    println!("  /say <channel> <message>    - Send message to channel");
    println!("  /msg <peer> <message>       - Send private message");
    println!("  /broadcast <message>        - Send public broadcast");
    println!("  /peers                      - List connected peers");
    println!("  /channels                   - List joined channels");
    println!("  /nick <nickname>            - Set your nickname");
    println!("  /help                       - Show this help");
    println!("  /quit                       - Exit BitChat");
}

/// Parse user input into BitchatCommand
fn parse_command(input: &str) -> Result<BitchatCommand> {
    let parts: Vec<&str> = input.split_whitespace().collect();
    if parts.is_empty() {
        return Err(anyhow::anyhow!("Empty command"));
    }

    match parts[0] {
        "/join" | "/j" => {
            if parts.len() < 2 {
                return Err(anyhow::anyhow!("Usage: /join <channel> [password]"));
            }
            let channel = parts[1].to_string();
            let password = if parts.len() > 2 {
                Some(parts[2..].join(" "))
            } else {
                None
            };
            Ok(BitchatCommand::Join { channel, password })
        }
        "/leave" | "/l" => {
            if parts.len() < 2 {
                return Err(anyhow::anyhow!("Usage: /leave <channel>"));
            }
            let channel = parts[1].to_string();
            Ok(BitchatCommand::Leave { channel })
        }
        "/msg" | "/message" => {
            if parts.len() < 3 {
                return Err(anyhow::anyhow!("Usage: /msg <recipient> <message>"));
            }
            let recipient = Some(parts[1].to_string());
            let content = parts[2..].join(" ");
            Ok(BitchatCommand::Message { 
                content, 
                channel: None, 
                recipient 
            })
        }
        "/say" => {
            if parts.len() < 3 {
                return Err(anyhow::anyhow!("Usage: /say <channel> <message>"));
            }
            let channel = Some(parts[1].to_string());
            let content = parts[2..].join(" ");
            Ok(BitchatCommand::Message { 
                content, 
                channel, 
                recipient: None 
            })
        }
        "/broadcast" | "/bc" => {
            if parts.len() < 2 {
                return Err(anyhow::anyhow!("Usage: /broadcast <message>"));
            }
            let content = parts[1..].join(" ");
            Ok(BitchatCommand::Message { 
                content, 
                channel: None, 
                recipient: None 
            })
        }
        "/peers" | "/who" => Ok(BitchatCommand::ListPeers),
        "/channels" | "/ch" => Ok(BitchatCommand::ListChannels),
        "/nick" | "/nickname" => {
            if parts.len() < 2 {
                return Err(anyhow::anyhow!("Usage: /nick <nickname>"));
            }
            let nickname = parts[1..].join(" ");
            Ok(BitchatCommand::SetNickname { nickname })
        }
        "/quit" | "/exit" | "/q" => Ok(BitchatCommand::Quit),
        "/help" | "/h" => {
            print_help();
            Err(anyhow::anyhow!("Help displayed"))
        }
        _ => Err(anyhow::anyhow!("Unknown command: {}", parts[0]))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("🔹 BitChat CLI v1.0.0");
    println!("Type '/help' for commands or '/quit' to exit\n");

    // Create configuration
    let config = Config::default();
    println!("📡 Device Name: {}", config.device_name);
    println!("💾 Data Directory: {}\n", config.data_dir.display());

    // Initialize BitChat core
    let core = BitchatCore::new(config).await?;
    let my_peer_id = core.get_peer_id();
    
    println!("🆔 Peer ID: {}", hex::encode(my_peer_id));
    println!("🔄 Starting BitChat services...\n");

    // Create command processor
    let processor = CommandProcessor::new(
        core.bluetooth.clone(),
        Arc::new(Mutex::new(core.crypto)),
        Arc::new(core.storage),
        Arc::new(core.config),
        core.packet_router.clone(),
        core.channel_manager.clone(),
        my_peer_id,
    );

    println!("✅ BitChat ready! Available commands:");
    print_help();
    println!();

    // Start command loop
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        print!("> ");
        io::stdout().flush()?;
        
        line.clear();
        if reader.read_line(&mut line).await? == 0 {
            break; // EOF
        }

        let input = line.trim();
        if input.is_empty() {
            continue;
        }

        match parse_command(input) {
            Ok(command) => match processor.process_command(command).await {
                Ok(result) => handle_command_result(result),
                Err(e) => println!("❌ Command failed: {}", e),
            },
            Err(e) => {
                println!("❌ Invalid command: {}", e);
                println!("💡 Type '/help' for usage information");
            }
        }
    }

    Ok(())
}

fn handle_command_result(result: CommandResult) {
    match result {
        CommandResult::Success { message } => println!("✅ {}", message),
        CommandResult::Error { error } => println!("❌ {}", error),
        CommandResult::PeerList { peers } => {
            if peers.is_empty() {
                println!("📋 No connected peers");
            } else {
                println!("📋 Connected peers:");
                for peer in peers {
                    println!("  - {}", peer);
                }
            }
        }
        CommandResult::ChannelList { channels } => {
            if channels.is_empty() {
                println!("📋 No joined channels");
            } else {
                println!("📋 Joined channels:");
                for channel in channels {
                    println!("  - #{}", channel);
                }
            }
        }
        CommandResult::Quit => println!("👋 Goodbye!"),
    }
}