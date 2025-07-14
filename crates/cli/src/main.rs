//! SecureMesh CLI Application with iOS/Android Compatibility

use anyhow::Result;
use bitchat_core::SecureMeshCore;
use clap::{Arg, Command};
use std::io::{self, Write};
use tracing::{info, error};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Parse command line arguments
    let matches = Command::new("bitchat-cli")
        .version("0.1.0")
        .about("SecureMesh CLI - Secure P2P messaging with iOS/Android compatibility")
        .arg(
            Arg::new("peer-id")
                .long("peer-id")
                .value_name("ID")
                .help("Set custom peer ID (8 hex characters)")
        )
        .get_matches();
    
    info!("Starting SecureMesh CLI");
    
    // Create and start the mesh core
    let core = SecureMeshCore::new_with_compatibility().await?;
    info!("SecureMesh core initialized with peer ID: {}", core.get_peer_id());
    
    core.start().await?;
    info!("SecureMesh services started");
    
    // Print welcome message
    println!("🔐 SecureMesh CLI");
    println!("Peer ID: {}", core.get_peer_id());
    println!("Type '/help' for commands or just type to chat");
    println!("Use Ctrl+C to exit");
    println!();
    
    // Main command loop
    loop {
        print!("> ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                let input = input.trim();
                if input.is_empty() {
                    continue;
                }
                
                if let Err(e) = process_input(&core, input).await {
                    eprintln!("Error: {}", e);
                }
            }
            Err(e) => {
                error!("Failed to read input: {}", e);
                break;
            }
        }
    }
    
    Ok(())
}

async fn process_input(core: &SecureMeshCore, input: &str) -> Result<()> {
    if input.starts_with('/') {
        process_command(core, input).await
    } else {
        // Regular message - broadcast to all peers
        core.broadcast_message(input).await?;
        println!("📤 Sent: {}", input);
        Ok(())
    }
}

async fn process_command(core: &SecureMeshCore, input: &str) -> Result<()> {
    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    let command = parts[0];
    let args = parts.get(1).unwrap_or(&"");
    
    match command {
        "/help" | "/h" => {
            println!("Available commands:");
            println!("  /help, /h          - Show this help");
            println!("  /quit, /exit, /q   - Exit the application");
            println!("  /peers, /p         - List connected peers");
            println!("  /join, /j <channel> - Join a channel");
            println!("  /leave <channel>   - Leave a channel");
            println!("  /channels          - List joined channels");
            println!("  /debug             - Show debug information");
            println!("  /clear             - Clear the screen");
            println!();
            println!("Type any message (without /) to broadcast it to all peers.");
        }
        "/quit" | "/exit" | "/q" => {
            println!("👋 Goodbye!");
            std::process::exit(0);
        }
        "/peers" | "/p" => {
            let peers = core.get_connected_peers().await;
            if peers.is_empty() {
                println!("No connected peers");
            } else {
                println!("Connected peers ({}):", peers.len());
                for peer_id in peers {
                    println!("  - {}", peer_id);
                }
            }
        }
        "/join" | "/j" => {
            if args.is_empty() {
                println!("Usage: /join <channel>");
            } else {
                match core.join_channel(args).await {
                    Ok(msg) => println!("📢 {}", msg),
                    Err(e) => println!("❌ Failed to join channel: {}", e),
                }
            }
        }
        "/leave" => {
            if args.is_empty() {
                println!("Usage: /leave <channel>");
            } else {
                match core.leave_channel(args).await {
                    Ok(msg) => println!("📤 {}", msg),
                    Err(e) => println!("❌ Failed to leave channel: {}", e),
                }
            }
        }
        "/channels" => {
            match core.list_channels().await {
                Ok(list) => println!("📋 {}", list),
                Err(e) => println!("❌ Failed to list channels: {}", e),
            }
        }
        "/debug" => {
            let debug_info = core.get_debug_info().await;
            println!("🔧 Debug Information:");
            println!("{}", debug_info);
        }
        "/clear" => {
            // Clear screen (works on most terminals)
            print!("\x1B[2J\x1B[1;1H");
            io::stdout().flush()?;
        }
        _ => {
            println!("Unknown command: {}. Type '/help' for available commands.", command);
        }
    }
    
    Ok(())
}