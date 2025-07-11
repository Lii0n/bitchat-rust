use anyhow::Result;
use bitchat_core::{init, Config, BluetoothEvent, BluetoothConnectionDelegate};
use clap::{Parser, Subcommand};
use std::io::{self, Write};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[derive(Parser)]
#[command(name = "bitchat")]
#[command(about = "A secure, decentralized, peer-to-peer messaging app for Windows")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Set device name
    #[arg(short, long)]
    name: Option<String>,

    /// Set data directory
    #[arg(long)]
    data_dir: Option<String>,

    /// Enable debug logging
    #[arg(short, long)]
    debug: bool,
}

#[derive(Subcommand)]
enum Commands {
    /// Start interactive chat mode
    Chat,
    /// Send a single message
    Send {
        /// The message to send
        message: String,
        /// Channel to send to (optional)
        #[arg(short, long)]
        channel: Option<String>,
    },
    /// List connected peers
    Peers,
    /// Clear all data
    Clear,
}

// Bluetooth event handler
pub struct BitchatBluetoothDelegate;

impl BluetoothConnectionDelegate for BitchatBluetoothDelegate {
    fn on_bluetooth_event(&self, event: BluetoothEvent) {
        match event {
            BluetoothEvent::PeerDiscovered { peer_id, name, rssi } => {
                println!("🔍 Discovered peer: {} ({}) RSSI: {}dBm", 
                    name.as_deref().unwrap_or("Unknown"), 
                    &peer_id[..8], 
                    rssi
                );
            }
            BluetoothEvent::PeerConnected { peer_id } => {
                println!("🤝 Connected to peer: {}", &peer_id[..8]);
            }
            BluetoothEvent::PeerDisconnected { peer_id } => {
                println!("👋 Peer disconnected: {}", &peer_id[..8]);
            }
            BluetoothEvent::MessageReceived { peer_id, data } => {
                // Fixed: Clone data before trying to use it in both places
                if let Ok(message) = String::from_utf8(data.clone()) {
                    println!("📨 Message from {}: {}", &peer_id[..8], message);
                } else {
                    println!("📨 Binary message from {} ({} bytes)", &peer_id[..8], data.len());
                }
            }
            BluetoothEvent::PeerError { peer_id, error } => {
                println!("❌ Error with peer {}: {}", &peer_id[..8], error);
            }
            BluetoothEvent::ScanningStateChanged { scanning } => {
                println!("📡 Scanning: {}", if scanning { "ON" } else { "OFF" });
            }
            BluetoothEvent::AdvertisingStateChanged { advertising } => {
                println!("📢 Advertising: {}", if advertising { "ON" } else { "OFF" });
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.debug {
        EnvFilter::new("bitchat=debug,bitchat_core=debug")
    } else {
        EnvFilter::new("bitchat=info,bitchat_core=info")
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    // Create configuration
    let mut config = Config::default();
    if let Some(name) = cli.name {
        config.device_name = name;
    }
    if let Some(data_dir) = cli.data_dir {
        config.data_dir = data_dir.into();
    }

    info!("Starting BitChat CLI with device name: {}", config.device_name);

    match cli.command {
        Some(Commands::Chat) => run_interactive_mode(config).await,
        Some(Commands::Send { message, channel }) => send_message(config, message, channel).await,
        Some(Commands::Peers) => list_peers(config).await,
        Some(Commands::Clear) => clear_data(config).await,
        None => run_interactive_mode(config).await,
    }
}

async fn run_interactive_mode(config: Config) -> Result<()> {
    println!("🔗 BitChat CLI - Secure Mesh Messaging for Windows");
    println!("Device: {}", config.device_name);
    println!("Data: {}", config.data_dir.display());
    println!("Type /help for commands, /quit to exit\n");

    let core = init(config).await?;
    
    // Get the event receiver before starting
    if let Some(mut event_receiver) = core.take_bluetooth_events().await {
        // Start BitChat services
        let mut core = core; // Make it mutable
        core.start().await?;

        let stdin = tokio::io::stdin();
        let mut lines = BufReader::new(stdin).lines();

        // Show initial prompt
        print!("> ");
        io::stdout().flush()?;

        loop {
            tokio::select! {
                // Handle Bluetooth events
                event = event_receiver.recv() => {
                    if let Some(event) = event {
                        let delegate = BitchatBluetoothDelegate;
                        delegate.on_bluetooth_event(event);
                        
                        // Re-show prompt after event
                        print!("> ");
                        io::stdout().flush()?;
                    }
                }
                
                // Handle user input
                line = lines.next_line() => {
                    if let Ok(Some(line)) = line {
                        let line = line.trim();
                        
                        if line.is_empty() {
                            print!("> ");
                            io::stdout().flush()?;
                            continue;
                        }

                        if line.starts_with('/') {
                            match handle_command(&core, line).await {
                                Ok(should_quit) => {
                                    if should_quit {
                                        break;
                                    }
                                }
                                Err(e) => println!("Command error: {}", e),
                            }
                        } else {
                            // Send public message to all connected peers
                            match core.broadcast_message(line).await {
                                Ok(_) => println!("📤 Broadcast: {}", line),
                                Err(e) => {
                                    println!("📤 Local: {} ({})", line, e);
                                }
                            }
                        }
                        
                        print!("> ");
                        io::stdout().flush()?;
                    }
                }
            }
        }

        // Stop services
        let mut core = core;
        core.stop().await?;
    } else {
        println!("⚠️  Could not get Bluetooth event receiver");
        return Ok(());
    }

    println!("👋 Goodbye!");
    Ok(())
}

async fn handle_command(core: &bitchat_core::BitchatCore, command: &str) -> Result<bool> {
    let parts: Vec<&str> = command.split_whitespace().collect();
    if parts.is_empty() {
        return Ok(false);
    }

    match parts[0] {
        "/help" | "/h" => {
            println!("Commands:");
            println!("  /help, /h           - Show this help");
            println!("  /quit, /q           - Exit BitChat");
            println!("  /peers, /who        - List connected peers");
            println!("  /scan               - Start/stop scanning");
            println!("  /send <peer> <msg>  - Send direct message to peer");
            println!("  /broadcast <msg>    - Broadcast message to all peers");
            println!("  /clear              - Clear chat history");
            println!("  /status             - Show connection status");
        }
        "/quit" | "/q" => {
            return Ok(true);
        }
        "/status" => {
            let connected_peers = core.get_connected_peers().await;
            println!("📡 Bluetooth available: {}", core.bluetooth.is_available());
            println!("📡 Currently scanning: {}", core.bluetooth.is_scanning_async().await);
            println!("📢 Currently advertising: {}", core.bluetooth.is_advertising_async().await);
            println!("👥 Connected peers: {}", connected_peers.len());
            for peer_id in connected_peers {
                if let Some(peer_info) = core.get_peer_info(&peer_id).await {
                    println!("  - {} ({}) RSSI: {}dBm", 
                        peer_info.display_name(),
                        peer_info.short_id(),
                        peer_info.rssi
                    );
                }
            }
        }
        "/peers" | "/who" => {
            let connected_peers = core.get_connected_peers().await;
            if connected_peers.is_empty() {
                println!("No connected peers");
            } else {
                println!("Connected peers:");
                for peer_id in connected_peers {
                    if let Some(peer_info) = core.get_peer_info(&peer_id).await {
                        println!("  🟢 {} ({}) RSSI: {}dBm", 
                            peer_info.display_name(),
                            peer_info.short_id(),
                            peer_info.rssi
                        );
                    }
                }
            }
        }
        "/scan" => {
            if core.bluetooth.is_scanning_async().await {
                println!("⚠️  Cannot manually control scanning in this version");
            } else {
                println!("⚠️  Cannot manually control scanning in this version");
            }
        }
        "/send" => {
            if parts.len() >= 3 {
                let peer_partial = parts[1];
                let message = parts[2..].join(" ");
                
                // Find peer by partial ID
                let connected_peers = core.get_connected_peers().await;
                if let Some(peer_id) = connected_peers.iter().find(|id| id.starts_with(peer_partial)) {
                    match core.send_message_to_peer(peer_id, &message).await {
                        Ok(_) => println!("📨 Sent to {}: {}", &peer_id[..8], message),
                        Err(e) => println!("❌ Failed to send: {}", e),
                    }
                } else {
                    println!("❌ Peer not found: {}", peer_partial);
                    println!("Available peers:");
                    for peer_id in connected_peers {
                        println!("  - {}", &peer_id[..8]);
                    }
                }
            } else {
                println!("❌ Usage: /send <peer_id> <message>");
            }
        }
        "/broadcast" => {
            if parts.len() >= 2 {
                let message = parts[1..].join(" ");
                match core.broadcast_message(&message).await {
                    Ok(_) => println!("📢 Broadcast: {}", message),
                    Err(e) => println!("❌ Broadcast failed: {}", e),
                }
            } else {
                println!("❌ Usage: /broadcast <message>");
            }
        }
        "/clear" => {
            core.storage.clear_all_data()?;
            println!("🗑️  All data cleared");
        }
        _ => {
            println!("❌ Unknown command: {}. Type /help for available commands.", parts[0]);
        }
    }

    Ok(false)
}

async fn send_message(config: Config, message: String, _channel: Option<String>) -> Result<()> {
    let _core = init(config).await?;  // Fixed: prefixed with underscore
    println!("📤 Sending message: {}", message);
    // TODO: Actually send the message
    Ok(())
}

async fn list_peers(config: Config) -> Result<()> {
    let core = init(config).await?;
    let peers = core.peer_manager.get_peers();
    
    if peers.is_empty() {
        println!("No peers found");
    } else {
        println!("Known peers:");
        for peer in peers {
            let status = if peer.connected { "🟢" } else { "🔴" };
            println!("  {} {} ({})", status, peer.name, peer.address);
        }
    }
    Ok(())
}

async fn clear_data(config: Config) -> Result<()> {
    let core = init(config).await?;
    core.storage.clear_all_data()?;
    println!("🗑️  All BitChat data cleared!");
    Ok(())
}
