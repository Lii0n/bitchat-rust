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
    /// Show protocol information
    Protocol,
}

// Bluetooth event handler with protocol awareness
pub struct BitchatBluetoothDelegate {
    pub core: Option<std::sync::Arc<bitchat_core::BitchatCore>>,
}

impl BitchatBluetoothDelegate {
    pub fn new() -> Self {
        Self { core: None }
    }

    pub fn set_core(&mut self, core: std::sync::Arc<bitchat_core::BitchatCore>) {
        self.core = Some(core);
    }
}

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
                
                // Send ANNOUNCE packet to newly connected peer
                if let Some(core) = &self.core {
                    let core_clone = core.clone();
                    tokio::spawn(async move {
                        if let Err(e) = core_clone.announce_presence().await {
                            tracing::error!("Failed to announce to new peer: {}", e);
                        }
                    });
                }
            }
            BluetoothEvent::PeerDisconnected { peer_id } => {
                println!("❌ Disconnected from peer: {}", &peer_id[..8]);
            }
            BluetoothEvent::MessageReceived { peer_id, data } => {
                if let Some(core) = &self.core {
                    let core_clone = core.clone();
                    tokio::spawn(async move {
                        if let Err(e) = core_clone.process_packet(&data).await {
                            tracing::error!("Failed to process packet from {}: {}", 
                                          &peer_id[..8], e);
                        }
                    });
                }
            }
            BluetoothEvent::ScanningStateChanged { scanning } => {
                if scanning {
                    println!("🔍 Started scanning for peers");
                } else {
                    println!("⏹️ Stopped scanning");
                }
            }
            BluetoothEvent::AdvertisingStateChanged { advertising } => {
                if advertising {
                    println!("📡 Started advertising");
                } else {
                    println!("⏹️ Stopped advertising");
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
    let filter = if cli.debug {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };

    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(filter)
        .init();

    // Create config
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
        Some(Commands::Protocol) => show_protocol_info(config).await,
        None => run_interactive_mode(config).await,
    }
}

async fn run_interactive_mode(config: Config) -> Result<()> {
    println!("🔗 BitChat CLI - Secure Mesh Messaging for Windows");
    println!("Device: {}", config.device_name);
    println!("Data: {}", config.data_dir.display());
    println!("Type /help for commands, /quit to exit\n");

    let core = init(config).await?;
    let core = std::sync::Arc::new(core);
    
    // Get the event receiver before starting
    if let Some(mut event_receiver) = core.take_bluetooth_events().await {
        // Create and configure the delegate
        let mut delegate = BitchatBluetoothDelegate::new();
        delegate.set_core(core.clone());
        
        println!("🆔 My Peer ID: {}", core.get_my_peer_id());
        println!("🔗 Short ID: {}", core.get_my_short_peer_id());
        println!("🚀 Starting services...");
        
        // Start BitChat services
        if let Err(e) = core.start().await {
            println!("⚠️  Could not start all services: {}", e);
        } else {
            println!("✅ Services started successfully");
        }

        let stdin = tokio::io::stdin();
        let mut lines = BufReader::new(stdin).lines();

        println!();

        // Show initial prompt
        print!("> ");
        io::stdout().flush()?;

        loop {
            tokio::select! {
                // Handle Bluetooth events
                event = event_receiver.recv() => {
                    if let Some(event) = event {
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
                            // Send protocol message to all connected peers
                            match core.send_protocol_message(line, None).await {
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

        // Send leave announcement
        if let Err(e) = core.announce_leave().await {
            println!("Warning: Could not send leave announcement: {}", e);
        }
    } else {
        println!("⚠️  Could not get Bluetooth event receiver");
        return Ok(());
    }

    println!("👋 Goodbye!");
    Ok(())
}

async fn handle_command(core: &std::sync::Arc<bitchat_core::BitchatCore>, command: &str) -> Result<bool> {
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
            println!("  /protocol, /p       - Show protocol information");
            println!("  /announce           - Send ANNOUNCE packet");
            println!("  /send <peer> <msg>  - Send direct message to peer");
            println!("  /broadcast <msg>    - Broadcast message to all peers");
            println!("  /clear              - Clear chat history");
            println!("  /status             - Show connection status");
            println!();
            println!("Protocol Info:");
            println!("  - Messages use binary protocol");
            println!("  - Max 7 hops for relay");
            println!("  - Automatic peer discovery");
            println!("  - End-to-end encryption");
        }
        "/quit" | "/q" => {
            println!("Shutting down...");
            return Ok(true);
        }
        "/peers" | "/who" => {
            let peers = core.get_connected_peers().await;
            if peers.is_empty() {
                println!("No connected peers");
            } else {
                println!("Connected peers ({}):", peers.len());
                for peer_id in peers {
                    if let Some(peer_info) = core.get_peer_info(&peer_id).await {
                        println!("  {} - {} (RSSI: {}dBm)", 
                               peer_info.short_id(),
                               peer_info.name.as_deref().unwrap_or("Unknown"),
                               peer_info.rssi.unwrap_or(0)
                        );
                    } else {
                        println!("  {}", &peer_id[..8]);
                    }
                }
            }
        }
        "/protocol" | "/p" => {
            println!("BitChat Protocol Information:");
            println!("  My Peer ID: {}", core.get_my_peer_id());
            println!("  Short ID: {}", core.get_my_short_peer_id());
            println!("  Protocol Version: Binary v1.0");
            println!("  Max TTL: 7 hops");
            println!("  Encryption: XChaCha20-Poly1305");
            println!("  Key Exchange: X25519");
        }
        "/announce" => {
            match core.announce_presence().await {
                Ok(_) => println!("✅ Sent ANNOUNCE packet"),
                Err(e) => println!("❌ Failed to announce: {}", e),
            }
        }
        "/send" => {
            if parts.len() < 3 {
                println!("Usage: /send <peer_short_id> <message>");
                return Ok(false);
            }
            let _peer_short_id = parts[1];
            let message = parts[2..].join(" ");
            
            // For now, just broadcast since we don't have peer ID mapping
            match core.send_protocol_message(&message, None).await {
                Ok(_) => println!("📤 Sent to network: {}", message),
                Err(e) => println!("❌ Failed to send: {}", e),
            }
        }
        "/broadcast" => {
            if parts.len() < 2 {
                println!("Usage: /broadcast <message>");
                return Ok(false);
            }
            let message = parts[1..].join(" ");
            match core.send_protocol_message(&message, None).await {
                Ok(_) => println!("📤 Broadcast: {}", message),
                Err(e) => println!("❌ Failed to broadcast: {}", e),
            }
        }
        "/clear" => {
            // Clear terminal (simplified)
            print!("\x1B[2J\x1B[1;1H");
            println!("Chat history cleared");
        }
        "/status" => {
            let peers = core.get_connected_peers().await;
            println!("BitChat Status:");
            println!("  Device: {}", core.get_my_short_peer_id());
            println!("  Connected Peers: {}", peers.len());
            println!("  Protocol: Active");
            
            // Note: We can't easily check scanning/advertising state with current architecture
            // You might want to add methods to check these states
        }
        _ => {
            println!("Unknown command: {}. Type /help for available commands.", parts[0]);
        }
    }

    Ok(false)
}

async fn send_message(config: Config, message: String, _channel: Option<String>) -> Result<()> {
    println!("Sending message: {}", message);
    
    let core = init(config).await?;
    core.start().await?;
    
    // Wait a moment for connections
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
    
    // Send the message
    match core.send_protocol_message(&message, None).await {
        Ok(_) => println!("✅ Message sent"),
        Err(e) => println!("❌ Failed to send message: {}", e),
    }
    
    Ok(())
}

async fn list_peers(config: Config) -> Result<()> {
    let core = init(config).await?;
    core.start().await?;
    
    // Wait for discovery
    tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
    
    let peers = core.get_connected_peers().await;
    if peers.is_empty() {
        println!("No peers found");
    } else {
        println!("Found {} peer(s):", peers.len());
        for peer_id in peers {
            if let Some(peer_info) = core.get_peer_info(&peer_id).await {
                println!("  {} - {}", 
                       peer_info.short_id(),
                       peer_info.name.as_deref().unwrap_or("Unknown")
                );
            } else {
                println!("  {}", &peer_id[..8]);
            }
        }
    }
    
    Ok(())
}

async fn clear_data(config: Config) -> Result<()> {
    println!("Clearing all BitChat data...");
    
    if config.data_dir.exists() {
        std::fs::remove_dir_all(&config.data_dir)?;
        println!("✅ Data cleared from: {}", config.data_dir.display());
    } else {
        println!("No data directory found");
    }
    
    Ok(())
}

async fn show_protocol_info(config: Config) -> Result<()> {
    let core = init(config).await?;
    
    println!("BitChat Protocol Information:");
    println!("  Device Name: {}", config.device_name);
    println!("  Peer ID: {}", core.get_my_peer_id());
    println!("  Short ID: {}", core.get_my_short_peer_id());
    println!("  Data Directory: {}", config.data_dir.display());
    println!("  Protocol: Binary BitChat v1.0");
    println!("  Encryption: XChaCha20-Poly1305");
    println!("  Key Exchange: X25519");
    println!("  Transport: Bluetooth Low Energy");
    println!("  Max Hops: 7");
    
    Ok(())
}