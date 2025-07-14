use bitchat_core::{BitchatCore, Config, BitchatBluetoothDelegate};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tracing::info;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Device name (will be used as peer ID)
    #[arg(short, long, default_value = "RustBitChat")]
    device_name: String,
    
    /// Data directory
    #[arg(short, long)]
    data_dir: Option<PathBuf>,
    
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the BitChat service
    Start,
    /// Send a test message
    Send {
        /// Message content
        message: String,
    },
    /// Show connected peers
    Peers,
}

// Simple delegate implementation for CLI
struct CliDelegate;

impl BitchatBluetoothDelegate for CliDelegate {
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
        if let Ok(packet) = bitchat_core::BinaryProtocolManager::decode(data) {
            match packet.message_type {
                bitchat_core::MessageType::Message => {
                    if let Ok(content) = String::from_utf8(packet.payload) {
                        println!("💬 {}: {}", from_peer, content);
                    }
                }
                bitchat_core::MessageType::Announce => {
                    if let Ok(nickname) = String::from_utf8(packet.payload) {
                        println!("👋 {} announced as: {}", from_peer, nickname);
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    
    // Create config
    let data_dir = cli.data_dir.unwrap_or_else(|| {
        dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("bitchat")
    });
    
    let config = Config {
        device_name: cli.device_name.clone(),
        data_dir,
        ..Default::default()
    };
    
    info!("Starting BitChat with device name: {}", cli.device_name);
    
    // Create BitChat core
    let core = BitchatCore::new(config).await?;
    
    match cli.command {
        Some(Commands::Start) => {
            start_interactive_mode(core).await?;
        }
        Some(Commands::Send { message }) => {
            send_message(core, &message).await?;
        }
        Some(Commands::Peers) => {
            show_peers(core).await?;
        }
        None => {
            start_interactive_mode(core).await?;
        }
    }
    
    Ok(())
}

async fn start_interactive_mode(core: BitchatCore) -> anyhow::Result<()> {
    println!("🚀 Starting BitChat in interactive mode");
    println!("📱 Device: {}", core.config.device_name);
    println!("🔑 Peer ID: {}", hex::encode(core.get_peer_id()));
    println!();
    
    #[cfg(feature = "bluetooth")]
    {
        println!("🔵 Starting Bluetooth...");
        let delegate = Arc::new(CliDelegate);
        
        if let Err(e) = core.start_bluetooth_with_delegate(delegate).await {
            error!("Failed to start Bluetooth: {}", e);
            println!("❌ Bluetooth not available: {}", e);
            println!("💡 Make sure Bluetooth is enabled and you have permissions");
        } else {
            println!("✅ Bluetooth started successfully");
        }
    }
    
    #[cfg(not(feature = "bluetooth"))]
    {
        println!("⚠️  Bluetooth feature not enabled");
    }
    
    println!();
    println!("Commands:");
    println!("  /send <message>  - Send a message");
    println!("  /peers          - Show connected peers");
    println!("  /quit           - Exit");
    println!();
    
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();
    
    loop {
        print!("bitchat> ");
        line.clear();
        
        match reader.read_line(&mut line).await {
            Ok(0) => break, // EOF
            Ok(_) => {
                let input = line.trim();
                
                if input.is_empty() {
                    continue;
                }
                
                if input == "/quit" || input == "/exit" {
                    break;
                } else if input == "/peers" {
                    show_peers_inline(&core).await;
                } else if let Some(message) = input.strip_prefix("/send ") {
                    if let Err(e) = send_message_inline(&core, message).await {
                        eprintln!("❌ Failed to send message: {}", e);
                    }
                } else if input.starts_with('/') {
                    println!("❓ Unknown command: {}", input);
                } else {
                    // Treat as message
                    if let Err(e) = send_message_inline(&core, input).await {
                        eprintln!("❌ Failed to send message: {}", e);
                    }
                }
            }
            Err(e) => {
                eprintln!("❌ Error reading input: {}", e);
                break;
            }
        }
    }
    
    println!("👋 Shutting down...");
    
    #[cfg(feature = "bluetooth")]
    {
        if let Err(e) = core.stop_bluetooth().await {
            error!("Error stopping Bluetooth: {}", e);
        }
    }
    
    Ok(())
}

async fn send_message(core: BitchatCore, message: &str) -> anyhow::Result<()> {
    println!("📤 Sending message: {}", message);
    
    #[cfg(feature = "bluetooth")]
    {
        core.send_message(message).await?;
        println!("✅ Message sent");
    }
    
    #[cfg(not(feature = "bluetooth"))]
    {
        println!("⚠️  Bluetooth not available - message not sent");
    }
    
    Ok(())
}

async fn send_message_inline(core: &BitchatCore, message: &str) -> anyhow::Result<()> {
    #[cfg(feature = "bluetooth")]
    {
        core.send_message(message).await?;
        println!("📤 Sent: {}", message);
    }
    
    #[cfg(not(feature = "bluetooth"))]
    {
        println!("⚠️  Bluetooth not available");
    }
    
    Ok(())
}

async fn show_peers(core: BitchatCore) -> anyhow::Result<()> {
    show_peers_inline(&core).await;
    Ok(())
}

async fn show_peers_inline(core: &BitchatCore) {
    #[cfg(feature = "bluetooth")]
    {
        let bluetooth = core.bluetooth.lock().await;
        let peers = bluetooth.get_connected_peers().await;
        
        if peers.is_empty() {
            println!("👥 No connected peers");
        } else {
            println!("👥 Connected peers ({}):", peers.len());
            for peer in peers {
                println!("  🔗 {} (RSSI: {}dBm)", peer.peer_id, peer.rssi);
            }
        }
    }
    
    #[cfg(not(feature = "bluetooth"))]
    {
        println!("⚠️  Bluetooth not available");
    }
}