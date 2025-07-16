use bitchat_core::{BitchatCore, Config, BitchatBluetoothDelegate, BinaryProtocol, MessageType};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tracing::info;
use std::io::Write;

#[derive(Parser)]
#[command(name = "bitchat-cli")]
#[command(about = "BitChat command line interface")]
struct Cli {  // Changed from Args to Cli
    #[command(subcommand)]
    command: Option<Commands>,

    /// Data directory for BitChat
    #[arg(short = 'd', long, help = "Data directory path")]
    data_dir: Option<PathBuf>,

    /// Device name (peer ID)
    #[arg(short = 'n', long, help = "Device name/peer ID")]
    device_name: Option<String>,

    /// Enable verbose logging
    #[arg(short = 'v', long)]
    verbose: bool,
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
        if let Ok(packet) = BinaryProtocol::decode(data) {
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
    
    // Handle the Option<String> for device_name
    let device_name = cli.device_name.unwrap_or_else(|| {
        // Generate a default device name if none provided
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "bitchat-cli".to_string())
            .hash(&mut hasher);
        let hash = hasher.finish();
        
        let mut peer_bytes = [0u8; 8];
        peer_bytes.copy_from_slice(&hash.to_be_bytes());
        hex::encode(peer_bytes).to_uppercase()
    });
    
    let config = Config {
        device_name: device_name.clone(),  // Now it's a String, not Option<String>
        data_dir,
        ..Default::default()
    };
    
    info!("Starting BitChat with device name: {}", device_name);
    
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
            eprintln!("Failed to start Bluetooth: {}", e);
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
        Write::flush(&mut std::io::stdout())?;
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
                    println!("💡 Try /send <message>, /peers, or /quit");
                } else {
                    // Treat as regular message
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
    
    println!("👋 Goodbye!");
    Ok(())
}

async fn send_message(core: BitchatCore, message: &str) -> anyhow::Result<()> {
    println!("📤 Sending message: {}", message);
    core.send_channel_message("#general", message).await?;
    Ok(())
}

async fn send_message_inline(core: &BitchatCore, message: &str) -> anyhow::Result<()> {
    core.send_channel_message("#general", message).await?;
    println!("✅ Message sent: {}", message);
    Ok(())
}

async fn show_peers(core: BitchatCore) -> anyhow::Result<()> {
    let peers = core.list_peers();
    if peers.is_empty() {
        println!("👥 No connected peers");
    } else {
        println!("👥 Connected peers ({}):", peers.len());
        for peer in peers {
            println!("  • {}", peer);
        }
    }
    Ok(())
}

async fn show_peers_inline(core: &BitchatCore) {
    let peers = core.list_peers();
    if peers.is_empty() {
        println!("👥 No connected peers");
    } else {
        println!("👥 Connected peers ({}):", peers.len());
        for peer in peers {
            println!("  • {}", peer);
        }
    }
}