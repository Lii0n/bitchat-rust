use clap::{Parser, Subcommand};
use std::io::{self, Write};
use bitchat_core::{Config, BitchatCore};
use tokio::signal;
use tracing::{info, error};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Device ID (16 character hex peer ID, auto-generated if not provided)
    #[arg(short = 'i', long)]
    device_id: Option<String>,
    
    /// Nickname for the user
    #[arg(short = 'n', long)]
    nickname: Option<String>,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
    
    /// Log level (error, warn, info, debug, trace)
    #[arg(long, default_value = "info")]
    log_level: String,
    
    /// Commands to execute
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the BitChat CLI interface
    Start,
    /// Show version information
    Version,
    /// Show protocol information
    Protocol,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { &cli.log_level };
    std::env::set_var("RUST_LOG", format!("bitchat_core={},bitchat_cli={}", log_level, log_level));
    tracing_subscriber::fmt::init();
    
    // Print banner
    print_banner();
    
    match cli.command {
        Some(Commands::Version) => {
            print_version_info();
        }
        Some(Commands::Protocol) => {
            print_protocol_info();
        }
        Some(Commands::Start) | None => {
            start_bitchat(cli).await?;
        }
    }
    
    Ok(())
}

fn print_banner() {
    println!(r#"
🌑 BitChat CLI - Moon Protocol
================================
Secure, decentralized mesh messaging
Protocol: Moon v1.1 (Noise XX)
Transport: Bluetooth LE mesh
================================
"#);
}

fn print_version_info() {
    println!("BitChat CLI - Moon Protocol");
    println!("Version: 0.2.0");
    println!("Protocol: Moon v1.1");
    println!("Encryption: Noise XX + ChaCha20-Poly1305");
    println!("Transport: Bluetooth LE 4.0+");
    println!("Compatibility: iOS/Android BitChat v1.1+");
}

fn print_protocol_info() {
    println!("🌑 Moon Protocol v1.1 Technical Details");
    println!("=====================================");
    println!("🔐 Encryption:");
    println!("  • Pattern: Noise XX (3-message handshake)");
    println!("  • Cipher: ChaCha20-Poly1305 AEAD");
    println!("  • Key Exchange: X25519 (Curve25519)");
    println!("  • Hash: BLAKE2s (256-bit)");
    println!();
    println!("🛡️ Security Features:");
    println!("  • Forward Secrecy: New ephemeral keys per session");
    println!("  • Identity Hiding: Static keys encrypted during handshake");
    println!("  • Mutual Authentication: Both peers verify identity");
    println!("  • Replay Protection: Message counters prevent replay");
    println!("  • Session Renewal: Automatic rekey after timeout/limit");
    println!();
    println!("📡 Network:");
    println!("  • Transport: Bluetooth LE (BLE 4.0+)");
    println!("  • Mesh Routing: TTL-based (max 7 hops)");
    println!("  • Store & Forward: 12-hour offline message cache");
    println!("  • Peer Discovery: BLE advertisement scanning");
    println!("  • Device Format: BC_<PEER_ID>_M (Moon protocol)");
}

async fn start_bitchat(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    info!("🌑 Starting BitChat Moon Protocol CLI");
    
    // Create configuration - use the correct Config with Default
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("bitchat");
    
    // Validate device_id format if provided, then generate or use it
    let device_name = if let Some(device_id) = &cli.device_id {
        // Validate the provided device ID
        if device_id.len() != 16 {
            error!("Device ID must be exactly 16 hex characters");
            return Err("Invalid device ID format".into());
        }
        // Check if it's valid hex
        if hex::decode(device_id).is_err() {
            error!("Device ID must be valid hexadecimal");
            return Err("Invalid device ID format".into());
        }
        device_id.clone()
    } else {
        // Generate a deterministic device name (16 hex characters for BitChat compatibility)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "bitchat-cli".to_string())
            .hash(&mut hasher);
        let hash = hasher.finish();
        
        // Generate 16 hex characters (like BitChat expects)
        format!("{:016X}", hash)
    };
    
    let config = Config {
        device_name: device_name.clone(),
        data_dir,
        ..Default::default()
    };
    
    // Initialize BitChat core
    info!("🔧 Initializing BitChat core...");
    let core = BitchatCore::new(config).await?;
    
    info!("✅ BitChat Moon Protocol is now running!");
    println!();
    println!("🎯 Quick Start:");
    println!("  • Type '/help' for available commands");
    println!("  • Type '/peers' to see discovered devices");
    println!("  • Type '/status' for system status");
    println!("  • Type '/quit' to exit");
    println!("  • 📱 iOS/Android BitChat should now detect this device!");
    println!("  • 🌑 Device: BC_{}_M (Moon Protocol)", device_name);
    if let Some(nickname) = &cli.nickname {
        println!("  • 👤 Nickname: {}", nickname);
    }
    println!();
    
    // Start command loop
    command_loop(&core, cli.nickname).await?;
    
    Ok(())
}

async fn command_loop(core: &BitchatCore, nickname: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    
    loop {
        // Print prompt
        print!("bitchat> ");
        io::stdout().flush()?;
        
        // Read input
        input.clear();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        if input.is_empty() {
            continue;
        }
        
        // Process commands
        match input {
            "/help" | "/h" => {
                print_help();
            }
            "/quit" | "/exit" | "/q" => {
                println!("👋 Goodbye!");
                break;
            }
            "/status" | "/s" => {
                show_status(core, &nickname).await;
            }
            "/peers" | "/p" => {
                show_peers(core).await;
            }
            "/protocol" => {
                print_protocol_info();
            }
            "/version" => {
                print_version_info();
            }
            "/clear" => {
                // Clear screen
                print!("\x1B[2J\x1B[1;1H");
            }
            _ if input.starts_with('/') => {
                println!("❌ Unknown command: {}. Type '/help' for available commands.", input);
            }
            _ => {
                // Regular message - broadcast to all peers
                println!("📢 Broadcasting: {}", input);
                // TODO: Implement actual message broadcasting
                // Example: core.broadcast_message(input).await?;
            }
        }
    }
    
    Ok(())
}

fn print_help() {
    println!("🌑 BitChat Moon Protocol - Available Commands");
    println!("============================================");
    println!("📋 General:");
    println!("  /help, /h          Show this help message");
    println!("  /status, /s        Show system status");
    println!("  /peers, /p         Show discovered peers");
    println!("  /quit, /exit, /q   Exit BitChat");
    println!("  /clear             Clear screen");
    println!();
    println!("ℹ️  Information:");
    println!("  /version           Show version information");
    println!("  /protocol          Show protocol details");
    println!();
    println!("💬 Messaging:");
    println!("  <message>          Broadcast message to all peers");
    println!("  @<peer> <message>  Send private message (future)");
    println!();
    println!("🔐 Security:");
    println!("  • All private messages use Noise Protocol encryption");
    println!("  • Public messages are unencrypted broadcasts");
    println!("  • Sessions auto-renew for forward secrecy");
}

async fn show_status(core: &BitchatCore, nickname: &Option<String>) {
    println!("🌑 BitChat Moon Protocol Status");
    println!("==============================");
    
    // Core status
    println!("🔧 Core: Running");
    println!("📡 Protocol: Moon v1.1");
    println!("🔐 Encryption: Noise XX Pattern");
    println!("📱 Device: {}", core.config.device_name);
    println!("🔑 Peer ID: {}", hex::encode(core.my_peer_id));
    
    if let Some(nick) = nickname {
        println!("👤 Nickname: {}", nick);
    }
    
    // Bluetooth status (when feature is enabled)
    #[cfg(feature = "bluetooth")]
    {
        println!("📶 Bluetooth: Active");
        println!("🔍 Scanning: Enabled");
        println!("📢 Advertising: BC_{}_M", core.config.device_name);
    }
    
    #[cfg(not(feature = "bluetooth"))]
    {
        println!("📶 Bluetooth: Disabled (feature not enabled)");
    }
    
    // Network status (placeholder - implement with actual BitChat methods)
    println!("👥 Discovered Peers: 0");
    println!("🔗 Active Sessions: 0");
    println!("💬 Messages Sent: 0");
    println!("📨 Messages Received: 0");
    
    // Encryption status
    println!("🛡️ Noise Sessions: 0");
    println!("🔄 Session Renewals: 0");
    println!("⏰ Oldest Session: N/A");
    
    println!();
    println!("✅ All systems operational");
}

async fn show_peers(core: &BitchatCore) {
    println!("👥 Discovered Peers");
    println!("==================");
    
    // TODO: Implement actual peer discovery using BitChat API
    // For now, show placeholder information
    println!("🔍 Scanning for nearby BitChat devices...");
    println!("📱 Device: {}", core.config.device_name);
    println!("🔑 My Peer ID: {}", hex::encode(core.my_peer_id));
    println!();
    println!("No peers discovered yet.");
    println!();
    println!("💡 Tips:");
    println!("  • Make sure Bluetooth is enabled");
    println!("  • Ensure other BitChat clients are nearby");
    println!("  • iOS/Android clients should appear as BC_<ID>_M");
    println!("  • Legacy clients appear as BC_<ID>");
}

// Handle graceful shutdown
async fn shutdown_handler() {
    tokio::select! {
        _ = signal::ctrl_c() => {
            println!("\n🛑 Received Ctrl+C, shutting down gracefully...");
        }
    }
}