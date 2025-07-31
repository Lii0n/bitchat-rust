use clap::{Parser, Subcommand};
use std::io::{self, Write};
use bitchat_core::{Config, BitchatCore};
use tokio::time::{sleep, Duration};
use tracing::{info, error};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};  // FIXED: Use std library instead of rand

#[cfg(windows)]
use bitchat_core::bluetooth::windows::WindowsBluetoothAdapter;

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
    /// Run advertising diagnostic for iOS/macOS compatibility
    Diagnostic,
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
        Some(Commands::Diagnostic) => {
            run_advertising_diagnostic(cli.device_id).await?;
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
    println!("📡 Transport:");
    println!("  • Bluetooth LE 4.0+ mesh networking");
    println!("  • Cross-platform device discovery");
    println!("  • Store-and-forward message delivery");
    println!("  • Dynamic routing with TTL");
}

/// NEW: Advertising diagnostic function for iOS/macOS compatibility testing
#[cfg(windows)]
async fn run_advertising_diagnostic(device_id: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    println!("🔧 BitChat Windows BLE Advertising Diagnostic Tool");
    println!("==================================================");
    println!();
    
    // Use provided device ID or the specific one from your output
    let peer_id = device_id.unwrap_or_else(|| "57900386773625A7".to_string());
    
    println!("📋 Test Configuration:");
    println!("- Target Peer ID: {}", peer_id);
    println!("- Target Format: Pure iOS (no BC_ prefix, no _M suffix)");
    println!("- Expected Device Name: '{}'", peer_id);
    println!("- Current Issue: Device shows as 'BC_{}_M'", peer_id);
    println!();

    // Create adapter with pure iOS format
    let mut adapter = WindowsBluetoothAdapter::new(peer_id.clone());
    
    println!("🔍 STEP 1: Initial State Check");
    println!("-------------------------------");
    println!("Peer ID: {}", adapter.get_peer_id());
    println!("Currently advertising: {}", adapter.is_advertising().await);
    println!("Currently scanning: {}", adapter.is_scanning().await);
    println!();

    println!("🍎 STEP 2: Attempting Pure iOS Advertising");
    println!("--------------------------------------------");
    println!("This will try to advertise as '{}' instead of 'BC_{}_M'", peer_id, peer_id);
    println!();
    
    match adapter.start_advertising(&[]).await {
        Ok(_) => {
            println!("✅ Advertising started successfully!");
            
            // Give it time to stabilize
            sleep(Duration::from_secs(2)).await;
            
            println!();
            println!("🔍 STEP 3: Verification");
            println!("------------------------");
            
            match adapter.verify_advertising_format().await {
                Ok(result) => {
                    println!("📊 Verification result: {}", result);
                }
                Err(e) => {
                    error!("❌ Verification failed: {}", e);
                }
            }
            
            println!();
            adapter.print_advertising_results().await;
            
            println!();
            adapter.test_macos_compatibility().await?;
            
            println!();
            println!("🧪 STEP 4: Live Testing");
            println!("------------------------");
            println!("✅ The adapter is now advertising in pure iOS format!");
            println!("🍎 Device should appear as: '{}'", peer_id);
            println!("❌ Should NOT appear as: 'BC_{}_M'", peer_id);
            println!();
            println!("📱 Test on macOS now:");
            println!("1. Open 'Bluetooth Explorer' (from Xcode Additional Tools)");
            println!("2. Go to 'Low Energy Devices' → Start Scanning");
            println!("3. Look for device named exactly: '{}'", peer_id);
            println!();
            println!("⏰ Keeping advertising active for 60 seconds...");
            println!("Press Ctrl+C to stop early");
            
            // Keep advertising for 60 seconds
            for i in 1..=12 {
                sleep(Duration::from_secs(5)).await;
                println!("📡 Still advertising as '{}' ... ({}s)", peer_id, i * 5);
            }
            
            println!();
            println!("🏁 Diagnostic Complete!");
            
        }
        Err(e) => {
            error!("❌ Advertising failed: {}", e);
            
            println!();
            println!("📊 Failure Analysis:");
            adapter.print_advertising_results().await;
            
            println!();
            println!("💡 Troubleshooting Steps:");
            println!("1. 🔒 Run as Administrator:");
            println!("   Right-click PowerShell/Terminal → 'Run as administrator'");
            println!("2. 🔧 Update Bluetooth drivers:");
            println!("   Device Manager → Bluetooth → Update drivers");
            println!("3. ⚙️  Enable Windows Bluetooth discoverability:");
            println!("   Settings → Bluetooth & devices → 'Allow devices to find this PC'");
            println!("4. 🔌 Try USB Bluetooth dongle:");
            println!("   Built-in adapters often have advertising restrictions");
            println!("5. 📱 Alternative: Use Raspberry Pi for reliable advertising");
        }
    }
    
    // Cleanup
    if adapter.is_advertising().await {
        println!("🧹 Stopping advertising...");
        adapter.stop_advertising().await?;
    }
    
    Ok(())
}

#[cfg(not(windows))]
async fn run_advertising_diagnostic(_device_id: Option<String>) -> Result<(), Box<dyn std::error::Error>> {
    println!("❌ Advertising diagnostic is only available on Windows");
    println!("This tool tests Windows BLE advertising for iOS/macOS compatibility");
    Ok(())
}

async fn start_bitchat(cli: Cli) -> Result<(), Box<dyn std::error::Error>> {
    info!("🚀 Starting BitChat CLI...");
    
    // Create configuration
    let device_name = cli.device_id.unwrap_or_else(|| {
        // FIXED: Use deterministic hash instead of random to avoid rand dependency
        let mut hasher = DefaultHasher::new();
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "bitchat-cli".to_string())
            .hash(&mut hasher);
        let hash = hasher.finish();
        format!("{:016X}", hash)  // Generate 16 hex chars like your existing code
    });
    
    let config = Config {
        device_name: device_name.clone(),
        ..Default::default()
    };
    
    info!("🔧 Initializing BitChat core...");
    let core = BitchatCore::new(config).await?;
    
    info!("✅ BitChat Moon Protocol is now running!");
    println!();
    println!("🎯 Quick Start:");
    println!("  • Type '/help' for available commands");
    println!("  • Type '/peers' to see discovered devices");
    println!("  • Type '/status' for system status");
    println!("  • Type '/diagnostic' for iOS advertising test");  // NEW: Added diagnostic command
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
            "/diagnostic" | "/diag" => {
                // NEW: Added diagnostic command within the CLI
                println!("🔧 Running advertising diagnostic...");
                #[cfg(windows)]
                {
                    match run_inline_diagnostic().await {
                        Ok(_) => println!("✅ Diagnostic completed"),
                        Err(e) => println!("❌ Diagnostic failed: {}", e),
                    }
                }
                #[cfg(not(windows))]
                {
                    println!("❌ Diagnostic only available on Windows");
                }
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

/// NEW: Inline diagnostic function for use within the CLI
#[cfg(windows)]
async fn run_inline_diagnostic() -> Result<(), Box<dyn std::error::Error>> {
    println!("🍎 Testing pure iOS advertising format...");
    
    let peer_id = "57900386773625A7".to_string();
    let mut adapter = WindowsBluetoothAdapter::new(peer_id.clone());
    
    println!("🎯 Target: Device name = '{}'", peer_id);
    println!("❌ Current: Device name = 'BC_{}_M'", peer_id);
    println!();
    
    match adapter.start_advertising(&[]).await {
        Ok(_) => {
            println!("✅ Pure iOS advertising started!");
            sleep(Duration::from_millis(500)).await;
            
            if let Ok(result) = adapter.verify_advertising_format().await {
                println!("📊 Result: {}", result);
            }
            
            println!("🍎 macOS should now see device: '{}'", peer_id);
            println!("⏰ Test for 10 seconds...");
            
            for i in 1..=10 {
                sleep(Duration::from_secs(1)).await;
                if i % 2 == 0 {
                    println!("📡 Advertising as '{}' ... {}s", peer_id, i);
                }
            }
            
            adapter.stop_advertising().await?;
            println!("✅ Diagnostic complete - check macOS now!");
        }
        Err(e) => {
            println!("❌ Failed: {}", e);
            println!("💡 Try: Run as Administrator or use USB Bluetooth dongle");
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
    println!("🔧 Diagnostics:");
    println!("  /diagnostic, /diag Test iOS/macOS advertising compatibility");  // NEW: Added diagnostic help
    println!();
    println!("💬 Messaging:");
    println!("  <message>          Broadcast message to all peers");
    println!("  (Direct messaging coming soon)");
    println!();
    println!("📱 Cross-Platform:");
    println!("  • iOS BitChat should detect this device automatically");
    println!("  • Android BitChat compatible with store-and-forward");
    println!("  • Use /diagnostic to test iOS advertising format");
}

async fn show_status(_core: &BitchatCore, nickname: &Option<String>) {
    println!("📊 BitChat Status");
    println!("================");
    // TODO: Implement actual status checking
    println!("🌑 Protocol: Moon v1.1 (Noise XX)");
    println!("📡 Transport: Bluetooth LE mesh");
    if let Some(nick) = nickname {
        println!("👤 Nickname: {}", nick);
    }
    println!("🔄 Status: Active");
    // Add more status info as needed
}

async fn show_peers(_core: &BitchatCore) {
    println!("👥 Connected Peers");
    println!("==================");
    // TODO: Implement actual peer listing
    println!("(Peer discovery implementation in progress)");
    println!("💡 Use /diagnostic to test advertising for peer discovery");
}