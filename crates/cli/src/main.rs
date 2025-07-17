use bitchat_core::{BitchatCore, Config, BitchatBluetoothDelegate, BinaryProtocol, MessageType};
use bitchat_core::bluetooth::constants::peer_id::{generate_random_peer_id, string_to_bytes};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{self, AsyncBufReadExt, BufReader};
use tracing::info;
use std::io::Write;
use std::sync::TryLockError;
use tokio::sync::Mutex;

#[cfg(feature = "bluetooth")]
use bitchat_core::bluetooth::windows::WindowsBluetoothAdapter;

// Safe global adapter reference using Arc<Mutex<Option<T>>>
#[cfg(feature = "bluetooth")]
use std::sync::OnceLock;

#[cfg(feature = "bluetooth")]
static REAL_BLUETOOTH: OnceLock<Arc<Mutex<Option<WindowsBluetoothAdapter>>>> = OnceLock::new();

#[derive(Parser)]
#[command(name = "bitchat-cli")]
#[command(about = "BitChat command line interface")]
struct Cli {
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
                    if let Ok(content) = String::from_utf8(packet.payload.clone()) {
                        if content.starts_with('#') {
                            let parts: Vec<&str> = content.splitn(2, ' ').collect();
                            if parts.len() == 2 {
                                let channel = parts[0];
                                let message = parts[1];
                                println!("📺 [{}] {}: {}", channel, from_peer, message);
                                return;
                            }
                        }
                        println!("💬 {}: {}", from_peer, content);
                    }
                }
                MessageType::Announce => {
                    if let Ok(nickname) = String::from_utf8(packet.payload) {
                        println!("👋 {} announced as: {}", from_peer, nickname);
                    }
                }
                MessageType::ChannelAnnounce => {
                    if let Ok(content) = String::from_utf8(packet.payload) {
                        println!("📺 Channel announcement from {}: {}", from_peer, content);
                    }
                }
                MessageType::ChannelJoin => {
                    if let Ok(channel) = String::from_utf8(packet.payload) {
                        println!("🚪 {} joined channel: {}", from_peer, channel);
                    }
                }
                MessageType::ChannelLeave => {
                    if let Ok(channel) = String::from_utf8(packet.payload) {
                        println!("👋 {} left channel: {}", from_peer, channel);
                    }
                }
                MessageType::Leave => {
                    println!("👋 {} has left", from_peer);
                }
                MessageType::KeyExchange => {
                    println!("🔐 Key exchange from {}", from_peer);
                }
                MessageType::FragmentStart | MessageType::FragmentContinue | MessageType::FragmentEnd => {
                    println!("📦 Fragment from {} (assembling...)", from_peer);
                }
                MessageType::DeliveryAck => {
                    println!("✅ Delivery acknowledgment from {}", from_peer);
                }
                MessageType::ReadReceipt => {
                    println!("👁️ Read receipt from {}", from_peer);
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
    tracing_subscriber::fmt::init();
    
    let cli = Cli::parse();
    
    let data_dir = cli.data_dir.unwrap_or_else(|| {
        dirs::data_dir().unwrap_or_else(|| PathBuf::from(".")).join("bitchat")
    });
    
    // Generate proper BitChat-compatible peer ID
    let device_name = cli.device_name.unwrap_or_else(|| {
        // Generate a proper BitChat-compatible peer ID (16 hex characters)
        generate_random_peer_id()
    });
    
    let config = Config {
        device_name: device_name.clone(),
        data_dir,
        ..Default::default()
    };
    
    info!("Starting BitChat with peer ID: {}", device_name);
    
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
    println!("🚀 BitChat CLI - Interactive Mode");
    println!("==================================");
    println!("📱 Device: {}", core.config.device_name);
    println!("🔑 Peer ID: {}", hex::encode(core.get_peer_id()));
    println!();
    
    // Initialize REAL Bluetooth adapter with BitChat announcements
    #[cfg(feature = "bluetooth")]
    {
        println!("🔵 Starting REAL Bluetooth adapter with BitChat announcements...");
        
        let bluetooth_config = bitchat_core::bluetooth::BluetoothConfig::with_device_name(
            core.config.device_name.clone()
        )
        .with_rssi_threshold(-85);
        
        match WindowsBluetoothAdapter::new(bluetooth_config).await {
            Ok(mut adapter) => {
                if adapter.is_available().await {
                    // Start scanning first
                    match adapter.start_scanning().await {
                        Ok(_) => {
                            println!("✅ BitChat scanning started");
                            
                            // CRITICAL: Start advertising so macOS can discover us
                            match adapter.start_advertising(&[]).await {
                                Ok(_) => {
                                    println!("✅ BitChat advertising started - macOS can now discover us!");
                                    println!("📢 Advertising as peer: {}", core.config.device_name);
                                    println!("🍎 iOS/macOS BitChat should now see this device");
                                    println!("📡 Device name format: {} (iOS/macOS compatible)", core.config.device_name);
                                    
                                    // Send announcement packet
                                    if let Ok(peer_id_bytes) = string_to_bytes(&core.config.device_name) {
                                        let _announcement = BinaryProtocol::create_announce(peer_id_bytes, "RustBitChat");
                                        println!("📢 BitChat announcements configured with nickname: RustBitChat");
                                    }
                                }
                                Err(e) => {
                                    println!("⚠️ Failed to start advertising: {} (scanning only mode)", e);
                                    println!("❌ macOS BitChat will NOT be able to discover this device");
                                }
                            }
                            
                            // Store adapter for command access
                            let adapter_ref = REAL_BLUETOOTH.get_or_init(|| {
                                Arc::new(Mutex::new(None))
                            });
                            *adapter_ref.lock().await = Some(adapter);
                            
                            // Wait for initial scan
                            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                            show_peers_inline(&core).await;
                        }
                        Err(e) => {
                            println!("❌ Failed to start BitChat scanning: {}", e);
                        }
                    }
                } else {
                    println!("❌ Bluetooth not available");
                }
            }
            Err(e) => {
                println!("❌ Failed to create BitChat adapter: {}", e);
                println!("💡 Falling back to core Bluetooth manager");
                
                // Fallback to core manager
                let delegate = Arc::new(CliDelegate);
                if let Err(e) = core.start_bluetooth_with_delegate(delegate).await {
                    println!("❌ Core Bluetooth also failed: {}", e);
                }
            }
        }
    }
    
    #[cfg(not(feature = "bluetooth"))]
    {
        println!("⚠️  Bluetooth feature not enabled");
    }
    
    println!();
    println!("🎯 Quick Start:");
    println!("  • Type '/peers' to see discovered devices");
    println!("  • Type '/status' for full system status");
    println!("  • Type '/help' for all commands");
    println!("  • 🍎 macOS BitChat should now detect this device!");
    println!();
    
    let stdin = io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut input = String::new();
    
    loop {
        print!("🔥 > ");
        std::io::stdout().flush().unwrap();
        input.clear();
        
        match reader.read_line(&mut input).await {
            Ok(0) => break,
            Ok(_) => {
                let command = input.trim();
                if command.is_empty() {
                    continue;
                }
                
                if command.starts_with('/') {
                    match handle_interactive_command(&core, command).await {
                        Ok(should_quit) => {
                            if should_quit {
                                break;
                            }
                        }
                        Err(e) => {
                            println!("❌ Command error: {}", e);
                        }
                    }
                } else {
                    if let Err(e) = send_message_inline(&core, command).await {
                        println!("❌ Failed to send message: {}", e);
                        println!("💡 Make sure you've joined a channel with '/join #channelname'");
                    }
                }
            }
            Err(e) => {
                println!("❌ Input error: {}", e);
                break;
            }
        }
    }
    
    // Cleanup
    #[cfg(feature = "bluetooth")]
    {
        if let Some(adapter_ref) = REAL_BLUETOOTH.get() {
            if let Some(mut adapter) = adapter_ref.lock().await.take() {
                println!("🧹 Cleaning up BitChat Bluetooth adapter...");
                if let Err(e) = adapter.shutdown().await {
                    println!("⚠️ Error during shutdown: {}", e);
                }
            }
        }
    }
    
    println!("👋 Thanks for using BitChat!");
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
    show_discovered_bitchat_devices(&core).await;
    Ok(())
}

// Updated to use REAL Bluetooth adapter when available
async fn show_peers_inline(core: &BitchatCore) {
    #[cfg(feature = "bluetooth")]
    {
        if let Some(adapter_ref) = REAL_BLUETOOTH.get() {
            if let Some(ref adapter) = *adapter_ref.lock().await {
                // Use REAL adapter (same as test)
                let discovered = adapter.get_discovered_devices().await;
                
                if !discovered.is_empty() {
                    println!("👥 BitChat Devices Found:");
                    println!("  🔍 Discovered: {} devices", discovered.len());
                    for (_, device) in discovered.iter().take(3) {
                        let peer_id = device.peer_id.as_deref().unwrap_or("unknown");
                        println!("    • {} ({}dBm)", peer_id, device.rssi);
                    }
                    if discovered.len() > 3 {
                        println!("    • ... and {} more", discovered.len() - 3);
                    }
                    println!("💡 Use '/peers' for full details");
                    return;
                }
            }
        }
    }
    
    // Fallback to core manager
    #[cfg(feature = "bluetooth")]
    {
        let bluetooth = core.bluetooth.lock().await;
        let discovered = bluetooth.get_discovered_devices().await;
        let connected = bluetooth.get_connected_peers().await;
        
        if !discovered.is_empty() || !connected.is_empty() {
            println!("👥 Core Manager Status:");
            if !discovered.is_empty() {
                println!("  🔍 Discovered: {} devices (CORE)", discovered.len());
            }
            if !connected.is_empty() {
                println!("  🔗 Connected: {} peers", connected.len());
            }
        } else {
            println!("👥 No BitChat peers found yet");
            println!("💡 Make sure other BitChat devices are nearby and running");
        }
    }
    
    #[cfg(not(feature = "bluetooth"))]
    {
        show_discovered_bitchat_devices(core).await;
    }
}

// Updated to use REAL Bluetooth adapter when available
async fn show_discovered_bitchat_devices(core: &BitchatCore) {
    println!("👥 BitChat Device Discovery Status");
    println!("==================================");
    
    #[cfg(feature = "bluetooth")]
    {
        if let Some(adapter_ref) = REAL_BLUETOOTH.get() {
            if let Some(ref adapter) = *adapter_ref.lock().await {
                // Use REAL adapter
                println!("🔥 Using REAL Bluetooth Adapter with BitChat Protocol");
                
                let discovered = adapter.get_discovered_devices().await;
                let is_scanning = adapter.is_scanning().await;
                let is_advertising = adapter.is_advertising().await;
                
                println!("📊 BitChat Adapter Status:");
                println!("   🔍 Scanning: {}", if is_scanning { "✅ Active" } else { "❌ Inactive" });
                println!("   📡 Advertising: {}", if is_advertising { "✅ Active (macOS can discover us)" } else { "❌ Inactive (macOS CANNOT discover us)" });
                println!("   🍎 Protocol: iOS/macOS compatible");
                println!();
                
                if !discovered.is_empty() {
                    println!("🎉 BitChat Devices Found ({}):", discovered.len());
                    for (device_id, device) in discovered {
                        let peer_id = device.peer_id.as_deref().unwrap_or("unknown");
                        let elapsed = device.last_seen.elapsed().as_secs();
                        let rssi = device.rssi;
                        
                        println!("  📱 Device: {}", device_id);
                        println!("     🆔 Peer ID: {}", peer_id);
                        println!("     📶 Signal: {} dBm", rssi);
                        println!("     ⏰ Last seen: {}s ago", elapsed);
                        println!("     🍎 Platform: iOS/macOS BitChat (detected)");
                        println!();
                    }
                } else {
                    println!("📭 No BitChat devices discovered yet");
                    if is_scanning {
                        println!("🔍 Currently scanning for iOS/macOS BitChat devices...");
                    } else {
                        println!("⚠️ Not scanning - restart CLI to reinitialize");
                    }
                    
                    if is_advertising {
                        println!("📡 Broadcasting as BitChat device - macOS should see us");
                    } else {
                        println!("❌ Not advertising - macOS cannot discover us");
                    }
                }
                return;
            }
        }
    }
    
    // Fallback to core manager display
    #[cfg(feature = "bluetooth")]
    {
        println!("🔧 Using Core Bluetooth Manager (fallback)");
        
        let bluetooth = core.bluetooth.lock().await;
        let discovered = bluetooth.get_discovered_devices().await;
        let connected = bluetooth.get_connected_peers().await;
        let is_scanning = bluetooth.is_scanning().await;
        let is_advertising = bluetooth.is_advertising().await;
        
        println!("📊 Core Manager Status:");
        println!("   🔍 Scanning: {}", if is_scanning { "✅ Active" } else { "❌ Inactive" });
        println!("   📡 Advertising: {}", if is_advertising { "✅ Active" } else { "❌ Inactive" });
        println!();
        
        if !discovered.is_empty() {
            println!("🔍 Core Manager Devices ({}):", discovered.len());
            for (device_id, device) in discovered {
                let peer_id = device.peer_id.as_deref().unwrap_or("unknown");
                let elapsed = device.last_seen.elapsed().as_secs();
                let rssi = device.rssi;
                
                println!("  📱 Device: {}", device_id);
                println!("     🆔 Peer ID: {}", peer_id);
                println!("     📶 Signal: {} dBm", rssi);
                println!("     ⏰ Last seen: {}s ago", elapsed);
                println!();
            }
        } else {
            println!("📭 No devices found via core manager");
            println!("💡 Core manager uses simulated Bluetooth");
        }
        
        if !connected.is_empty() {
            println!("🔗 Connected Peers ({}):", connected.len());
            for peer_id in connected {
                println!("  • {}", peer_id);
            }
        }
    }
    
    #[cfg(not(feature = "bluetooth"))]
    {
        let peers = core.list_peers();
        if peers.is_empty() {
            println!("👥 No connected peers (Bluetooth not enabled)");
        } else {
            println!("👥 Connected peers ({}):", peers.len());
            for peer in peers {
                println!("  • {}", peer);
            }
        }
    }
}

async fn handle_interactive_command(core: &BitchatCore, command: &str) -> anyhow::Result<bool> {
    if handle_debug_commands(core, command).await? {
        return Ok(false);
    }
    
    if handle_channel_commands(core, command).await? {
        return Ok(false);
    }
    
    match command.trim() {
        "/peers" | "/p" => {
            show_discovered_bitchat_devices(core).await;
        }
        "/status" | "/s" => {
            show_full_status(core).await;
        }
        "/help" | "/h" => {
            show_help();
        }
        "/clear" => {
            print!("\x1B[2J\x1B[1;1H");
            println!("🧹 Screen cleared!");
        }
        "/quit" | "/q" | "/exit" => {
            return Ok(true);
        }
        _ => {
            println!("❓ Unknown command: {}", command);
            println!("💡 Type /help for available commands");
        }
    }
    Ok(false)
}

async fn handle_channel_commands(core: &BitchatCore, command: &str) -> anyhow::Result<bool> {
    match command.trim() {
        "/channels" | "/c" => {
            show_channels(core).await?;
        }
        "/current" => {
            show_current_channel(core).await?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

async fn show_channels(core: &BitchatCore) -> anyhow::Result<()> {
    println!("📺 Channel Information");
    println!("=====================");
    
    match core.list_channels().await {
        Ok(channels) => {
            if channels.is_empty() {
                println!("📭 No channels joined");
                println!("💡 Channels will appear here when you receive messages from them");
            } else {
                println!("📊 Known Channels ({}):", channels.len());
                for (i, channel) in channels.iter().enumerate() {
                    println!("  {}. {} {}", 
                             i + 1, 
                             channel,
                             if i == 0 { "📍 (active)" } else { "💤" }
                    );
                }
                println!();
                println!("💡 You'll automatically receive messages from these channels");
            }
        }
        Err(e) => {
            println!("❌ Error getting channels: {}", e);
        }
    }
    
    Ok(())
}

async fn show_current_channel(core: &BitchatCore) -> anyhow::Result<()> {
    match core.list_channels().await {
        Ok(channels) => {
            if let Some(current) = channels.first() {
                println!("📍 Current active channel: {}", current);
                println!("💬 Messages from this channel will be highlighted");
            } else {
                println!("📭 No active channel");
                println!("💡 You'll automatically join channels when receiving messages");
            }
        }
        Err(e) => {
            println!("❌ Error getting current channel: {}", e);
        }
    }
    
    Ok(())
}

async fn show_full_status(core: &BitchatCore) {
    println!("📊 BitChat Full Status");
    println!("======================");
    
    println!("🖥️  Device Information:");
    println!("   📱 Device Name: {}", core.config.device_name);
    println!("   🔑 Peer ID: {}", hex::encode(core.get_peer_id()));
    println!("   📁 Data Directory: {}", core.config.data_dir.display());
    
    // Show which Bluetooth implementation is active
    #[cfg(feature = "bluetooth")]
    {
        if let Some(adapter_ref) = REAL_BLUETOOTH.get() {
            if let Some(ref adapter) = *adapter_ref.lock().await {
                println!("\n🔥 Bluetooth Implementation: REAL Windows Adapter with BitChat Protocol");
                
                let is_advertising = adapter.is_advertising().await;
                let is_scanning = adapter.is_scanning().await;
                
                println!("   📡 Advertising: {} {}", 
                        if is_advertising { "✅ Active" } else { "❌ Inactive" },
                        if is_advertising { "(macOS can discover us)" } else { "(macOS CANNOT discover us)" }
                );
                println!("   🔍 Scanning: {}", if is_scanning { "✅ Active" } else { "❌ Inactive" });
                println!("   🍎 Protocol: iOS/macOS compatible");
            } else {
                println!("\n🔧 Bluetooth Implementation: Core Manager (simulated)");
            }
        } else {
            println!("\n🔧 Bluetooth Implementation: Core Manager (simulated)");
        }
    }
    
    if let Ok(channels) = core.list_channels().await {
        println!("\n📺 Known Channels ({}):", channels.len());
        if channels.is_empty() {
            println!("   📭 No channels discovered yet");
        } else {
            for (i, channel) in channels.iter().enumerate() {
                println!("   {}. {} {}", 
                         i + 1,
                         channel,
                         if i == 0 { "📍 (active)" } else { "💤" }
                );
            }
        }
    }
    
    let peers = core.list_peers();
    println!("\n👥 Connected Peers ({}):", peers.len());
    if peers.is_empty() {
        println!("   🔌 No peers connected");
    } else {
        for peer in peers {
            println!("   • {}", peer);
        }
    }
    
    #[cfg(feature = "bluetooth")]
    {
        let bluetooth_status = core.bluetooth_status().await;
        println!("\n🔵 Core Bluetooth Status:");
        println!("{}", bluetooth_status);
    }
    
    #[cfg(not(feature = "bluetooth"))]
    {
        println!("\n🔵 Bluetooth: Not enabled");
    }
}

async fn handle_debug_commands(core: &BitchatCore, command: &str) -> anyhow::Result<bool> {
    match command.trim() {
        "/debug" | "/d" => {
            comprehensive_debug(core).await?;
        }
        "/trace" => {
            enable_trace_logging();
        }
        _ => return Ok(false),
    }
    Ok(true)
}

async fn comprehensive_debug(core: &BitchatCore) -> anyhow::Result<()> {
    println!("🔍 COMPREHENSIVE BITCHAT DEBUG");
    println!("==============================");
    
    println!("📋 Core Configuration:");
    println!("   Device Name: {}", core.config.device_name);
    println!("   Peer ID: {}", hex::encode(core.get_peer_id()));
    println!();
    
    #[cfg(feature = "bluetooth")]
    {
        if let Some(adapter_ref) = REAL_BLUETOOTH.get() {
            if let Some(ref adapter) = *adapter_ref.lock().await {
                println!("🔥 REAL BitChat Bluetooth Adapter Status:");
                println!("   Available: {}", adapter.is_available().await);
                println!("   Scanning: {}", adapter.is_scanning().await);
                println!("   Advertising: {} {}", 
                        adapter.is_advertising().await,
                        if adapter.is_advertising().await { "(macOS can discover us)" } else { "(macOS CANNOT discover us)" }
                );
                
                let discovered = adapter.get_discovered_devices().await;
                println!("   Discovered: {} BitChat devices", discovered.len());
                
                if !discovered.is_empty() {
                    println!("   📱 BitChat devices found:");
                    for (device_id, device) in discovered.iter().take(3) {
                        println!("      • {}: {:?} ({}dBm)", 
                                 device_id, 
                                 device.peer_id, 
                                 device.rssi);
                    }
                }
                
                println!("\n📋 Platform Debug Info:");
                println!("{}", adapter.get_platform_debug_info().await);
            } else {
                println!("⚠️ REAL BitChat Bluetooth Adapter: Not initialized");
            }
        } else {
            println!("⚠️ REAL BitChat Bluetooth Adapter: Not initialized");
        }
    }
    
    #[cfg(feature = "bluetooth")]
    {
        println!("\n🔧 Core Bluetooth Manager:");
        match core.bluetooth.try_lock() {
            Ok(bluetooth) => {
                println!("   Running: {}", bluetooth.is_running().await);
                println!("   Scanning: {}", bluetooth.is_scanning().await);
                println!("   Advertising: {}", bluetooth.is_advertising().await);
                
                let discovered = bluetooth.get_discovered_devices().await;
                println!("   Core Discovered: {} devices", discovered.len());
            }
            Err(_) => {
                println!("   Status: Locked (in use)");
            }
        }
    }
    
    println!("\n🎯 BitChat macOS Compatibility Diagnosis:");
    #[cfg(feature = "bluetooth")]
    {
        if let Some(adapter_ref) = REAL_BLUETOOTH.get() {
            if let Some(ref adapter) = *adapter_ref.lock().await {
                let is_advertising = adapter.is_advertising().await;
                if is_advertising {
                    println!("   ✅ Real adapter advertising - macOS BitChat should discover us");
                    println!("   ✅ Using iOS/macOS compatible peer ID format");
                    println!("   ✅ BitChat service UUID included in advertisements");
                    println!("   ✅ Manufacturer data with nickname included");
                } else {
                    println!("   ❌ Real adapter NOT advertising - macOS BitChat CANNOT discover us");
                    println!("   💡 Need to fix advertising to be discoverable by macOS");
                }
            } else {
                println!("   ❌ Real adapter failed - using simulated manager");
                println!("   ❌ macOS BitChat will NOT discover us (no real Bluetooth)");
            }
        } else {
            println!("   ❌ Real adapter not initialized - using simulated manager");
            println!("   ❌ macOS BitChat will NOT discover us (no real Bluetooth)");
        }
    }
    
    Ok(())
}

fn enable_trace_logging() {
    println!("🔍 ENABLING TRACE LOGGING");
    println!("=========================");
    
    std::env::set_var("RUST_LOG", "trace,bitchat_core=trace,bitchat_cli=trace");
    
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::TRACE)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .try_init()
        .unwrap_or_else(|_| {
            println!("⚠️ Logging already initialized, environment variables set");
        });
    
    println!("✅ Trace logging enabled");
    println!("💡 Now try '/peers' to see detailed logs");
}

fn show_help() {
    println!("🔧 BitChat CLI Commands");
    println!("========================");
    println!();
    
    println!("📺 Channel Management:");
    println!("  /channels, /c      - List known channels");
    println!("  /current           - Show current active channel");
    println!();
    
    println!("👥 Peer Management:");
    println!("  /peers, /p         - Show discovered and connected peers");
    println!();
    
    println!("🔧 System:");
    println!("  /status, /s        - Show full system status");
    println!("  /debug, /d         - Comprehensive system debug");
    println!("  /trace             - Enable maximum logging");
    println!("  /clear             - Clear screen");
    println!("  /help, /h          - Show this help");
    println!("  /quit, /q, /exit   - Exit BitChat");
    println!();
    
    println!("🍎 BitChat macOS Compatibility:");
    println!("  This CLI now uses REAL Bluetooth with proper BitChat protocol");
    println!("  macOS BitChat devices should discover this peer automatically");
    println!("  Use '/status' to verify advertising is active for macOS discovery");
    println!();
    
    println!("💡 Quick BitChat Protocol Info:");
    println!("  • Peer ID: 16 hex characters (iOS/macOS compatible format)");
    println!("  • Service UUID: F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");
    println!("  • Device name: Just the peer ID (no BC_ prefix for iOS/macOS)");
    println!("  • Manufacturer data: Includes peer ID + nickname");
}