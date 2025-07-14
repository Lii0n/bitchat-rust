//! BitChat Desktop Application

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use bitchat_core::{
    BitchatCore, Config, CommandProcessor, BitchatCommand, CommandResult,
};

async fn print_stats(processor: &Arc<CommandProcessor>) {
    println!("📊 === BitChat Desktop Statistics ===");
    
    if let Ok(CommandResult::PeerList { peers }) = processor.process_command(BitchatCommand::ListPeers).await {
        println!("👥 Connected Peers: {}", peers.len());
        for peer in peers.iter().take(5) {
            println!("   - {}", peer);
        }
        if peers.len() > 5 {
            println!("   ... and {} more", peers.len() - 5);
        }
    }
    
    if let Ok(CommandResult::ChannelList { channels }) = processor.process_command(BitchatCommand::ListChannels).await {
        println!("💬 Joined Channels: {}", channels.len());
        for channel in channels {
            println!("   - #{}", channel);
        }
    }
    
    println!("==========================================\n");
}

async fn send_heartbeat(processor: &Arc<CommandProcessor>) {
    let heartbeat_msg = format!("Desktop heartbeat - {}", chrono::Utc::now().format("%H:%M:%S"));
    match processor.process_command(BitchatCommand::Message {
        content: heartbeat_msg,
        channel: Some("general".to_string()),
        recipient: None,
    }).await {
        Ok(_) => println!("💓 Heartbeat sent to network"),
        Err(e) => println!("❌ Failed to send heartbeat: {}", e),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    println!("🖥️  BitChat Desktop v1.0.0");
    println!("Starting desktop application...\n");

    let mut config = Config::default();
    config.max_peers = 50;
    config.scan_interval_ms = 3000;
    
    println!("📡 Device Name: {}", config.device_name);
    println!("💾 Data Directory: {}\n", config.data_dir.display());

    let core = BitchatCore::new(config).await?;
    let my_peer_id = core.get_peer_id();
    
    println!("🆔 Peer ID: {}", hex::encode(my_peer_id));
    println!("🔄 Starting BitChat services...\n");

    let processor = Arc::new(CommandProcessor::new(
        core.bluetooth.clone(),
        Arc::new(Mutex::new(core.crypto)),
        Arc::new(core.storage),
        Arc::new(core.config),
        core.packet_router.clone(),
        core.channel_manager.clone(),
        my_peer_id,
    ));

    println!("✅ BitChat Desktop ready!");

    // Auto-join general channel
    if let Ok(CommandResult::Success { message }) = processor.process_command(BitchatCommand::Join {
        channel: "general".to_string(),
        password: None,
    }).await {
        println!("🔗 {}", message);
    }

    if let Ok(CommandResult::Success { message }) = processor.process_command(BitchatCommand::SetNickname {
        nickname: format!("Desktop-{}", &hex::encode(my_peer_id)[..4]),
    }).await {
        println!("👤 {}", message);
    }

    let mut stats_interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
    let mut heartbeat_interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

    loop {
        tokio::select! {
            _ = stats_interval.tick() => print_stats(&processor).await,
            _ = heartbeat_interval.tick() => send_heartbeat(&processor).await,
            _ = tokio::signal::ctrl_c() => {
                println!("\n📡 Shutting down...");
                break;
            }
        }
    }

    Ok(())
}