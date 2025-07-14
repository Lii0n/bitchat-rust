// Create crates/desktop/src/windows_bluetooth_example.rs

//! Example integration of Windows Bluetooth manager
//! Demonstrates how to use the new dual-role implementation

use bitchat_core::{
    bluetooth::{BluetoothConfig, BluetoothEvent, BluetoothManagerTrait, create_bluetooth_manager},
    protocol::{BitchatPacket, MessageType, BinaryProtocolManager, peer_utils},
    Config,
};
use anyhow::Result;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{info, warn, error};

/// Example Windows Bluetooth BitChat implementation
pub struct WindowsBitchatExample {
    bluetooth_manager: Box<dyn BluetoothManagerTrait + Send + Sync>,
    my_peer_id: String,
}

impl WindowsBitchatExample {
    /// Create new example instance
    pub async fn new() -> Result<Self> {
        // Initialize logging
        tracing_subscriber::fmt()
            .with_max_level(tracing::Level::INFO)
            .init();
        
        info!("?? Starting Windows BitChat example...");
        
        // Create configuration
        let config = Config::with_deterministic_peer_id();
        let bluetooth_config = BluetoothConfig::with_device_name(config.device_name.clone())
            .with_connection_limits(8, 5000)
            .with_rssi_threshold(-85)
            .with_debug_logging(true);
        
        let my_peer_id = bluetooth_config.get_peer_id_string();
        info!("?? Device Peer ID: {}", my_peer_id);
        info!("?? Advertisement Name: {}", bluetooth_config.get_advertisement_name());
        
        // Create Bluetooth manager
        let bluetooth_manager = create_bluetooth_manager(bluetooth_config).await?;
        
        Ok(Self {
            bluetooth_manager,
            my_peer_id,
        })
    }
    
    /// Start the BitChat example
    pub async fn run(&mut self) -> Result<()> {
        info!("?? Starting Bluetooth operations...");
        
        // Start Bluetooth (scanning + advertising)
        self.bluetooth_manager.start().await?;
        
        info!("? BitChat is now running!");
        info!("?? Scanning for iOS/Android BitChat devices...");
        info!("?? Advertising as BitChat device...");
        info!("?? Connect an iOS/Android BitChat device nearby to test!");
        
        // Main event loop
        self.run_event_loop().await?;
        
        Ok(())
    }
    
    /// Main event loop
    async fn run_event_loop(&mut self) -> Result<()> {
        let mut last_status_update = std::time::Instant::now();
        let mut message_counter = 0u32;
        
        loop {
            // Print status every 30 seconds
            if last_status_update.elapsed() > Duration::from_secs(30) {
                self.print_status().await;
                last_status_update = std::time::Instant::now();
            }
            
            // Send periodic announcements to connected peers
            if message_counter % 12 == 0 { // Every 60 seconds (12 * 5s)
                self.send_periodic_announcement().await?;
            }
            
            // Send test messages occasionally
            if message_counter % 24 == 0 && message_counter > 0 { // Every 2 minutes
                self.send_test_message().await?;
            }
            
            message_counter += 1;
            sleep(Duration::from_secs(5)).await;
        }
    }
    
    /// Print current status
    async fn print_status(&mut self) {
        let connected_peers = self.bluetooth_manager.get_connected_peers().await;
        let debug_info = self.bluetooth_manager.get_debug_info().await;
        
        info!("?? Status Update:");
        info!("   Connected Peers: {}", connected_peers.len());
        if !connected_peers.is_empty() {
            info!("   Peer List: {}", connected_peers.join(", "));
        }
        
        // Print detailed debug info
        println!("\n{}\n", debug_info);
    }
    
    /// Send periodic announcement
    async fn send_periodic_announcement(&mut self) -> Result<()> {
        let connected_peers = self.bluetooth_manager.get_connected_peers().await;
        
        if !connected_peers.is_empty() {
            let nickname = format!("Rust-{}", &self.my_peer_id[..4]);
            let announcement_packet = self.create_announcement_packet(&nickname)?;
            
            info!("?? Sending announcement to {} peers: {}", connected_peers.len(), nickname);
            
            if let Err(e) = self.bluetooth_manager.broadcast_packet(&announcement_packet).await {
                warn!("Failed to broadcast announcement: {}", e);
            }
        }
        
        Ok(())
    }
    
    /// Send test message
    async fn send_test_message(&mut self) -> Result<()> {
        let connected_peers = self.bluetooth_manager.get_connected_peers().await;
        
        if !connected_peers.is_empty() {
            let timestamp = chrono::Utc::now().timestamp() as u64;
            let message = format!("Hello from Rust BitChat! Time: {}", timestamp);
            let message_packet = self.create_message_packet(&message)?;
            
            info!("?? Sending test message to {} peers", connected_peers.len());
            
            if let Err(e) = self.bluetooth_manager.broadcast_packet(&message_packet).await {
                warn!("Failed to broadcast message: {}", e);
            }
        }
        
        Ok(())
    }
    
    /// Create announcement packet
    fn create_announcement_packet(&self, nickname: &str) -> Result<BitchatPacket> {
        let peer_id_bytes = peer_utils::peer_id_string_to_bytes(&self.my_peer_id)?;
        
        Ok(BitchatPacket::new_broadcast(
            MessageType::Announce,
            peer_id_bytes,
            nickname.as_bytes().to_vec(),
        ))
    }
    
    /// Create message packet
    fn create_message_packet(&self, content: &str) -> Result<BitchatPacket> {
        let peer_id_bytes = peer_utils::peer_id_string_to_bytes(&self.my_peer_id)?;
        
        Ok(BitchatPacket::new_broadcast(
            MessageType::Message,
            peer_id_bytes,
            content.as_bytes().to_vec(),
        ))
    }
    
    /// Stop the example
    pub async fn stop(&mut self) -> Result<()> {
        info!("?? Stopping BitChat...");
        self.bluetooth_manager.stop().await?;
        info!("? BitChat stopped");
        Ok(())
    }
}

/// Run the Windows BitChat example
pub async fn run_windows_example() -> Result<()> {
    let mut example = WindowsBitchatExample::new().await?;
    
    // Set up graceful shutdown
    let (tx, mut rx) = tokio::sync::oneshot::channel();
    
    // Handle Ctrl+C
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.expect("Failed to listen for Ctrl+C");
        let _ = tx.send(());
    });
    
    // Run example until shutdown signal
    tokio::select! {
        result = example.run() => {
            if let Err(e) = result {
                error!("Example failed: {}", e);
            }
        }
        _ = &mut rx => {
            info!("Received shutdown signal");
        }
    }
    
    // Graceful shutdown
    example.stop().await?;
    
    Ok(())
}

#[cfg(windows)]
#[tokio::main]
async fn main() -> Result<()> {
    run_windows_example().await
}

#[cfg(not(windows))]
fn main() {
    println!("This example only runs on Windows");
    println!("Use: cargo run --bin windows_bluetooth_example --target x86_64-pc-windows-msvc");
}