//! SecureMesh Core Library
//! 
//! Core functionality for secure peer-to-peer messaging with iOS/Android compatibility

pub mod bluetooth;
pub mod crypto;
pub mod protocol;
pub mod messaging;
pub mod commands;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};

use bluetooth::manager::BluetoothConnectionManager;
use bluetooth::events::BluetoothEvent;
use messaging::manager::MessageManager;
use messaging::channel::ChannelManager;
use protocol::router::PacketRouter;

/// Main SecureMesh core instance with iOS/Android compatibility
pub struct SecureMeshCore {
    bluetooth: Arc<RwLock<BluetoothConnectionManager>>,
    message_manager: Arc<RwLock<MessageManager>>,
    channel_manager: Arc<RwLock<ChannelManager>>,
    packet_router: Arc<RwLock<PacketRouter>>,
    my_peer_id: String,
}

impl SecureMeshCore {
    /// Create a new SecureMesh instance with iOS/Android compatibility
    pub async fn new_with_compatibility() -> Result<Self> {
        info!("Initializing SecureMesh with iOS/Android compatibility");
        
        // Create Bluetooth manager with compatibility
        let bluetooth_manager = BluetoothConnectionManager::new_with_compatibility().await?;
        let my_peer_id = bluetooth_manager.get_peer_id().to_string();
        
        info!("SecureMesh initialized with peer ID: {}", my_peer_id);
        
        let bluetooth = Arc::new(RwLock::new(bluetooth_manager));
        let message_manager = Arc::new(RwLock::new(MessageManager::new()));
        let channel_manager = Arc::new(RwLock::new(ChannelManager::new()));
        let packet_router = Arc::new(RwLock::new(PacketRouter::new()));
        
        Ok(Self {
            bluetooth,
            message_manager,
            channel_manager,
            packet_router,
            my_peer_id,
        })
    }
    
    /// Start the mesh networking services
    pub async fn start(&self) -> Result<()> {
        info!("Starting SecureMesh services");
        
        let mut bluetooth = self.bluetooth.write().await;
        bluetooth.start().await?;
        
        // Start event processing
        self.start_event_processing().await?;
        
        info!("SecureMesh services started successfully");
        Ok(())
    }
    
    /// Start processing Bluetooth events
    async fn start_event_processing(&self) -> Result<()> {
        // TODO: Implement event processing loop
        // This would handle BluetoothEvent::PeerConnected, PeerDisconnected, etc.
        info!("Event processing started");
        Ok(())
    }
    
    /// Send a message to a specific peer
    pub async fn send_message(&self, recipient: &str, content: &str) -> Result<()> {
        info!("Sending message to {}: {}", recipient, content);
        
        // Create message packet
        let message_data = content.as_bytes();
        
        // Send via Bluetooth
        let bluetooth = self.bluetooth.read().await;
        bluetooth.broadcast_message(message_data).await?;
        
        Ok(())
    }
    
    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&self, content: &str) -> Result<()> {
        info!("Broadcasting message: {}", content);
        
        let message_data = content.as_bytes();
        
        let bluetooth = self.bluetooth.read().await;
        bluetooth.broadcast_message(message_data).await?;
        
        Ok(())
    }
    
    /// Join a channel
    pub async fn join_channel(&self, channel: &str) -> Result<String> {
        info!("Joining channel: {}", channel);
        
        let mut cm = self.channel_manager.write().await;
        let joined = cm.join_channel(channel);
        
        if joined {
            // Announce channel join to network
            let join_message = format!("joined {}", channel);
            self.broadcast_message(&join_message).await?;
            Ok(format!("Joined channel {}", channel))
        } else {
            Ok(format!("Already in channel {}", channel))
        }
    }
    
    /// Leave a channel
    pub async fn leave_channel(&self, channel: &str) -> Result<String> {
        info!("Leaving channel: {}", channel);
        
        let mut cm = self.channel_manager.write().await;
        let left = cm.leave_channel(channel);
        
        if left {
            // Announce channel leave to network
            let leave_message = format!("left {}", channel);
            self.broadcast_message(&leave_message).await?;
            Ok(format!("Left channel {}", channel))
        } else {
            Ok(format!("Not in channel {}", channel))
        }
    }
    
    /// List joined channels
    pub async fn list_channels(&self) -> Result<String> {
        let cm = self.channel_manager.read().await;
        let channels = cm.get_joined_channels();
        let current = cm.get_current_channel();
        
        if channels.is_empty() {
            Ok("No channels joined".to_string())
        } else {
            let mut result = String::from("Joined channels:\n");
            for channel in channels {
                let marker = if current == Some(&channel) { " (current)" } else { "" };
                result.push_str(&format!("  {}{}\n", channel, marker));
            }
            Ok(result)
        }
    }
    
    /// Get connected peers
    pub async fn get_connected_peers(&self) -> Vec<String> {
        // TODO: Implement peer list retrieval
        vec![]
    }
    
    /// Get debug information
    pub async fn get_debug_info(&self) -> String {
        let bluetooth = self.bluetooth.read().await;
        bluetooth.get_debug_info_with_compatibility().await
    }
    
    /// Get peer ID
    pub fn get_peer_id(&self) -> &str {
        &self.my_peer_id
    }
    
    /// Stop all services
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping SecureMesh services");
        
        // TODO: Implement proper shutdown
        
        info!("SecureMesh services stopped");
        Ok(())
    }
}