// ==============================================================================
// crates/core/src/bluetooth/manager.rs - BitChat Compatible Version (Thread Safe)
// ==============================================================================

//! BitChat Bluetooth Manager - Compatible with existing BitChat architecture
//! 
//! This manager integrates with the existing BitChat structure while providing
//! a foundation for enhanced Windows-macOS compatibility.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{info, warn, debug};
use anyhow::{Result, anyhow};

// Use the correct imports from the BitChat structure
use crate::bluetooth::{BluetoothConfig, BluetoothEvent, compatibility::CompatibilityManager, constants};
use crate::protocol::{BitchatPacket, MessageType, BinaryProtocol};

/// Connected peer information (matches existing BitChat structure)
#[derive(Debug, Clone)]
pub struct ConnectedPeer {
    pub peer_id: String,
    pub connected_at: Instant,
    pub last_seen: Instant,
    pub rssi: Option<i16>,
    pub message_count: u32,
}

/// Discovered device information (matches existing BitChat structure)
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub device_id: String,
    pub peer_id: Option<String>,
    pub rssi: i16,
    pub last_seen: Instant,
    pub connection_attempts: u32,
}

/// Simple event callback type (compatible with existing BitChat)
pub type EventCallback = Box<dyn Fn(BluetoothEvent) + Send + Sync>;

/// Thread-Safe Bluetooth Manager - Compatible with BitChat
pub struct BluetoothManager {
    // Core configuration
    config: BluetoothConfig,
    my_peer_id: String,
    
    // Use compatibility manager when bluetooth feature is enabled
    #[cfg(feature = "bluetooth")]
    compatibility: CompatibilityManager,
    #[cfg(not(feature = "bluetooth"))]
    compatibility: (),
    
    // State management
    connected_peers: Arc<RwLock<HashMap<String, ConnectedPeer>>>,
    discovered_devices: Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
    
    // Event handling (compatible with existing BitChat callback style)
    event_callback: Option<EventCallback>,
    
    // Runtime state
    is_scanning: Arc<RwLock<bool>>,
    is_advertising: Arc<RwLock<bool>>,
    is_running: Arc<RwLock<bool>>,
}

impl BluetoothManager {
    /// Create new Bluetooth manager - compatible with existing BitChat usage
    pub async fn new() -> Result<Self> {
        let config = BluetoothConfig::default();
        Self::with_config(config).await
    }
    
    /// Create Bluetooth manager with custom configuration
    pub async fn with_config(config: BluetoothConfig) -> Result<Self> {
        info!("?? Initializing BitChat Bluetooth Manager");
        
        let my_peer_id = config.device_name.clone();
        
        // Validate peer ID format using the existing constants module
        #[cfg(feature = "bluetooth")]
        {
            if !constants::peer_id::is_valid_peer_id_string(&my_peer_id) {
                return Err(anyhow!("Invalid peer ID format: {}", my_peer_id));
            }
        }
        
        // Create compatibility manager when bluetooth feature is enabled
        #[cfg(feature = "bluetooth")]
        let compatibility = CompatibilityManager::new(my_peer_id.clone());
        
        #[cfg(not(feature = "bluetooth"))]
        let compatibility = ();
        
        let manager = Self {
            config,
            my_peer_id: my_peer_id.clone(),
            compatibility,
            
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
            
            event_callback: None,
            
            is_scanning: Arc::new(RwLock::new(false)),
            is_advertising: Arc::new(RwLock::new(false)),
            is_running: Arc::new(RwLock::new(false)),
        };
        
        info!("?? BitChat Bluetooth Manager initialized");
        info!("?? Device Peer ID: {}", my_peer_id);
        
        Ok(manager)
    }
    
    /// Set event callback - compatible with existing BitChat pattern
    pub fn set_event_callback<F>(&mut self, callback: F) 
    where 
        F: Fn(BluetoothEvent) + Send + Sync + 'static 
    {
        self.event_callback = Some(Box::new(callback));
        info!("Event callback configured");
    }
    
    /// Send event through callback
    fn send_event(&self, event: BluetoothEvent) {
        if let Some(ref callback) = self.event_callback {
            callback(event);
        }
    }
    
    /// Start all Bluetooth operations
    pub async fn start(&mut self) -> Result<()> {
        info!("?? Starting BitChat Bluetooth Manager...");
        
        // Check if already running
        {
            let mut running = self.is_running.write().await;
            if *running {
                warn!("Bluetooth manager already running");
                return Ok(());
            }
            *running = true;
        }
        
        // Send adapter state event
        self.send_event(BluetoothEvent::AdapterStateChanged {
            powered_on: true,
            scanning: false,
            advertising: false,
        });
        
        // Start scanning and advertising (simulated for now)
        self.start_scanning().await?;
        self.start_advertising().await?;
        
        info!("? BitChat Bluetooth Manager started successfully");
        info!("?? Ready for BitChat device connections...");
        
        Ok(())
    }
    
    /// Stop all Bluetooth operations
    pub async fn stop(&mut self) -> Result<()> {
        info!("?? Stopping BitChat Bluetooth Manager...");
        
        *self.is_running.write().await = false;
        
        // Stop scanning and advertising
        self.stop_scanning().await?;
        self.stop_advertising().await?;
        
        // Disconnect all peers
        self.disconnect_all_peers().await?;
        
        info!("? BitChat Bluetooth Manager stopped");
        Ok(())
    }
    
    /// Start scanning (basic implementation for compatibility)
    pub async fn start_scanning(&mut self) -> Result<()> {
        info!("?? Starting BitChat device scanning...");
        
        if *self.is_scanning.read().await {
            warn!("Already scanning");
            return Ok(());
        }
        
        *self.is_scanning.write().await = true;
        
        self.send_event(BluetoothEvent::AdapterStateChanged {
            powered_on: true,
            scanning: true,
            advertising: *self.is_advertising.read().await,
        });
        
        info!("?? Scanning active - ready for BitChat devices");
        Ok(())
    }
    
    /// Start advertising (basic implementation for compatibility)
    pub async fn start_advertising(&mut self) -> Result<()> {
        info!("?? Starting BitChat advertising...");
        
        if *self.is_advertising.read().await {
            warn!("Already advertising");
            return Ok(());
        }
        
        *self.is_advertising.write().await = true;
        
        self.send_event(BluetoothEvent::AdapterStateChanged {
            powered_on: true,
            scanning: *self.is_scanning.read().await,
            advertising: true,
        });
        
        info!("?? Advertising active - visible to BitChat devices");
        Ok(())
    }
    
    /// Connect to a discovered device (simulated for compatibility)
    pub async fn connect_to_device(&mut self, device_id: &str) -> Result<ConnectedPeer> {
        info!("?? Connecting to BitChat device: {}", device_id);
        
        // Create a simulated connected peer for testing
        let connected_peer = ConnectedPeer {
            peer_id: device_id.to_string(),
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            rssi: Some(-50), // Simulated good signal
            message_count: 0,
        };
        
        // Store peer
        {
            let mut peers = self.connected_peers.write().await;
            peers.insert(connected_peer.peer_id.clone(), connected_peer.clone());
        }
        
        // Send connection event
        self.send_event(BluetoothEvent::PeerConnected {
            peer_id: connected_peer.peer_id.clone(),
        });
        
        info!("?? Successfully connected to BitChat device: {}", connected_peer.peer_id);
        
        Ok(connected_peer)
    }
    
    /// Send data to specific peer (simulated for compatibility)
    pub async fn send_to_peer(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        debug!("?? Sending {} bytes to peer: {}", data.len(), peer_id);
        
        // Check if peer is connected
        {
            let peers = self.connected_peers.read().await;
            if !peers.contains_key(peer_id) {
                return Err(anyhow!("Peer not connected: {}", peer_id));
            }
        }
        
        // Simulate successful send
        info!("?? Successfully sent {} bytes to {}", data.len(), peer_id);
        Ok(())
    }
    
    /// Send BitChat packet to peer - compatible with existing protocol
    pub async fn send_packet_to_peer(&self, peer_id: &str, packet: &BitchatPacket) -> Result<()> {
        // Use the existing BitChat binary protocol encoding
        let encoded_data = BinaryProtocol::encode(packet)?;
        self.send_to_peer(peer_id, &encoded_data).await
    }
    
    /// Send announcement to specific peer - compatible with existing BitChat
    pub async fn send_announcement_to_peer(&self, peer_id: &str, nickname: &str) -> Result<()> {
        info!("?? Sending announcement to {}: {}", peer_id, nickname);
        
        // Use the existing peer module for ID conversion
        #[cfg(feature = "bluetooth")]
        {
            let my_peer_id_bytes = crate::protocol::peer_utils::string_to_peer_id(&self.my_peer_id)
                .ok_or_else(|| anyhow!("Invalid peer ID format: {}", self.my_peer_id))?;
            let packet = BitchatPacket::new_broadcast(
                MessageType::Announce,
                my_peer_id_bytes,
                nickname.as_bytes().to_vec(),
            );
            
            self.send_packet_to_peer(peer_id, &packet).await
        }
        
        #[cfg(not(feature = "bluetooth"))]
        {
            warn!("Bluetooth feature not enabled, cannot send announcement");
            Ok(())
        }
    }
    
    /// Send message to specific peer - compatible with existing BitChat
    pub async fn send_message_to_peer(&self, peer_id: &str, message: &str) -> Result<()> {
        info!("?? Sending message to {}: {}", peer_id, message);
        
        #[cfg(feature = "bluetooth")]
        {
            let my_peer_id_bytes = crate::protocol::peer_utils::string_to_peer_id(&self.my_peer_id)
                .ok_or_else(|| anyhow!("Invalid peer ID format: {}", self.my_peer_id))?;
            let packet = BitchatPacket::new_broadcast(
                MessageType::Message,
                my_peer_id_bytes,
                message.as_bytes().to_vec(),
            );
            
            self.send_packet_to_peer(peer_id, &packet).await
        }
        
        #[cfg(not(feature = "bluetooth"))]
        {
            warn!("Bluetooth feature not enabled, cannot send message");
            Ok(())
        }
    }
    
    /// Broadcast message to all connected peers - compatible with existing BitChat
    pub async fn broadcast_message(&self, message: &str) -> Result<()> {
        info!("?? Broadcasting message: {}", message);
        
        let peer_ids: Vec<String> = {
            let peers = self.connected_peers.read().await;
            peers.keys().cloned().collect()
        };
        
        if peer_ids.is_empty() {
            warn!("No connected peers to broadcast to");
            return Ok(());
        }
        
        #[cfg(feature = "bluetooth")]
        {
            let my_peer_id_bytes = crate::protocol::peer_utils::string_to_peer_id(&self.my_peer_id)
                .ok_or_else(|| anyhow!("Invalid peer ID format: {}", self.my_peer_id))?;
            let packet = BitchatPacket::new_broadcast(
                MessageType::Message,
                my_peer_id_bytes,
                message.as_bytes().to_vec(),
            );
            
            for peer_id in peer_ids {
                if let Err(e) = self.send_packet_to_peer(&peer_id, &packet).await {
                    warn!("Failed to send broadcast to {}: {}", peer_id, e);
                }
            }
        }
        
        info!("?? Broadcast completed");
        Ok(())
    }
    
    /// Helper methods
    async fn get_connected_peer(&self, peer_id: &str) -> Result<ConnectedPeer> {
        let peers = self.connected_peers.read().await;
        peers.get(peer_id).cloned()
            .ok_or_else(|| anyhow!("Peer not connected: {}", peer_id))
    }
    
    async fn disconnect_all_peers(&self) -> Result<()> {
        let peer_ids: Vec<String> = {
            let peers = self.connected_peers.read().await;
            peers.keys().cloned().collect()
        };
        
        for peer_id in peer_ids {
            self.send_event(BluetoothEvent::PeerDisconnected {
                peer_id: peer_id.clone(),
            });
        }
        
        self.connected_peers.write().await.clear();
        Ok(())
    }
    
    async fn stop_scanning(&mut self) -> Result<()> {
        *self.is_scanning.write().await = false;
        
        self.send_event(BluetoothEvent::AdapterStateChanged {
            powered_on: true,
            scanning: false,
            advertising: *self.is_advertising.read().await,
        });
        
        Ok(())
    }
    
    async fn stop_advertising(&mut self) -> Result<()> {
        *self.is_advertising.write().await = false;
        
        self.send_event(BluetoothEvent::AdapterStateChanged {
            powered_on: true,
            scanning: *self.is_scanning.read().await,
            advertising: false,
        });
        
        Ok(())
    }
    
    /// Public query methods - compatible with existing BitChat API
    pub async fn get_discovered_devices(&self) -> HashMap<String, DiscoveredDevice> {
        self.discovered_devices.read().await.clone()
    }
    
    pub async fn get_connected_peers(&self) -> Vec<String> {
        let peers = self.connected_peers.read().await;
        peers.keys().cloned().collect()
    }
    
    pub async fn get_available_adapters(&self) -> String {
        "BitChat Core Adapter".to_string()
    }
    
    pub async fn is_scanning(&self) -> bool {
        *self.is_scanning.read().await
    }
    
    pub async fn is_advertising(&self) -> bool {
        *self.is_advertising.read().await
    }
    
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    /// Get comprehensive status - compatible with existing BitChat
    pub async fn get_status(&self) -> String {
        let discovered = self.discovered_devices.read().await.len();
        let connected = self.connected_peers.read().await.len();
        let adapters = self.get_available_adapters().await;
        
        format!(
            "BitChat Bluetooth Manager\n\
             =========================\n\
             Peer ID: {}\n\
             Running: {}\n\
             Scanning: {}\n\
             Advertising: {}\n\
             Discovered: {} devices\n\
             Connected: {} peers\n\
             Adapters: {}",
            self.my_peer_id,
            self.is_running().await,
            self.is_scanning().await,
            self.is_advertising().await,
            discovered,
            connected,
            adapters
        )
    }
}