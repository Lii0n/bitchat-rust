//! Bluetooth Connection Manager - Core mesh networking implementation with iOS/Android compatibility

use super::events::{BluetoothEvent, ConnectedPeer, BluetoothConfig};
use super::compatibility::CompatibilityManager;
use anyhow::{Result, anyhow};
#[cfg(feature = "bluetooth")]
use btleplug::api::{
    Central, Manager as _, Peripheral as _, ScanFilter
};
#[cfg(feature = "bluetooth")]
use btleplug::platform::{Manager, Adapter};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{mpsc, RwLock, Mutex};
use uuid::Uuid;
use tracing::{info, warn, error, debug};
use tokio_stream::StreamExt;

/// BitChat service UUID - MUST MATCH iOS/macOS versions EXACTLY
pub const BITCHAT_SERVICE_UUID: Uuid = uuid::uuid!("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");
/// Message characteristic UUID - MUST MATCH iOS/macOS versions EXACTLY  
pub const MESSAGE_CHARACTERISTIC_UUID: Uuid = uuid::uuid!("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D");

/// Main Bluetooth connection manager with iOS/Android compatibility
pub struct BluetoothConnectionManager {
    config: BluetoothConfig,
    #[cfg(feature = "bluetooth")]
    manager: Option<Manager>,
    #[cfg(feature = "bluetooth")]
    adapter: Option<Adapter>,
    
    // Compatibility layer
    compatibility: Option<CompatibilityManager>,
    
    // Connection state
    connected_peers: Arc<RwLock<HashMap<String, ConnectedPeer>>>,
    scanning: Arc<RwLock<bool>>,
    advertising: Arc<RwLock<bool>>,
    
    // Event handling
    event_sender: mpsc::UnboundedSender<BluetoothEvent>,
    event_receiver: Arc<Mutex<Option<mpsc::UnboundedReceiver<BluetoothEvent>>>>,
    
    // Background tasks
    scan_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    cleanup_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl BluetoothConnectionManager {
    /// Create a new BluetoothConnectionManager with iOS/Android compatibility
    pub async fn new_with_compatibility() -> Result<Self> {
        // Generate iOS/Android compatible peer ID (8 hex characters)
        let peer_id = CompatibilityManager::generate_compatible_peer_id();
        info!("Generated compatible peer ID: {}", peer_id);
        
        let config = BluetoothConfig {
            peer_id: peer_id.clone(),
            ..Default::default()
        };
        
        Self::with_compatibility_config(config).await
    }

    /// Create a new BluetoothConnectionManager with custom config and compatibility
    pub async fn with_compatibility_config(config: BluetoothConfig) -> Result<Self> {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        // Create compatibility manager
        let compatibility = CompatibilityManager::new(config.peer_id.clone());
        
        let mut manager = Self {
            config,
            manager: None,
            adapter: None,
            compatibility: Some(compatibility),
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            scanning: Arc::new(RwLock::new(false)),
            advertising: Arc::new(RwLock::new(false)),
            event_sender,
            event_receiver: Arc::new(Mutex::new(Some(event_receiver))),
            scan_task: Arc::new(Mutex::new(None)),
            cleanup_task: Arc::new(Mutex::new(None)),
        };

        // Try to initialize, but don't fail if Bluetooth unavailable
        if let Err(e) = manager.initialize().await {
            warn!("Bluetooth initialization failed: {}. Running in offline mode.", e);
        }

        Ok(manager)
    }

    /// Initialize the Bluetooth manager
    async fn initialize(&mut self) -> Result<()> {
        info!("Initializing Bluetooth with iOS/Android compatibility...");
        info!("Service UUID: {}", BITCHAT_SERVICE_UUID);
        info!("Characteristic UUID: {}", MESSAGE_CHARACTERISTIC_UUID);
        info!("My Peer ID: {}", self.config.peer_id);
        
        let manager = Manager::new().await?;
        let adapters = manager.adapters().await?;
        
        if adapters.is_empty() {
            return Err(anyhow!("No Bluetooth adapters found"));
        }
        
        let adapter = adapters.into_iter().next().unwrap();
        info!("Using Bluetooth adapter: {:?}", adapter.adapter_info().await);
        
        self.manager = Some(manager);
        self.adapter = Some(adapter);
        
        // Start cleanup task
        self.start_cleanup_task().await;
        
        Ok(())
    }

    /// Start services with compatibility mode
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting Bluetooth mesh services in compatibility mode");
        
        // Start advertising first (as peripheral)
        self.start_advertising_compatible().await?;
        
        // Start scanning (as central)
        self.start_scanning_compatible().await?;
        
        info!("Bluetooth mesh services started successfully");
        Ok(())
    }

    /// Start advertising with iOS/Android compatible format
    pub async fn start_advertising_compatible(&self) -> Result<()> {
        let compatibility = self.compatibility.as_ref()
            .ok_or_else(|| anyhow!("Compatibility manager not initialized"))?;
        
        let advertisement_name = compatibility.create_advertisement_name();
        info!("Starting advertising with compatible name: {}", advertisement_name);
        
        // Implementation depends on your BLE library setup
        // This is a placeholder - you'll need to implement the actual advertising
        self.start_advertising_with_name(&advertisement_name).await?;
        
        let mut advertising = self.advertising.write().await;
        *advertising = true;
        
        Ok(())
    }

    /// Start scanning with compatibility logic
    pub async fn start_scanning_compatible(&self) -> Result<()> {
        let adapter = self.adapter.as_ref()
            .ok_or_else(|| anyhow!("No Bluetooth adapter available"))?;
        
        info!("Starting compatible scanning for bitchat devices");
        
        // Start scanning for bitchat service UUID
        adapter.start_scan(ScanFilter {
            services: vec![BITCHAT_SERVICE_UUID],
        }).await?;
        
        let mut scanning = self.scanning.write().await;
        *scanning = true;
        
        // Start discovery monitoring task
        self.start_discovery_task().await?;
        
        Ok(())
    }

    /// Handle discovered device with compatibility logic
    pub async fn handle_discovered_device_compatible(
        &self,
        device_id: String,
        device_name: Option<String>,
        rssi: i8,
    ) -> Result<()> {
        let compatibility = self.compatibility.as_ref()
            .ok_or_else(|| anyhow!("Compatibility manager not initialized"))?;
        
        let current_connections = self.connected_peers.read().await.len();
        let max_connections = 8; // Match iOS/Android limit
        
        if let Some(peer_id) = compatibility.handle_discovered_device(
            device_id.clone(),
            device_name,
            rssi,
            current_connections,
            max_connections,
        ).await {
            info!("Attempting to connect to peer: {}", peer_id);
            
            // Add jitter delay to avoid simultaneous attempts
            let jitter_ms = fastrand::u64(100..=500);
            tokio::time::sleep(std::time::Duration::from_millis(jitter_ms)).await;
            
            // Double-check we should still connect after jitter
            if compatibility.should_initiate_connection(&peer_id) {
                match self.connect_to_device(&device_id).await {
                    Ok(_) => {
                        info!("Successfully connected to {}", peer_id);
                        compatibility.mark_connection_complete(&peer_id).await;
                        
                        // Add to connected peers
                        let connected_peer = ConnectedPeer {
                            peer_id: peer_id.clone(),
                            device_id,
                            connected_at: Instant::now(),
                            last_seen: Instant::now(),
                        };
                        
                        let mut peers = self.connected_peers.write().await;
                        peers.insert(peer_id.clone(), connected_peer);
                        
                        // Notify connection event
                        let _ = self.event_sender.send(BluetoothEvent::PeerConnected { peer_id });
                    }
                    Err(e) => {
                        warn!("Failed to connect to {}: {}", peer_id, e);
                        compatibility.mark_connection_complete(&peer_id).await;
                        
                        // Schedule retry if appropriate
                        self.schedule_retry_connection(peer_id, device_id).await?;
                    }
                }
            } else {
                info!("Connection role changed during jitter, aborting connection to {}", peer_id);
                compatibility.mark_connection_complete(&peer_id).await;
            }
        }
        
        Ok(())
    }

    /// Schedule connection retry with exponential backoff
    async fn schedule_retry_connection(&self, peer_id: String, device_id: String) -> Result<()> {
        let compatibility = self.compatibility.as_ref()
            .ok_or_else(|| anyhow!("Compatibility manager not initialized"))?;
        
        if compatibility.should_retry_connection(&peer_id).await {
            let retry_delay = compatibility.get_retry_delay(&peer_id).await;
            info!("Scheduling retry for {} after {:?}", peer_id, retry_delay);
            
            // Clone necessary data for the retry task
            let compatibility_clone = compatibility.clone(); // You'll need to make CompatibilityManager cloneable
            let manager_clone = self.clone(); // You'll need to make BluetoothConnectionManager cloneable
            
            tokio::spawn(async move {
                tokio::time::sleep(retry_delay).await;
                
                // Only retry if we should still be the one connecting
                if compatibility_clone.should_initiate_connection(&peer_id) {
                    if let Err(e) = manager_clone.handle_discovered_device_compatible(
                        device_id,
                        Some(peer_id.clone()),
                        -70 // Use a reasonable default RSSI for retry
                    ).await {
                        error!("Retry connection failed for {}: {}", peer_id, e);
                    }
                }
            });
        } else {
            info!("Max retries reached for {}", peer_id);
        }
        
        Ok(())
    }

    /// Handle device disconnection
    pub async fn handle_device_disconnected(&self, peer_id: String, was_error: bool) -> Result<()> {
        info!("Disconnected from peer: {}", peer_id);
        
        // Remove from connected peers
        {
            let mut peers = self.connected_peers.write().await;
            peers.remove(&peer_id);
        }
        
        // Mark connection as complete in compatibility manager
        if let Some(compatibility) = &self.compatibility {
            compatibility.mark_connection_complete(&peer_id).await;
        }
        
        // Notify disconnection event
        let _ = self.event_sender.send(BluetoothEvent::PeerDisconnected { peer_id: peer_id.clone() });
        
        // Auto-reconnect if this was unexpected and we should be the connector
        if was_error {
            if let Some(compatibility) = &self.compatibility {
                if compatibility.should_initiate_connection(&peer_id) {
                    info!("Scheduling reconnection attempt for {} after unexpected disconnect", peer_id);
                    
                    let manager_clone = self.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        
                        // Only reconnect if we're still not connected
                        let current_connections = manager_clone.connected_peers.read().await;
                        if !current_connections.contains_key(&peer_id) {
                            info!("Attempting to rediscover {} after unexpected disconnect", peer_id);
                            // The scanning will naturally rediscover the device if it's still advertising
                        }
                    });
                }
            }
        }
        
        Ok(())
    }

    /// Start discovery monitoring task
    async fn start_discovery_task(&self) -> Result<()> {
        let adapter = self.adapter.as_ref()
            .ok_or_else(|| anyhow!("No Bluetooth adapter available"))?;
        
        let manager_clone = self.clone(); // You'll need to implement Clone
        
        tokio::spawn(async move {
            let mut events = adapter.events().await.unwrap();
            
            while let Some(event) = events.next().await {
                use btleplug::api::CentralEvent;
                
                match event {
                    CentralEvent::DeviceDiscovered(id) => {
                        if let Ok(peripheral) = adapter.peripheral(&id).await {
                            let device_name = peripheral.properties().await
                                .unwrap_or_default()
                                .unwrap_or_default()
                                .local_name;
                            
                            let rssi = peripheral.properties().await
                                .unwrap_or_default()
                                .unwrap_or_default()
                                .rssi
                                .unwrap_or(-100) as i8;
                            
                            if let Err(e) = manager_clone.handle_discovered_device_compatible(
                                id.to_string(),
                                device_name,
                                rssi
                            ).await {
                                error!("Error handling discovered device: {}", e);
                            }
                        }
                    }
                    CentralEvent::DeviceDisconnected(id) => {
                        // Handle disconnection
                        if let Err(e) = manager_clone.handle_device_disconnected(
                            id.to_string(),
                            true // Assume error disconnect for now
                        ).await {
                            error!("Error handling device disconnection: {}", e);
                        }
                    }
                    _ => {}
                }
            }
        });
        
        Ok(())
    }

    /// Start cleanup task for old discoveries and connections
    async fn start_cleanup_task(&self) {
        let compatibility = self.compatibility.clone();
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                if let Some(ref compat) = compatibility {
                    compat.cleanup_old_discoveries().await;
                }
            }
        });
    }

    /// Placeholder for actual BLE advertising implementation
    async fn start_advertising_with_name(&self, _name: &str) -> Result<()> {
        // TODO: Implement actual BLE advertising with btleplug
        // This will depend on your specific btleplug setup
        warn!("BLE advertising not yet implemented - placeholder");
        Ok(())
    }

    /// Placeholder for actual BLE connection implementation
    async fn connect_to_device(&self, _device_id: &str) -> Result<()> {
        // TODO: Implement actual BLE connection with btleplug
        // This will depend on your specific btleplug setup
        warn!("BLE connection not yet implemented - placeholder");
        Ok(())
    }

    /// Get debug info including compatibility status
    pub async fn get_debug_info_with_compatibility(&self) -> String {
        let mut info = String::new();
        
        info.push_str("Bluetooth Connection Manager Debug\n");
        info.push_str("==================================\n\n");
        
        // Basic info
        info.push_str(&format!("Peer ID: {}\n", self.config.peer_id));
        info.push_str(&format!("Scanning: {}\n", *self.scanning.read().await));
        info.push_str(&format!("Advertising: {}\n", *self.advertising.read().await));
        
        // Connected peers
        let peers = self.connected_peers.read().await;
        info.push_str(&format!("Connected Peers: {}\n", peers.len()));
        for (peer_id, peer) in peers.iter() {
            info.push_str(&format!("  - {}: connected {}s ago\n", 
                                 peer_id, 
                                 peer.connected_at.elapsed().as_secs()));
        }
        
        info.push_str("\n");
        
        // Compatibility info
        if let Some(compatibility) = &self.compatibility {
            info.push_str(&compatibility.get_debug_info().await);
        }
        
        info
    }

    /// Get the peer ID
    pub fn get_peer_id(&self) -> &str {
        &self.config.peer_id
    }

    /// Get connected peers count
    pub async fn get_connected_count(&self) -> usize {
        self.connected_peers.read().await.len()
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&self, _data: &[u8]) -> Result<()> {
        // TODO: Implement message broadcasting
        warn!("Message broadcasting not yet implemented - placeholder");
        Ok(())
    }
}

// TODO: Implement Clone for BluetoothConnectionManager if needed for retry logic
// This might require using Arc for internal state