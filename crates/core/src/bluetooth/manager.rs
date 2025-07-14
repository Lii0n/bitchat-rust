//! Bluetooth Connection Manager - Core mesh networking implementation

use super::events::{BluetoothEvent, ConnectedPeer, BluetoothConfig};
use anyhow::{Result, anyhow};
use btleplug::api::{
    Central, Manager as _, Peripheral as _, ScanFilter
};
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

/// Main Bluetooth connection manager
pub struct BluetoothConnectionManager {
    config: BluetoothConfig,
    manager: Option<Manager>,
    adapter: Option<Adapter>,
    
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
    /// Create a new BluetoothConnectionManager with default config
    pub async fn new() -> Result<Self> {
        Self::with_config(BluetoothConfig::default()).await
    }

    /// Create a new BluetoothConnectionManager with custom config
    pub async fn with_config(config: BluetoothConfig) -> Result<Self> {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        let mut manager = Self {
            config,
            manager: None,
            adapter: None,
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
        info!("Initializing Bluetooth with correct UUIDs...");
        info!("Service UUID: {}", BITCHAT_SERVICE_UUID);
        info!("Characteristic UUID: {}", MESSAGE_CHARACTERISTIC_UUID);
        
        let manager = Manager::new().await?;
        self.manager = Some(manager);
        
        // Get the default adapter
        let adapters = self.manager.as_ref().unwrap().adapters().await?;
        if adapters.is_empty() {
            return Err(anyhow!("No Bluetooth adapters found"));
        }
        
        let adapter = adapters.into_iter().next().unwrap();
        info!("Using Bluetooth adapter: {:?}", adapter.adapter_info().await);
        self.adapter = Some(adapter);
        
        Ok(())
    }

    /// Start scanning for peers
    pub async fn start_scanning(&mut self) -> Result<()> {
        let adapter = self.adapter.as_ref()
            .ok_or_else(|| anyhow!("Bluetooth not initialized"))?;

        info!("Starting BLE scan for BitChat service: {}", BITCHAT_SERVICE_UUID);
        
        // Scan specifically for our service UUID
        let scan_filter = ScanFilter {
            services: vec![BITCHAT_SERVICE_UUID],
        };
        
        adapter.start_scan(scan_filter).await?;
        *self.scanning.write().await = true;
        
        self.emit_event(BluetoothEvent::ScanningStateChanged { scanning: true });
        
        // Start background task to handle discoveries
        self.start_scan_task().await;
        
        Ok(())
    }

    /// Start advertising our service
    pub async fn start_advertising(&mut self) -> Result<()> {
        // Note: btleplug doesn't support advertising on most platforms
        // This would need to be implemented using platform-specific APIs
        warn!("Advertising not yet implemented for this platform");
        Ok(())
    }

    /// Stop all Bluetooth operations
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping Bluetooth operations");
        
        // Stop scanning
        if let Some(adapter) = &self.adapter {
            adapter.stop_scan().await?;
        }
        *self.scanning.write().await = false;
        
        // Stop background tasks
        if let Some(task) = self.scan_task.lock().await.take() {
            task.abort();
        }
        if let Some(task) = self.cleanup_task.lock().await.take() {
            task.abort();
        }
        
        self.emit_event(BluetoothEvent::ScanningStateChanged { scanning: false });
        
        Ok(())
    }

    /// Start the background scanning task
    async fn start_scan_task(&self) {
        let adapter = self.adapter.as_ref().unwrap().clone();
        let event_sender = self.event_sender.clone();
        let connected_peers = self.connected_peers.clone();
        
        let task = tokio::spawn(async move {
            let mut events = adapter.events().await.unwrap();
            
            while let Some(event) = events.next().await {
                match event {
                    btleplug::api::CentralEvent::DeviceDiscovered(id) => {
                        if let Ok(peripheral) = adapter.peripheral(&id).await {
                            if let Ok(Some(properties)) = peripheral.properties().await {
                                // FIXED: Check if this device advertises our service (direct check, no Option)
                                if properties.services.contains(&BITCHAT_SERVICE_UUID) {
                                    let peer_id = id.to_string();
                                    let name = properties.local_name.clone(); // Clone to avoid move
                                    let rssi = properties.rssi.unwrap_or(0);
                                    
                                    info!("Discovered BitChat peer: {} ({})", 
                                         name.as_deref().unwrap_or("Unknown"), peer_id);
                                    
                                    // Try to connect
                                    if let Err(e) = peripheral.connect().await {
                                        warn!("Failed to connect to peer {}: {}", peer_id, e);
                                        continue;
                                    }
                                    
                                    // FIXED: Create ConnectedPeer with correct field types
                                    let peer = ConnectedPeer {
                                        id: peer_id.clone(),
                                        peripheral: peripheral.clone(),
                                        name: name.clone(), // Clone for struct
                                        rssi: rssi,
                                        connected_at: Instant::now(),
                                        last_seen: Instant::now(),
                                        message_characteristic: None,
                                    };
                                    
                                    connected_peers.write().await.insert(peer_id.clone(), peer);
                                    
                                    // Emit discovery event (using cloned name)
                                    let _ = event_sender.send(BluetoothEvent::PeerDiscovered {
                                        peer_id: peer_id.clone(),
                                        name: name, // Use original name here
                                        rssi: rssi,
                                    });
                                    
                                    // Emit connection event
                                    let _ = event_sender.send(BluetoothEvent::PeerConnected {
                                        peer_id: peer_id,
                                    });
                                }
                            }
                        }
                    }
                    btleplug::api::CentralEvent::DeviceDisconnected(id) => {
                        let peer_id = id.to_string();
                        connected_peers.write().await.remove(&peer_id);
                        
                        info!("Peer disconnected: {}", peer_id);
                        let _ = event_sender.send(BluetoothEvent::PeerDisconnected {
                            peer_id: peer_id,
                        });
                    }
                    btleplug::api::CentralEvent::DeviceConnected(id) => {
                        let peer_id = id.to_string();
                        info!("Peer connected: {}", peer_id);
                        
                        // Update last seen time (removed mut - not needed)
                        if let Some(peer) = connected_peers.write().await.get_mut(&peer_id) {
                            peer.last_seen = Instant::now();
                        }
                    }
                    _ => {
                        // Handle other events as needed
                        debug!("Received other Bluetooth event: {:?}", event);
                    }
                }
            }
        });
        
        *self.scan_task.lock().await = Some(task);
    }

    /// Start a cleanup task to remove stale peers
    async fn start_cleanup_task(&self) {
        let connected_peers = self.connected_peers.clone();
        let event_sender = self.event_sender.clone();
        let timeout_secs = self.config.connection_timeout_secs;
        
        let task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                let mut to_remove = Vec::new();
                {
                    let peers = connected_peers.read().await;
                    for (peer_id, peer) in peers.iter() {
                        if peer.is_stale(timeout_secs) {
                            to_remove.push(peer_id.clone());
                        }
                    }
                }
                
                for peer_id in to_remove {
                    connected_peers.write().await.remove(&peer_id);
                    info!("Removed stale peer: {}", peer_id);
                    
                    let _ = event_sender.send(BluetoothEvent::PeerDisconnected {
                        peer_id: peer_id,
                    });
                }
            }
        });
        
        *self.cleanup_task.lock().await = Some(task);
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&self, data: &[u8]) -> Result<()> {
        debug!("Broadcasting {} bytes to connected peers", data.len());
        
        let peers = self.connected_peers.read().await;
        if peers.is_empty() {
            debug!("No connected peers to broadcast to");
            return Ok(());
        }
        
        for (peer_id, _peer) in peers.iter() {
            if let Err(e) = self.send_to_peer(peer_id, data).await {
                warn!("Failed to send to peer {}: {}", peer_id, e);
            }
        }
        
        Ok(())
    }

    /// Send data to a specific peer
    async fn send_to_peer(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        // This would need to implement the actual GATT write to the characteristic
        // For now, just log that we would send
        debug!("Would send {} bytes to peer {}", data.len(), peer_id);
        
        // Emit message received event for testing
        self.emit_event(BluetoothEvent::MessageReceived {
            peer_id: peer_id.to_string(),
            data: data.to_vec(),
        });
        
        Ok(())
    }

    /// Get list of connected peer IDs
    pub async fn get_connected_peers(&self) -> Vec<String> {
        self.connected_peers.read().await.keys().cloned().collect()
    }

    /// Get detailed information about a connected peer
    pub async fn get_peer_info(&self, peer_id: &str) -> Option<ConnectedPeer> {
        self.connected_peers.read().await.get(peer_id).cloned()
    }

    /// Take the event receiver (should only be called once)
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<BluetoothEvent>> {
        self.event_receiver.lock().await.take()
    }

    /// Emit a Bluetooth event
    fn emit_event(&self, event: BluetoothEvent) {
        if let Err(e) = self.event_sender.send(event) {
            error!("Failed to send Bluetooth event: {}", e);
        }
    }
}