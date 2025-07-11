//! Bluetooth Connection Manager - Core mesh networking implementation

use super::events::{BluetoothEvent, ConnectedPeer, BluetoothConfig};
use anyhow::{Result, anyhow};
use btleplug::api::{
    Central, Manager as _, Peripheral as _, CharPropFlags,
    WriteType, ScanFilter
};
use btleplug::platform::{Manager, Adapter, Peripheral};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Mutex};
use tokio::time;
use uuid::Uuid;
use tracing::{info, warn, error, debug};
use tokio_stream::StreamExt;  // Changed from futures to tokio_stream

/// BitChat service UUID - must match iOS/Android versions
pub const BITCHAT_SERVICE_UUID: Uuid = Uuid::from_u128(0x12345678_1234_5678_1234_567812345678);
/// Message characteristic UUID for sending/receiving messages  
pub const MESSAGE_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0x87654321_4321_8765_4321_876543218765);

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
        info!("Initializing Bluetooth manager");

        // Create manager and get adapter
        let manager = Manager::new().await.map_err(|e| {
            anyhow!("Failed to create Bluetooth manager: {}. Is Bluetooth enabled?", e)
        })?;

        let adapters = manager.adapters().await.map_err(|e| {
            anyhow!("Failed to get Bluetooth adapters: {}", e)
        })?;

        if adapters.is_empty() {
            return Err(anyhow!("No Bluetooth adapters found"));
        }

        let adapter = adapters.into_iter().next().unwrap();
        
        if self.config.verbose_logging {
            info!("Using Bluetooth adapter: {:?}", adapter.adapter_info().await);
        }

        self.manager = Some(manager);
        self.adapter = Some(adapter);

        // Start cleanup task
        self.start_cleanup_task().await;

        Ok(())
    }

    /// Start scanning for BitChat devices
    pub async fn start_scanning(&mut self) -> Result<()> {
        let adapter = self.adapter.as_ref()
            .ok_or_else(|| anyhow!("Bluetooth not initialized"))?;

        info!("Starting BLE scanning for BitChat devices");

        // Set up scan filter for BitChat service
        let scan_filter = ScanFilter {
            services: vec![BITCHAT_SERVICE_UUID],
        };

        // Start scanning
        adapter.start_scan(scan_filter).await.map_err(|e| {
            anyhow!("Failed to start scanning: {}", e)
        })?;

        *self.scanning.write().await = true;
        self.emit_event(BluetoothEvent::ScanningStateChanged { scanning: true });

        // Start scan monitoring task
        self.start_scan_monitoring_task().await;

        Ok(())
    }

    /// Stop scanning
    pub async fn stop_scanning(&mut self) -> Result<()> {
        if let Some(adapter) = &self.adapter {
            adapter.stop_scan().await.map_err(|e| {
                warn!("Error stopping scan: {}", e);
                e
            }).ok();
        }

        *self.scanning.write().await = false;
        self.emit_event(BluetoothEvent::ScanningStateChanged { scanning: false });

        // Stop scan monitoring task
        if let Some(task) = self.scan_task.lock().await.take() {
            task.abort();
        }

        info!("Stopped BLE scanning");
        Ok(())
    }

    /// Start advertising (stub for now)
    pub async fn start_advertising(&mut self) -> Result<()> {
        if self.adapter.is_some() {
            info!("Starting Bluetooth LE advertising (not implemented yet)");
            *self.advertising.write().await = true;
            self.emit_event(BluetoothEvent::AdvertisingStateChanged { advertising: true });
        } else {
            info!("Bluetooth not available - advertising disabled");
        }
        Ok(())
    }

    /// Send a message to a specific peer
    pub async fn send_message_to_peer(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        let peers = self.connected_peers.read().await;
        let peer = peers.get(peer_id)
            .ok_or_else(|| anyhow!("Peer {} not connected", peer_id))?;

        if let Some(characteristic) = &peer.message_characteristic {
            peer.peripheral.write(characteristic, data, WriteType::WithoutResponse).await
                .map_err(|e| anyhow!("Failed to send message to {}: {}", peer_id, e))?;
            
            if self.config.verbose_logging {
                debug!("Sent {} bytes to peer {}", data.len(), peer.short_id());
            }
        } else {
            return Err(anyhow!("No message characteristic available for peer {}", peer_id));
        }

        Ok(())
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&self, data: &[u8]) -> Result<()> {
        let peers = self.connected_peers.read().await;
        let mut send_count = 0;
        let mut errors = Vec::new();

        for (_peer_id, peer) in peers.iter() {
            if let Some(characteristic) = &peer.message_characteristic {
                match peer.peripheral.write(characteristic, data, WriteType::WithoutResponse).await {
                    Ok(_) => {
                        send_count += 1;
                        if self.config.verbose_logging {
                            debug!("Broadcast message sent to peer {}", peer.short_id());
                        }
                    }
                    Err(e) => {
                        errors.push(format!("Failed to send to {}: {}", peer.short_id(), e));
                    }
                }
            }
        }

        info!("Broadcast message sent to {}/{} peers", send_count, peers.len());
        
        if !errors.is_empty() && self.config.verbose_logging {
            warn!("Broadcast errors: {:?}", errors);
        }

        Ok(())
    }

    /// Get list of connected peer IDs
    pub async fn get_connected_peers(&self) -> Vec<String> {
        self.connected_peers.read().await.keys().cloned().collect()
    }

    /// Get detailed information about connected peers
    pub async fn get_peer_info(&self, peer_id: &str) -> Option<ConnectedPeer> {
        self.connected_peers.read().await.get(peer_id).cloned()
    }

    /// Get count of connected peers
    pub async fn get_peer_count(&self) -> usize {
        self.connected_peers.read().await.len()
    }

    /// Check if currently scanning
    pub fn is_scanning(&self) -> bool {
        false
    }

    /// Check if currently scanning (async version)
    pub async fn is_scanning_async(&self) -> bool {
        *self.scanning.read().await
    }

    /// Check if currently advertising
    pub fn is_advertising(&self) -> bool {
        false
    }

    /// Check if currently advertising (async version)
    pub async fn is_advertising_async(&self) -> bool {
        *self.advertising.read().await
    }

    /// Check if Bluetooth is available
    pub fn is_available(&self) -> bool {
        self.manager.is_some() && self.adapter.is_some()
    }

    /// Get the event receiver (should be called once)
    pub async fn take_event_receiver(&self) -> Option<mpsc::UnboundedReceiver<BluetoothEvent>> {
        self.event_receiver.lock().await.take()
    }

    /// Stop all operations
    pub async fn stop(&mut self) -> Result<()> {
        info!("Shutting down Bluetooth connection manager");

        // Stop scanning
        self.stop_scanning().await.ok();

        // Disconnect all peers
        let peers: Vec<_> = self.connected_peers.read().await.keys().cloned().collect();
        for peer_id in peers {
            if let Some(peer) = self.connected_peers.write().await.remove(&peer_id) {
                let _ = peer.peripheral.disconnect().await;
            }
        }

        // Stop background tasks
        if let Some(task) = self.cleanup_task.lock().await.take() {
            task.abort();
        }

        *self.advertising.write().await = false;
        self.emit_event(BluetoothEvent::AdvertisingStateChanged { advertising: false });

        info!("Bluetooth connection manager shutdown complete");
        Ok(())
    }

    // Private helper methods...

    /// Start the scan monitoring task
    async fn start_scan_monitoring_task(&self) {
        let adapter = self.adapter.as_ref().unwrap().clone();
        let event_sender = self.event_sender.clone();
        let connected_peers = Arc::clone(&self.connected_peers);
        let config = self.config.clone();

        let task = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_millis(config.scan_interval_ms));
            
            loop {
                interval.tick().await;
                
                match adapter.peripherals().await {
                    Ok(peripherals) => {
                        for peripheral in peripherals {
                            // Check if this is a BitChat device
                            if let Ok(Some(properties)) = peripheral.properties().await {
                                let services = &properties.services;
                                if services.contains(&BITCHAT_SERVICE_UUID) {
                                    let peer_id = peripheral.id().to_string();
                                    
                                    // Skip if already connected
                                    if connected_peers.read().await.contains_key(&peer_id) {
                                        continue;
                                    }

                                    let name = properties.local_name;
                                    let rssi = properties.rssi.unwrap_or(0);

                                    if config.verbose_logging {
                                        debug!("Discovered BitChat device: {} ({})", 
                                               name.as_deref().unwrap_or("Unknown"), &peer_id[..8]);
                                    }

                                    let _ = event_sender.send(BluetoothEvent::PeerDiscovered {
                                        peer_id: peer_id.clone(),
                                        name,
                                        rssi,
                                    });

                                    // Attempt connection if under limit
                                    if connected_peers.read().await.len() < config.max_connections {
                                        Self::attempt_connection(
                                            peripheral,
                                            peer_id,
                                            event_sender.clone(),
                                            Arc::clone(&connected_peers),
                                            config.connection_timeout_secs,
                                            config.verbose_logging,
                                        ).await;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Error getting peripherals: {}", e);
                    }
                }
            }
        });

        *self.scan_task.lock().await = Some(task);
    }

    /// Attempt to connect to a peripheral
    async fn attempt_connection(
        peripheral: Peripheral,
        peer_id: String,
        event_sender: mpsc::UnboundedSender<BluetoothEvent>,
        connected_peers: Arc<RwLock<HashMap<String, ConnectedPeer>>>,
        timeout_secs: u64,
        verbose_logging: bool,
    ) {
        let event_sender_clone = event_sender.clone();
        let connected_peers_clone = Arc::clone(&connected_peers);

        tokio::spawn(async move {
            // Set connection timeout
            let connection_result = tokio::time::timeout(
                Duration::from_secs(timeout_secs),
                Self::connect_to_peripheral(peripheral.clone(), peer_id.clone(), verbose_logging)
            ).await;

            match connection_result {
                Ok(Ok(connected_peer)) => {
                    info!("Successfully connected to peer: {}", &peer_id[..8]);
                    
                    // Add to connected peers
                    connected_peers_clone.write().await.insert(peer_id.clone(), connected_peer);
                    
                    let _ = event_sender_clone.send(BluetoothEvent::PeerConnected { 
                        peer_id: peer_id.clone() 
                    });

                    // Start monitoring this connection
                    Self::monitor_connection(
                        peripheral,
                        peer_id,
                        event_sender_clone,
                        connected_peers_clone,
                        verbose_logging,
                    ).await;
                }
                Ok(Err(e)) => {
                    error!("Failed to connect to peer {}: {}", &peer_id[..8], e);
                    let _ = event_sender_clone.send(BluetoothEvent::PeerError {
                        peer_id,
                        error: e.to_string(),
                    });
                }
                Err(_) => {
                    error!("Connection to peer {} timed out", &peer_id[..8]);
                    let _ = event_sender_clone.send(BluetoothEvent::PeerError {
                        peer_id,
                        error: "Connection timeout".to_string(),
                    });
                }
            }
        });
    }

    /// Connect to a specific peripheral
    async fn connect_to_peripheral(peripheral: Peripheral, peer_id: String, verbose_logging: bool) -> Result<ConnectedPeer> {
        if verbose_logging {
            debug!("Attempting to connect to peripheral: {}", &peer_id[..8]);
        }

        // Connect to the device
        peripheral.connect().await.map_err(|e| {
            anyhow!("Failed to connect to peripheral: {}", e)
        })?;

        // Discover services
        peripheral.discover_services().await.map_err(|e| {
            anyhow!("Failed to discover services: {}", e)
        })?;

        // Find BitChat service and message characteristic
        let services = peripheral.services();
        let bitchat_service = services.iter()
            .find(|s| s.uuid == BITCHAT_SERVICE_UUID)
            .ok_or_else(|| anyhow!("BitChat service not found"))?;

        let message_characteristic = bitchat_service.characteristics.iter()
            .find(|c| c.uuid == MESSAGE_CHARACTERISTIC_UUID)
            .cloned();

        if message_characteristic.is_none() {
            warn!("Message characteristic not found for peer {}", &peer_id[..8]);
        }

        // Get device properties
        let properties = peripheral.properties().await.map_err(|e| {
            anyhow!("Failed to get device properties: {}", e)
        })?.unwrap_or_default();

        let connected_peer = ConnectedPeer {
            id: peer_id,
            peripheral,
            name: properties.local_name,
            rssi: properties.rssi.unwrap_or(0),
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            message_characteristic,
        };

        Ok(connected_peer)
    }

    /// Monitor a connection for incoming messages and disconnections
    async fn monitor_connection(
        peripheral: Peripheral,
        peer_id: String,
        event_sender: mpsc::UnboundedSender<BluetoothEvent>,
        connected_peers: Arc<RwLock<HashMap<String, ConnectedPeer>>>,
        verbose_logging: bool,
    ) {
        // Subscribe to notifications if characteristic supports it
        if let Some(connected_peer) = connected_peers.read().await.get(&peer_id) {
            if let Some(characteristic) = &connected_peer.message_characteristic {
                if characteristic.properties.contains(CharPropFlags::NOTIFY) {
                    if let Err(e) = peripheral.subscribe(characteristic).await {
                        error!("Failed to subscribe to notifications for {}: {}", &peer_id[..8], e);
                    } else if verbose_logging {
                        debug!("Subscribed to notifications for peer: {}", &peer_id[..8]);
                    }
                }
            }
        }

        // Monitor for events
        let mut notification_stream = match peripheral.notifications().await {
            Ok(stream) => stream,
            Err(e) => {
                error!("Failed to get notification stream for peer {}: {}", &peer_id[..8], e);
                return;
            }
        };
        
        loop {
            tokio::select! {
                // Handle notifications (incoming messages) - using next() directly
                notification = notification_stream.next() => {
                    match notification {
                        Some(data) => {
                            // Update last seen
                            if let Some(peer) = connected_peers.write().await.get_mut(&peer_id) {
                                peer.last_seen = Instant::now();
                            }

                            let _ = event_sender.send(BluetoothEvent::MessageReceived {
                                peer_id: peer_id.clone(),
                                data: data.value,
                            });
                        }
                        None => {
                            // Stream ended - peer disconnected
                            break;
                        }
                    }
                }
                
                // Check connection status periodically
                _ = time::sleep(Duration::from_secs(10)) => {
                    if !peripheral.is_connected().await.unwrap_or(false) {
                        break;
                    }
                }
            }
        }

        // Peer disconnected
        info!("Peer disconnected: {}", &peer_id[..8]);
        connected_peers.write().await.remove(&peer_id);
        let _ = event_sender.send(BluetoothEvent::PeerDisconnected { peer_id });
    }

    /// Start the cleanup task for stale connections
    async fn start_cleanup_task(&self) {
        let connected_peers = Arc::clone(&self.connected_peers);
        let event_sender = self.event_sender.clone();
        let cleanup_timeout = self.config.peer_cleanup_timeout_secs;

        let task = tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                let mut to_remove = Vec::new();
                let mut peers = connected_peers.write().await;
                
                for (peer_id, peer) in peers.iter() {
                    // Check if peer hasn't been seen for the cleanup timeout
                    if peer.is_stale(cleanup_timeout) {
                        if !peer.peripheral.is_connected().await.unwrap_or(false) {
                            to_remove.push(peer_id.clone());
                        }
                    }
                }
                
                for peer_id in to_remove {
                    info!("Cleaning up stale peer: {}", &peer_id[..8]);
                    peers.remove(&peer_id);
                    let _ = event_sender.send(BluetoothEvent::PeerDisconnected { peer_id });
                }
            }
        });

        *self.cleanup_task.lock().await = Some(task);
    }

    /// Emit an event
    fn emit_event(&self, event: BluetoothEvent) {
        if let Err(_) = self.event_sender.send(event) {
            // Channel closed - this is fine during shutdown
        }
    }
}

impl Drop for BluetoothConnectionManager {
    fn drop(&mut self) {
        debug!("BluetoothConnectionManager dropped");
    }
}
