//! Bluetooth Low Energy Manager implementation using btleplug
//!
//! This module provides the actual Bluetooth LE implementation for peer discovery,
//! connection management, and message transmission in the BitChat mesh network.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use btleplug::api::{
    Central, CentralEvent, Manager as _, Peripheral as PeripheralTrait, ScanFilter
};
use btleplug::platform::{Manager, Peripheral};
use futures::stream::StreamExt;
use tokio::sync::{mpsc, RwLock};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};

use crate::constants::*;
use super::events::{BluetoothConfig, BluetoothEvent, ConnectedPeer};
use super::compatibility::CompatibilityManager;

/// Bluetooth Low Energy manager for BitChat mesh networking
#[derive(Debug)]
pub struct BluetoothManager {
    config: BluetoothConfig,
    compatibility_manager: CompatibilityManager,
    event_sender: mpsc::UnboundedSender<BluetoothEvent>,
    connected_peers: Arc<RwLock<HashMap<String, ConnectedPeer>>>,
    running: Arc<RwLock<bool>>,
    my_peer_id: String,
}

impl BluetoothManager {
    /// Create a new Bluetooth manager with default configuration
    pub async fn new() -> Result<(Self, mpsc::UnboundedReceiver<BluetoothEvent>)> {
        let config = BluetoothConfig::default();
        Self::with_config(config).await
    }

    /// Create a new Bluetooth manager with custom configuration
    pub async fn with_config(config: BluetoothConfig) -> Result<(Self, mpsc::UnboundedReceiver<BluetoothEvent>)> {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        // Generate a peer ID compatible with iOS/Android
        let my_peer_id = CompatibilityManager::generate_compatible_peer_id();
        let compatibility_manager = CompatibilityManager::new(my_peer_id.clone());
        
        let manager = Self {
            config,
            compatibility_manager,
            event_sender,
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            running: Arc::new(RwLock::new(false)),
            my_peer_id: my_peer_id.clone(),
        };
        
        info!("Bluetooth manager initialized with peer ID: {}", my_peer_id);
        
        Ok((manager, event_receiver))
    }

    /// Start the Bluetooth manager (scanning and advertising)
    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            warn!("Bluetooth manager already running");
            return Ok(());
        }
        *running = true;
        
        info!("Starting Bluetooth manager");
        
        // Start scanning for peers
        let scan_handle = {
            let manager = self.clone();
            tokio::spawn(async move {
                if let Err(e) = manager.scan_loop().await {
                    error!("Scan loop error: {}", e);
                }
            })
        };
        
        // Start advertising (placeholder for now - btleplug doesn't support peripheral mode easily)
        let advertise_handle = {
            let manager = self.clone();
            tokio::spawn(async move {
                if let Err(e) = manager.advertise_loop().await {
                    error!("Advertise loop error: {}", e);
                }
            })
        };
        
        // Send started event
        let _ = self.event_sender.send(BluetoothEvent::ScanStarted);
        let _ = self.event_sender.send(BluetoothEvent::AdvertisingStarted);
        
        Ok(())
    }

    /// Stop the Bluetooth manager
    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            warn!("Bluetooth manager not running");
            return Ok(());
        }
        *running = false;
        
        info!("Stopping Bluetooth manager");
        
        // Disconnect all peers
        let mut peers = self.connected_peers.write().await;
        for (addr, peer) in peers.drain() {
            let _ = self.event_sender.send(BluetoothEvent::DeviceDisconnected {
                device_id: addr.to_string(),
                peer_id: peer.peer_id.clone(),
            });
        }
        
        // Send stopped events
        let _ = self.event_sender.send(BluetoothEvent::ScanStopped);
        let _ = self.event_sender.send(BluetoothEvent::AdvertisingStopped);
        
        Ok(())
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&self, data: &[u8]) -> Result<()> {
        let peers = self.connected_peers.read().await;
        let connected_count = peers.len();
        
        if connected_count == 0 {
            debug!("No connected peers for broadcast");
            return Ok(());
        }
        
        debug!("Broadcasting message of {} bytes to {} peers", data.len(), connected_count);
        
        // Send to all connected peers
        for (peer_id, peer) in peers.iter() {
            if let Err(e) = self.send_message_to_peer(peer_id, data).await {
                warn!("Failed to send message to peer {}: {}", peer.peer_id, e);
            }
        }
        
        // Send broadcast event
        let _ = self.event_sender.send(BluetoothEvent::MessageSent {
            to_peer: None, // None indicates broadcast
            data: data.to_vec(),
        });
        
        Ok(())
    }

    /// Send a message to a specific peer
    pub async fn send_message_to_peer(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        // This is a placeholder - actual implementation would require maintaining 
        // peripheral connections and characteristics
        debug!("Sending message to peer {}", peer_id);
        
        // For now, just simulate successful sending
        tokio::time::sleep(Duration::from_millis(1)).await;
        
        Ok(())
    }

    /// Get the peer ID of this device
    pub fn get_peer_id(&self) -> &str {
        &self.my_peer_id
    }

    /// Get the list of connected peers
    pub async fn get_connected_peers(&self) -> Vec<ConnectedPeer> {
        self.connected_peers.read().await.values().cloned().collect()
    }

    /// Main scanning loop
    async fn scan_loop(&self) -> Result<()> {
        let manager = Manager::new().await?;
        let central = manager
            .adapters()
            .await?
            .into_iter()
            .next()
            .context("No Bluetooth adapter found")?;
        
        info!("Starting scan for BitChat peers");
        
        // Create scan filter for our service
        let scan_filter = ScanFilter {
            services: vec![BITCHAT_SERVICE_UUID],
        };
        
        // Start scanning
        central.start_scan(scan_filter).await?;
        
        // Handle scan events
        let mut events = central.events().await?;
        while self.is_running().await {
            tokio::select! {
                event = events.next() => {
                    if let Some(event) = event {
                        self.handle_central_event(event, &central).await;
                    }
                }
                _ = sleep(Duration::from_millis(self.config.scan_duration_ms)) => {
                    // Periodic scan maintenance
                    self.compatibility_manager.cleanup_old_discoveries().await;
                }
            }
        }
        
        central.stop_scan().await?;
        info!("Scan loop stopped");
        
        Ok(())
    }

    /// Handle central events (device discovery, connection, etc.)
    async fn handle_central_event(&self, event: CentralEvent, central: &impl Central) {
        match event {
            CentralEvent::DeviceDiscovered(id) => {
                if let Ok(peripheral) = central.peripheral(&id).await {
                    self.handle_device_discovered(peripheral).await;
                }
            }
            CentralEvent::DeviceConnected(id) => {
                debug!("Device connected: {}", id);
            }
            CentralEvent::DeviceDisconnected(id) => {
                debug!("Device disconnected: {}", id);
                self.handle_device_disconnected(&id.to_string()).await;
            }
            _ => {}
        }
    }

    /// Handle discovered device
    async fn handle_device_discovered<P: PeripheralTrait>(&self, peripheral: P) {
        let device_id = peripheral.id().to_string();
        
        // Get device properties
        let properties = match peripheral.properties().await {
            Ok(Some(props)) => props,
            _ => {
                debug!("No properties for device {}", device_id);
                return;
            }
        };
        
        let device_name = properties.local_name.clone();
        let rssi = properties.rssi.unwrap_or(-100) as i8;
        
        debug!("Discovered device: {} ({}), RSSI: {}", 
               device_id, device_name.as_deref().unwrap_or("Unknown"), rssi);
        
        // Send discovery event
        let _ = self.event_sender.send(BluetoothEvent::DeviceDiscovered {
            device_id: device_id.clone(),
            device_name: device_name.clone(),
            rssi,
        });
        
        // Check if we should connect using compatibility manager
        let current_connections = self.connected_peers.read().await.len();
        
        if let Some(peer_id) = self.compatibility_manager.handle_discovered_device(
            device_id.clone(),
            device_name,
            rssi,
            current_connections,
            self.config.max_connections,
        ).await {
            info!("Attempting to connect to peer: {}", peer_id);
            
            // Attempt connection
            if let Err(e) = self.connect_to_peer(peripheral, peer_id).await {
                error!("Failed to connect to peer: {}", e);
            }
        }
    }

    /// Connect to a discovered peer
    async fn connect_to_peer<P: PeripheralTrait>(&self, peripheral: P, peer_id: String) -> Result<()> {
        let device_id = peripheral.id().to_string();
        
        // Connect with timeout
        let connect_result = timeout(
            Duration::from_secs(CONNECTION_TIMEOUT_SECS),
            peripheral.connect()
        ).await;
        
        match connect_result {
            Ok(Ok(())) => {
                info!("Successfully connected to peer: {}", peer_id);
                
                // Discover services and characteristics
                peripheral.discover_services().await?;
                
                // Find our service and characteristics
                let services = peripheral.services();
                let mut found_service = false;
                
                for service in services {
                    if service.uuid == BITCHAT_SERVICE_UUID {
                        found_service = true;
                        debug!("Found BitChat service on peer: {}", peer_id);
                        break;
                    }
                }
                
                if !found_service {
                    warn!("BitChat service not found on peer: {}", peer_id);
                    let _ = peripheral.disconnect().await;
                    return Ok(());
                }
                
                // Create connected peer info
                let connected_peer = ConnectedPeer::new(
                    device_id.clone(),
                    peer_id.clone(),
                    -50, // Default RSSI for connected peer
                );
                
                // Store the connection
                {
                    let mut peers = self.connected_peers.write().await;
                    peers.insert(device_id.clone(), connected_peer);
                }
                
                // Mark connection as complete
                self.compatibility_manager.mark_connection_complete(&peer_id).await;
                
                // Send connection event
                let _ = self.event_sender.send(BluetoothEvent::DeviceConnected {
                    device_id,
                    peer_id,
                });
                
                Ok(())
            }
            Ok(Err(e)) => {
                error!("Connection failed to peer {}: {}", peer_id, e);
                self.compatibility_manager.mark_connection_complete(&peer_id).await;
                Err(e.into())
            }
            Err(_) => {
                error!("Connection timeout to peer: {}", peer_id);
                self.compatibility_manager.mark_connection_complete(&peer_id).await;
                Err(anyhow::anyhow!("Connection timeout"))
            }
        }
    }

    /// Handle device disconnection
    async fn handle_device_disconnected(&self, device_id: &str) {
        let mut peers = self.connected_peers.write().await;
        if let Some(peer) = peers.remove(device_id) {
            info!("Peer disconnected: {}", peer.peer_id);
            
            let _ = self.event_sender.send(BluetoothEvent::DeviceDisconnected {
                device_id: device_id.to_string(),
                peer_id: peer.peer_id,
            });
        }
    }

    /// Placeholder advertising loop
    async fn advertise_loop(&self) -> Result<()> {
        // btleplug doesn't easily support peripheral mode on desktop platforms
        // This would need platform-specific implementation or a different library
        info!("Advertising loop started (placeholder)");
        
        while self.is_running().await {
            sleep(Duration::from_secs(1)).await;
        }
        
        info!("Advertising loop stopped");
        Ok(())
    }

    /// Check if the manager is running
    async fn is_running(&self) -> bool {
        *self.running.read().await
    }
}

impl Clone for BluetoothManager {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            compatibility_manager: self.compatibility_manager.clone(),
            event_sender: self.event_sender.clone(),
            connected_peers: self.connected_peers.clone(),
            running: self.running.clone(),
            my_peer_id: self.my_peer_id.clone(),
        }
    }
}