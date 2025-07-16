//! Unified BitChat Bluetooth Manager
//! 
//! Consolidates the duplicated functionality between manager.rs and windows.rs
//! into a shared core with platform-specific adapters. This eliminates code
//! duplication while maintaining optimal platform-specific implementations.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{debug, error, info, warn};
use anyhow::{Result, anyhow};

use crate::bluetooth::{BluetoothConfig, compatibility::CompatibilityManager, constants};
use crate::protocol::{BitchatPacket, BinaryProtocolManager};
use crate::events::{EventSender, BluetoothEvent, ProtocolEvent, ConnectionType, DisconnectionReason}; // NEW: Unified events

// Import centralized constants
use constants::{service_uuids, connection, scanning, peer_id};

// ============================================================================
// SHARED DATA STRUCTURES
// ============================================================================

/// Connected peer information (shared across all platforms)
#[derive(Debug, Clone)]
pub struct ConnectedPeer {
    pub peer_id: String,
    pub connected_at: Instant,
    pub last_seen: Instant,
    pub rssi: Option<i16>,
    pub message_count: u32,
    pub platform_data: PlatformPeerData,
}

/// Platform-specific peer connection data
#[derive(Debug, Clone)]
pub enum PlatformPeerData {
    #[cfg(windows)]
    Windows {
        device: Option<windows::Devices::Bluetooth::BluetoothLEDevice>,
        gatt_session: Option<windows::Devices::Bluetooth::GenericAttributeProfile::GattSession>,
        characteristic: Option<windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristic>,
    },
    #[cfg(not(windows))]
    Btleplug {
        peripheral: btleplug::platform::Peripheral,
        characteristic: Option<btleplug::api::Characteristic>,
    },
}

/// Discovered device information (shared across all platforms)
#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub device_id: String,
    pub peer_id: Option<String>,
    pub rssi: i16,
    pub last_seen: Instant,
    pub connection_attempts: u32,
    pub platform_data: PlatformDeviceData,
}

/// Platform-specific discovered device data
#[derive(Debug, Clone)]
pub enum PlatformDeviceData {
    #[cfg(windows)]
    Windows {
        device: windows::Devices::Bluetooth::BluetoothLEDevice,
    },
    #[cfg(not(windows))]
    Btleplug {
        peripheral: btleplug::platform::Peripheral,
        peripheral_id: btleplug::platform::PeripheralId,
    },
}

// ============================================================================
// PLATFORM ADAPTER TRAIT
// ============================================================================

/// Platform-specific Bluetooth adapter interface
/// 
/// This trait abstracts the platform differences between Windows WinRT APIs
/// and cross-platform btleplug, allowing the core logic to be shared.
#[async_trait::async_trait]
pub trait PlatformBluetoothAdapter: Send + Sync {
    /// Initialize the platform-specific Bluetooth adapter
    async fn initialize(&mut self) -> Result<()>;
    
    /// Start scanning for BitChat devices
    async fn start_scanning(&mut self) -> Result<()>;
    
    /// Stop scanning
    async fn stop_scanning(&mut self) -> Result<()>;
    
    /// Start advertising as a BitChat device
    async fn start_advertising(&mut self, advertisement_data: &[u8]) -> Result<()>;
    
    /// Stop advertising
    async fn stop_advertising(&mut self) -> Result<()>;
    
    /// Connect to a discovered device
    async fn connect_to_device(&mut self, device: &DiscoveredDevice) -> Result<ConnectedPeer>;
    
    /// Disconnect from a peer
    async fn disconnect_from_peer(&mut self, peer: &ConnectedPeer) -> Result<()>;
    
    /// Send data to a connected peer
    async fn send_to_peer(&self, peer: &ConnectedPeer, data: &[u8]) -> Result<()>;
    
    /// Check if adapter is available
    async fn is_available(&self) -> bool;
    
    /// Get platform-specific debug information
    async fn get_platform_debug_info(&self) -> String;
}

// ============================================================================
// UNIFIED BLUETOOTH MANAGER
// ============================================================================

/// Unified Bluetooth manager that works across all platforms
/// 
/// This replaces both manager.rs and windows.rs with a single implementation
/// that uses platform-specific adapters for the low-level operations.
pub struct BluetoothManager {
    // Configuration and identity
    config: BluetoothConfig,
    my_peer_id: String,
    compatibility: CompatibilityManager,
    
    // Platform adapter
    adapter: Box<dyn PlatformBluetoothAdapter>,
    
    // Shared state management (common across all platforms)
    connected_peers: Arc<RwLock<HashMap<String, ConnectedPeer>>>,
    discovered_devices: Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
    connection_attempts: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
    processed_messages: Arc<RwLock<HashSet<String>>>,
    
    // Event handling - NEW: Unified event system
    event_sender: EventSender,
    
    // Runtime state
    is_scanning: Arc<RwLock<bool>>,
    is_advertising: Arc<RwLock<bool>>,
    is_running: Arc<RwLock<bool>>,
}

impl BluetoothManager {
    /// Create new Bluetooth manager with default configuration
    pub async fn new() -> Result<Self> {
        Self::with_config(BluetoothConfig::default()).await
    }
    
    /// Create Bluetooth manager with custom configuration
    pub async fn with_config(config: BluetoothConfig, event_sender: EventSender) -> Result<Self> {
        info!("Initializing unified Bluetooth manager with config: {:?}", config);
        
        // Generate peer ID compatible with iOS/Android (4-byte lowercase hex)
        let my_peer_id = if config.device_name.len() == peer_id::PEER_ID_STRING_LENGTH &&
                             peer_id::is_valid_peer_id_string(&config.device_name) {
            config.device_name.clone()
        } else {
            peer_id::generate_random_peer_id()
        };
        
        // Create compatibility manager
        let compatibility = CompatibilityManager::new(my_peer_id.clone());
        
        // Create platform-specific adapter
        let adapter = Self::create_platform_adapter(&config).await?;
        
        info!("Bluetooth manager initialized with peer ID: {}", my_peer_id);
        
        Ok(Self {
            config,
            my_peer_id,
            compatibility,
            adapter,
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
            connection_attempts: Arc::new(RwLock::new(HashMap::new())),
            processed_messages: Arc::new(RwLock::new(HashSet::new())),
            event_sender, // NEW: Use provided event sender
            is_scanning: Arc::new(RwLock::new(false)),
            is_advertising: Arc::new(RwLock::new(false)),
            is_running: Arc::new(RwLock::new(false)),
        })
    }
    
    /// Create platform-appropriate adapter
    async fn create_platform_adapter(config: &BluetoothConfig) -> Result<Box<dyn PlatformBluetoothAdapter>> {
        #[cfg(windows)]
        {
            let adapter = WindowsBluetoothAdapter::new(config.clone()).await?;
            Ok(Box::new(adapter))
        }
        
        #[cfg(not(windows))]
        {
            let adapter = BtleplugAdapter::new(config.clone()).await?;
            Ok(Box::new(adapter))
        }
    }
    
    /// Start Bluetooth operations (scanning and advertising)
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting unified Bluetooth manager...");
        
        // Check if already running
        {
            let mut running = self.is_running.write().await;
            if *running {
                warn!("Bluetooth manager already running");
                return Ok(());
            }
            *running = true;
        }
        
        // Send adapter state change event
        self.event_sender.send_bluetooth(BluetoothEvent::AdapterStateChanged {
            powered_on: true,
            scanning: false,
            advertising: false,
        })?;
        
        // Initialize platform adapter
        self.adapter.initialize().await?;
        
        // Start scanning and advertising concurrently
        let scan_task = self.start_scanning_internal();
        let advertising_task = self.start_advertising_internal();
        let cleanup_task = self.start_cleanup_task();
        
        tokio::try_join!(scan_task, advertising_task, cleanup_task)?;
        
        info!("Unified Bluetooth manager started successfully");
        Ok(())
    }
    
    /// Stop all Bluetooth operations
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping unified Bluetooth manager...");
        
        // Mark as not running
        *self.is_running.write().await = false;
        
        // Stop scanning and advertising
        self.adapter.stop_scanning().await?;
        self.adapter.stop_advertising().await?;
        
        *self.is_scanning.write().await = false;
        *self.is_advertising.write().await = false;
        
        // Send adapter state change event
        self.event_sender.send_bluetooth(BluetoothEvent::AdapterStateChanged {
            powered_on: false,
            scanning: false,
            advertising: false,
        })?;
        
        // Disconnect all peers
        self.disconnect_all_peers().await?;
        
        info!("Unified Bluetooth manager stopped");
        Ok(())
    }
    
    /// Start scanning for BitChat devices
    async fn start_scanning_internal(&mut self) -> Result<()> {
        info!("Starting device scanning...");
        
        *self.is_scanning.write().await = true;
        self.adapter.start_scanning().await?;
        
        // Send adapter state change event
        self.event_sender.send_bluetooth(BluetoothEvent::AdapterStateChanged {
            powered_on: true,
            scanning: true,
            advertising: *self.is_advertising.read().await,
        })?;
        
        // Start scan management loop
        let manager = Arc::new(self);
        tokio::spawn(async move {
            manager.scan_management_loop().await;
        });
        
        Ok(())
    }
    
    /// Start advertising as BitChat device
    async fn start_advertising_internal(&mut self) -> Result<()> {
        info!("Starting device advertising...");
        
        // Create advertisement data with peer ID
        let advertisement_data = self.create_advertisement_data();
        
        *self.is_advertising.write().await = true;
        self.adapter.start_advertising(&advertisement_data).await?;
        
        // Send adapter state change event
        self.event_sender.send_bluetooth(BluetoothEvent::AdapterStateChanged {
            powered_on: true,
            scanning: *self.is_scanning.read().await,
            advertising: true,
        })?;
        
        Ok(())
    }
    
    /// Create advertisement data containing our peer ID
    fn create_advertisement_data(&self) -> Vec<u8> {
        // Create BitChat advertisement packet
        // Format: Service UUID (16 bytes) + Peer ID (4 bytes) + Flags (1 byte)
        let mut data = Vec::new();
        
        // Add service UUID
        data.extend_from_slice(service_uuids::BITCHAT_SERVICE.as_bytes());
        
        // Add our peer ID
        if let Ok(peer_bytes) = peer_id::string_to_bytes(&self.my_peer_id) {
            data.extend_from_slice(&peer_bytes);
        }
        
        // Add flags (version info, capabilities, etc.)
        data.push(0x01); // Version 1
        
        data
    }
    
    /// Scan management loop (handles discovered devices)
    async fn scan_management_loop(self: Arc<Self>) {
        let mut scan_interval = tokio::time::interval(scanning::SCAN_INTERVAL);
        
        while *self.is_running.read().await {
            scan_interval.tick().await;
            
            // Process discovered devices and attempt connections
            if let Err(e) = self.process_discovered_devices().await {
                error!("Error processing discovered devices: {}", e);
                let _ = self.event_sender.send_error(&format!("Error processing discovered devices: {}", e), Some("scan_management"));
            }
            
            // Clean up old discovered devices
            self.cleanup_discovered_devices().await;
        }
    }
    
    /// Process discovered devices and attempt connections
    async fn process_discovered_devices(&self) -> Result<()> {
        let discovered = self.discovered_devices.read().await.clone();
        let connected = self.connected_peers.read().await;
        
        for (device_id, device) in discovered {
            // Skip if already connected
            if let Some(peer_id) = &device.peer_id {
                if connected.contains_key(peer_id) {
                    continue;
                }
                
                // Check if we should connect based on compatibility rules
                if !self.compatibility.should_initiate_connection(peer_id) {
                    continue;
                }
            }
            
            // Check connection limits
            if connected.len() >= connection::MAX_CONNECTIONS {
                continue;
            }
            
            // Check RSSI threshold
            if device.rssi < connection::RSSI_THRESHOLD {
                continue;
            }
            
            // Attempt connection
            if let Err(e) = self.attempt_connection(&device).await {
                warn!("Failed to connect to device {}: {}", device_id, e);
            }
        }
        
        Ok(())
    }
    
    /// Attempt connection to a discovered device
    async fn attempt_connection(&self, device: &DiscoveredDevice) -> Result<()> {
        debug!("Attempting connection to device: {}", device.device_id);
        
        // Check retry limits
        {
            let mut attempts = self.connection_attempts.write().await;
            let (retry_count, last_attempt) = attempts
                .entry(device.device_id.clone())
                .or_insert((0, Instant::now()));
            
            if *retry_count >= connection::MAX_RETRY_ATTEMPTS {
                return Err(anyhow!("Max retry attempts reached"));
            }
            
            if last_attempt.elapsed() < connection::RETRY_BACKOFF {
                return Err(anyhow!("Still in retry backoff period"));
            }
            
            *retry_count += 1;
            *last_attempt = Instant::now();
        }
        
        // Attempt platform-specific connection
        match self.adapter.connect_to_device(device).await {
            Ok(peer) => {
                info!("Successfully connected to peer: {}", peer.peer_id);
                
                // Store connected peer
                self.connected_peers.write().await.insert(peer.peer_id.clone(), peer.clone());
                
                // Send connection event - NEW: Unified event
                self.event_sender.send_bluetooth(BluetoothEvent::PeerConnected {
                    peer_id: peer.peer_id.clone(),
                    device_id: device.device_id.clone(),
                    connection_type: ConnectionType::Outgoing,
                    rssi: peer.rssi,
                })?;
                
                // Clear retry attempts
                self.connection_attempts.write().await.remove(&device.device_id);
                
                Ok(())
            }
            Err(e) => {
                warn!("Connection failed to {}: {}", device.device_id, e);
                
                // Send connection failed event - NEW: Unified event
                self.event_sender.send_bluetooth(BluetoothEvent::ConnectionFailed {
                    device_id: device.device_id.clone(),
                    peer_id: device.peer_id.clone(),
                    error: e.to_string(),
                    retry_count: self.connection_attempts.read().await.get(&device.device_id).map(|(c, _)| *c).unwrap_or(0),
                })?;
                
                Err(e)
            }
        }
    }
    
    /// Handle device discovered event - NEW: Unified event handling
    pub async fn handle_device_discovered(&self, device: DiscoveredDevice) -> Result<()> {
        // Send device discovered event
        self.event_sender.send_bluetooth(BluetoothEvent::DeviceDiscovered {
            device_id: device.device_id.clone(),
            device_name: None, // Platform adapters can provide this
            peer_id: device.peer_id.clone(),
            rssi: device.rssi,
            advertisement_data: None,
        })?;
        
        // Store discovered device
        self.discovered_devices.write().await.insert(device.device_id.clone(), device);
        
        Ok(())
    }
    
    /// Handle incoming data - NEW: Unified event handling
    pub async fn handle_data_received(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        debug!("Received {} bytes from peer: {}", data.len(), peer_id);
        
        // Send raw data received event
        self.event_sender.send_bluetooth(BluetoothEvent::DataReceived {
            peer_id: peer_id.to_string(),
            data: data.to_vec(),
        })?;
        
        // Try to decode packet
        match BinaryProtocolManager::decode(data) {
            Ok(packet) => {
                // Check for duplicates
                let message_id = format!("{}-{}", hex::encode(&packet.sender_id), packet.timestamp);
                {
                    let mut processed = self.processed_messages.write().await;
                    if processed.contains(&message_id) {
                        debug!("Ignoring duplicate message: {}", message_id);
                        
                        // Send duplicate message event
                        self.event_sender.send_protocol(ProtocolEvent::DuplicateMessage {
                            message_id,
                            peer_id: peer_id.to_string(),
                        })?;
                        
                        return Ok(());
                    }
                    processed.insert(message_id);
                }
                
                // Send packet received event - NEW: Unified event
                self.event_sender.send_protocol(ProtocolEvent::PacketReceived {
                    peer_id: peer_id.to_string(),
                    packet,
                })?;
                
            }
            Err(e) => {
                warn!("Failed to decode packet from {}: {}", peer_id, e);
                
                // Send packet decode failed event
                self.event_sender.send_protocol(ProtocolEvent::PacketDecodeFailed {
                    peer_id: peer_id.to_string(),
                    data_size: data.len(),
                    error: e.to_string(),
                })?;
            }
        }
        
        Ok(())
    }
    
    /// Disconnect all connected peers
    async fn disconnect_all_peers(&self) -> Result<()> {
        let peers = self.connected_peers.read().await.clone();
        
        for (peer_id, peer) in peers {
            if let Err(e) = self.adapter.disconnect_from_peer(&peer).await {
                warn!("Failed to disconnect from {}: {}", peer_id, e);
                let _ = self.event_sender.send_error(&format!("Failed to disconnect from {}: {}", peer_id, e), Some("disconnect_all"));
            } else {
                // Send disconnection event
                let _ = self.event_sender.send_bluetooth(BluetoothEvent::PeerDisconnected {
                    peer_id: peer_id.clone(),
                    device_id: "unknown".to_string(), // Platform adapters should provide this
                    reason: DisconnectionReason::UserInitiated,
                });
            }
        }
        
        self.connected_peers.write().await.clear();
        Ok(())
    }
    
    /// Cleanup task for old connections and devices
    async fn start_cleanup_task(&self) -> Result<()> {
        let manager = Arc::new(self);
        tokio::spawn(async move {
            manager.cleanup_loop().await;
        });
        Ok(())
    }
    
    /// Cleanup loop
    async fn cleanup_loop(self: Arc<Self>) {
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(30));
        
        while *self.is_running.read().await {
            cleanup_interval.tick().await;
            
            self.cleanup_discovered_devices().await;
            self.cleanup_stale_connections().await;
        }
    }
    
    /// Remove old discovered devices
    async fn cleanup_discovered_devices(&self) {
        let mut discovered = self.discovered_devices.write().await;
        let cutoff = Instant::now() - Duration::from_secs(300); // 5 minutes
        
        discovered.retain(|_, device| device.last_seen > cutoff);
    }
    
    /// Remove stale connections
    async fn cleanup_stale_connections(&self) {
        let mut connected = self.connected_peers.write().await;
        let cutoff = Instant::now() - connection::KEEPALIVE_INTERVAL * 3;
        
        connected.retain(|peer_id, peer| {
            if peer.last_seen < cutoff {
                warn!("Removing stale connection to {}", peer_id);
                
                // Send disconnection event for stale connection
                let _ = self.event_sender.send_bluetooth(BluetoothEvent::PeerDisconnected {
                    peer_id: peer_id.clone(),
                    device_id: "unknown".to_string(),
                    reason: DisconnectionReason::Timeout,
                });
                
                false
            } else {
                true
            }
        });
    }
    
    /// Send packet to specific peer
    pub async fn send_packet(&self, peer_id: &str, packet: &BitchatPacket) -> Result<()> {
        let connected = self.connected_peers.read().await;
        let peer = connected.get(peer_id)
            .ok_or_else(|| anyhow!("Peer {} not connected", peer_id))?;
        
        // Encode packet
        let data = BinaryProtocolManager::encode(packet)?;
        
        // Send via platform adapter
        match self.adapter.send_to_peer(peer, &data).await {
            Ok(()) => {
                // Send packet sent event
                self.event_sender.send_protocol(ProtocolEvent::PacketSent {
                    peer_id: peer_id.to_string(),
                    packet_type: format!("{:?}", packet.message_type),
                    size: data.len(),
                })?;
                Ok(())
            }
            Err(e) => {
                // Send data send failed event
                self.event_sender.send_bluetooth(BluetoothEvent::DataSendFailed {
                    peer_id: peer_id.to_string(),
                    error: e.to_string(),
                })?;
                Err(e)
            }
        }
    }
    
    /// Broadcast packet to all connected peers
    pub async fn broadcast_packet(&self, packet: &BitchatPacket) -> Result<()> {
        let connected = self.connected_peers.read().await;
        let data = BinaryProtocolManager::encode(packet)?;
        
        for (peer_id, peer) in connected.iter() {
            match self.adapter.send_to_peer(peer, &data).await {
                Ok(()) => {
                    // Send packet sent event
                    let _ = self.event_sender.send_protocol(ProtocolEvent::PacketSent {
                        peer_id: peer_id.to_string(),
                        packet_type: format!("{:?}", packet.message_type),
                        size: data.len(),
                    });
                }
                Err(e) => {
                    warn!("Failed to send packet to {}: {}", peer_id, e);
                    // Send data send failed event
                    let _ = self.event_sender.send_bluetooth(BluetoothEvent::DataSendFailed {
                        peer_id: peer_id.to_string(),
                        error: e.to_string(),
                    });
                }
            }
        }
        
        Ok(())
    }
    
    /// Get list of connected peer IDs
    pub async fn get_connected_peers(&self) -> Vec<String> {
        self.connected_peers.read().await.keys().cloned().collect()
    }
    
    /// Get our peer ID
    pub fn get_our_peer_id(&self) -> String {
        self.my_peer_id.clone()
    }
    
    /// Check if Bluetooth is available
    pub async fn is_available(&self) -> bool {
        self.adapter.is_available().await
    }
    
    /// Get comprehensive debug information
    pub async fn get_debug_info(&self) -> String {
        let connected = self.connected_peers.read().await;
        let discovered = self.discovered_devices.read().await;
        let compatibility_info = self.compatibility.get_debug_info().await;
        let platform_info = self.adapter.get_platform_debug_info().await;
        
        format!(
            "Unified BitChat Bluetooth Manager Status:\n\
             ==========================================\n\
             Platform: {}\n\
             Our Peer ID: {}\n\
             Running: {}\n\
             Scanning: {}\n\
             Advertising: {}\n\
             Connected Peers: {}\n\
             Discovered Devices: {}\n\
             \n\
             Connected Peers:\n\
             {}\n\
             \n\
             Compatibility Manager:\n\
             {}\n\
             \n\
             Platform-Specific Info:\n\
             {}",
            crate::bluetooth::get_platform_info(),
            self.my_peer_id,
            *self.is_running.read().await,
            *self.is_scanning.read().await,
            *self.is_advertising.read().await,
            connected.len(),
            discovered.len(),
            connected.keys().cloned().collect::<Vec<_>>().join(", "),
            compatibility_info,
            platform_info
        )
    }
}

// Implement the trait for the unified manager
#[async_trait::async_trait]
impl crate::bluetooth::BluetoothManagerTrait for BluetoothManager {
    async fn start(&mut self) -> Result<()> {
        self.start().await
    }
    
    async fn stop(&mut self) -> Result<()> {
        self.stop().await
    }
    
    async fn send_packet(&self, peer_id: &str, packet: &BitchatPacket) -> Result<()> {
        self.send_packet(peer_id, packet).await
    }
    
    async fn broadcast_packet(&self, packet: &BitchatPacket) -> Result<()> {
        self.broadcast_packet(packet).await
    }
    
    async fn get_connected_peers(&self) -> Vec<String> {
        self.get_connected_peers().await
    }
    
    async fn get_debug_info(&self) -> String {
        self.get_debug_info().await
    }
    
    async fn is_available(&self) -> bool {
        self.is_available().await
    }
    
    fn get_our_peer_id(&self) -> String {
        self.get_our_peer_id()
    }
}

// ============================================================================
// PLATFORM-SPECIFIC ADAPTERS
// ============================================================================

// Windows WinRT Adapter
#[cfg(windows)]
mod windows_adapter;
#[cfg(windows)]
pub use windows_adapter::WindowsBluetoothAdapter;

// Cross-platform btleplug Adapter  
#[cfg(not(windows))]
mod btleplug_adapter;
#[cfg(not(windows))]
pub use btleplug_adapter::BtleplugAdapter;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_manager_creation() {
        let config = BluetoothConfig::default();
        let event_bus = crate::events::EventBus::new();
        let event_sender = event_bus.create_sender("test");
        
        let manager = BluetoothManager::with_config(config, event_sender).await;
        
        // Should create successfully (actual Bluetooth may not be available in test)
        assert!(manager.is_ok() || manager.unwrap_err().to_string().contains("Bluetooth"));
    }
    
    #[test]
    fn test_peer_id_format() {
        let config = BluetoothConfig::default();
        assert!(peer_id::is_valid_peer_id_string(&config.device_name));
        assert_eq!(config.device_name.len(), peer_id::PEER_ID_STRING_LENGTH);
    }
}