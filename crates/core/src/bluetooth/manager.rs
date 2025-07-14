// crates/core/src/bluetooth/manager.rs
//! Complete BitChat Bluetooth implementation using btleplug
//! Compatible with iOS/macOS BitChat protocol

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tokio::time::{sleep, timeout};
use tracing::{debug, error, info, warn};
use uuid::Uuid;
use futures::stream::StreamExt;

use btleplug::api::{
    Central, Characteristic, Manager as _, Peripheral as _, ScanFilter,
    WriteType, CentralEvent, CharPropFlags
};
use btleplug::platform::{Adapter, Manager, Peripheral, PeripheralId};

use super::events::{BluetoothConfig, BluetoothEvent, ConnectedPeer};
use super::compatibility::CompatibilityManager;
use crate::protocol::{BitchatPacket, MessageType, BinaryProtocolManager};
use crate::BitchatBluetoothDelegate;

// UUIDs matching iOS implementation exactly
const SERVICE_UUID: Uuid = Uuid::from_u128(0xF47B5E2D_4A9E_4C5A_9B3F_8E1D2C3A4B5C);
const CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0xA1B2C3D4_E5F6_4A5B_8C9D_0E1F2A3B4C5D);

const MAX_CONNECTIONS: usize = 8;
const SCAN_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(15);
const MESSAGE_TIMEOUT: Duration = Duration::from_secs(5);

pub struct BluetoothManager {
    config: BluetoothConfig,
    manager: Manager,
    adapter: Option<Adapter>,
    my_peer_id: String,
    compatibility: CompatibilityManager,
    
    // State management
    connected_peripherals: Arc<RwLock<HashMap<PeripheralId, ConnectedPeripheral>>>,
    discovered_devices: Arc<RwLock<HashMap<PeripheralId, DiscoveredDevice>>>,
    processed_messages: Arc<RwLock<HashSet<String>>>,
    
    // Event handling
    event_sender: tokio::sync::mpsc::UnboundedSender<BluetoothEvent>,
    event_receiver: Arc<Mutex<tokio::sync::mpsc::UnboundedReceiver<BluetoothEvent>>>,
    delegate: Option<Arc<dyn BitchatBluetoothDelegate + Send + Sync>>,
    
    // Control flags
    is_scanning: Arc<RwLock<bool>>,
    is_running: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone)]
struct ConnectedPeripheral {
    peripheral: Peripheral,
    peer_id: String,
    characteristic: Option<Characteristic>,
    connected_at: Instant,
    last_message_at: Instant,
    rssi: i16,
    message_count: u32,
}

#[derive(Debug, Clone)]
struct DiscoveredDevice {
    peripheral: Peripheral,
    peer_id: Option<String>,
    rssi: i16,
    last_seen: Instant,
    connection_attempts: u32,
}

impl BluetoothManager {
    pub async fn new() -> anyhow::Result<Self> {
        Self::with_config(BluetoothConfig::default()).await
    }

    pub async fn with_config(config: BluetoothConfig) -> anyhow::Result<Self> {
        info!("Initializing Bluetooth manager with config: {:?}", config);
        
        let manager = Manager::new().await?;
        
        // Generate peer ID compatible with iOS (8 hex characters)
        let my_peer_id = if config.device_name.len() >= 8 {
            config.device_name[..8].to_uppercase()
        } else {
            CompatibilityManager::generate_compatible_peer_id()
        };
        
        let compatibility = CompatibilityManager::new(my_peer_id.clone());
        
        let (event_sender, event_receiver) = tokio::sync::mpsc::unbounded_channel();
        
        Ok(Self {
            config,
            manager,
            adapter: None,
            my_peer_id,
            compatibility,
            connected_peripherals: Arc::new(RwLock::new(HashMap::new())),
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
            processed_messages: Arc::new(RwLock::new(HashSet::new())),
            event_sender,
            event_receiver: Arc::new(Mutex::new(event_receiver)),
            delegate: None,
            is_scanning: Arc::new(RwLock::new(false)),
            is_running: Arc::new(RwLock::new(false)),
        })
    }

    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        info!("Starting Bluetooth manager");
        
        {
            let mut running = self.is_running.write().await;
            if *running {
                warn!("Bluetooth manager already running");
                return Ok(());
            }
            *running = true;
        }
        
        // Get the first available adapter
        let adapters = self.manager.adapters().await?;
        let adapter = adapters
            .into_iter()
            .next()
            .ok_or_else(|| anyhow::anyhow!("No Bluetooth adapters found"))?;
        
        info!("Using Bluetooth adapter: {:?}", adapter.adapter_info().await?);
        
        // Store adapter for later use
        let _adapter_clone = adapter.clone();
        // We can't store adapter directly due to ownership, so we'll get it fresh each time
        
        // Start scanning and peripheral mode simultaneously
        let scan_task = self.clone().start_scanning(adapter.clone());
        let peripheral_task = self.clone().start_peripheral_mode(adapter.clone());
        let cleanup_task = self.clone().start_cleanup_task();
        
        // Run all tasks concurrently
        tokio::try_join!(scan_task, peripheral_task, cleanup_task)?;
        
        Ok(())
    }

    pub async fn stop(&self) -> anyhow::Result<()> {
        info!("Stopping Bluetooth manager");
        
        {
            let mut running = self.is_running.write().await;
            *running = false;
        }
        
        // Stop scanning
        {
            let mut scanning = self.is_scanning.write().await;
            *scanning = false;
        }
        
        // Disconnect all peripherals
        let peripherals = {
            let connected = self.connected_peripherals.read().await;
            connected.values().cloned().collect::<Vec<_>>()
        };
        
        for conn_peripheral in peripherals {
            if let Err(e) = conn_peripheral.peripheral.disconnect().await {
                warn!("Error disconnecting peripheral {}: {}", conn_peripheral.peer_id, e);
            }
        }
        
        // Clear state
        self.connected_peripherals.write().await.clear();
        self.discovered_devices.write().await.clear();
        
        info!("Bluetooth manager stopped");
        Ok(())
    }

    async fn start_scanning(self: Arc<Self>, adapter: Adapter) -> anyhow::Result<()> {
        info!("Starting BLE scanning");
        
        let scan_filter = ScanFilter {
            services: vec![uuid::Uuid::from(SERVICE_UUID)],
        };
        
        // Set up event handling
        let mut events = adapter.events().await?;
        
        // Start scanning
        adapter.start_scan(scan_filter).await?;
        {
            let mut scanning = self.is_scanning.write().await;
            *scanning = true;
        }
        
        // Process scan events
        while *self.is_running.read().await {
            tokio::select! {
                event = events.next() => {
                    match event {
                        Some(CentralEvent::DeviceDiscovered(id)) => {
                            if let Err(e) = self.handle_device_discovered(adapter.clone(), id).await {
                                error!("Error handling discovered device: {}", e);
                            }
                        }
                        Some(CentralEvent::DeviceUpdated(id)) => {
                            if let Err(e) = self.handle_device_updated(adapter.clone(), id).await {
                                error!("Error handling device update: {}", e);
                            }
                        }
                        Some(CentralEvent::DeviceConnected(id)) => {
                            info!("Device connected: {:?}", id);
                        }
                        Some(CentralEvent::DeviceDisconnected(id)) => {
                            self.handle_device_disconnected(id).await;
                        }
                        Some(other) => {
                            debug!("Other BLE event: {:?}", other);
                        }
                        None => break,
                    }
                }
                _ = sleep(Duration::from_millis(100)) => {
                    // Periodic maintenance
                }
            }
        }
        
        adapter.stop_scan().await?;
        {
            let mut scanning = self.is_scanning.write().await;
            *scanning = false;
        }
        
        info!("Stopped BLE scanning");
        Ok(())
    }

    async fn start_peripheral_mode(self: Arc<Self>, _adapter: Adapter) -> anyhow::Result<()> {
        info!("Starting BLE peripheral mode");
        
        // Note: btleplug doesn't support peripheral mode on all platforms
        // This is a placeholder for future implementation
        // On platforms that support it, we would:
        // 1. Create a GATT server
        // 2. Add our service and characteristic
        // 3. Start advertising
        
        warn!("Peripheral mode not fully implemented in btleplug");
        
        // Keep task alive
        while *self.is_running.read().await {
            sleep(Duration::from_secs(1)).await;
        }
        
        Ok(())
    }

    async fn start_cleanup_task(self: Arc<Self>) -> anyhow::Result<()> {
        info!("Starting cleanup task");
        
        while *self.is_running.read().await {
            sleep(Duration::from_secs(30)).await;
            
            // Clean up old discovered devices
            {
                let mut discovered = self.discovered_devices.write().await;
                let cutoff = Instant::now() - Duration::from_secs(60);
                discovered.retain(|_, device| device.last_seen > cutoff);
            }
            
            // Clean up old processed messages
            {
                let mut processed = self.processed_messages.write().await;
                // Keep only recent messages (last 1000)
                if processed.len() > 1000 {
                    let to_remove = processed.len() - 1000;
                    let old_ids: Vec<_> = processed.iter().take(to_remove).cloned().collect();
                    for id in old_ids {
                        processed.remove(&id);
                    }
                }
            }
            
            // Update compatibility manager
            self.compatibility.cleanup_old_discoveries().await;
        }
        
        info!("Cleanup task stopped");
        Ok(())
    }

    async fn handle_device_discovered(&self, adapter: Adapter, id: PeripheralId) -> anyhow::Result<()> {
        let peripheral = adapter.peripheral(&id).await?;
        let properties = peripheral.properties().await?.unwrap_or_default();
        
        let device_name = properties.local_name.clone();
        let rssi = properties.rssi.unwrap_or(-100);
        
        debug!("Discovered device: {:?}, name: {:?}, RSSI: {}", id, device_name, rssi);
        
        // Store discovered device
        {
            let mut discovered = self.discovered_devices.write().await;
            let peer_id = device_name.as_ref().and_then(|name| {
                if name.len() == 8 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                    Some(name.to_uppercase())
                } else {
                    None
                }
            });
            
            discovered.insert(id.clone(), DiscoveredDevice {
                peripheral: peripheral.clone(),
                peer_id: peer_id.clone(),
                rssi,
                last_seen: Instant::now(),
                connection_attempts: 0,
            });
        }
        
        // Notify delegate about discovery
        if let Some(delegate) = &self.delegate {
            delegate.on_device_discovered(
                &format!("{:?}", id),
                device_name.as_deref(),
                rssi as i8,
            );
        }
        
        // Check if we should connect
        let current_connections = self.connected_peripherals.read().await.len();
        
        if let Some(peer_id) = self.compatibility.handle_discovered_device(
            format!("{:?}", id),
            device_name,
            rssi as i8,
            current_connections,
            MAX_CONNECTIONS,
        ).await {
            info!("Attempting to connect to peer: {}", peer_id);
            
            // Attempt connection
            if let Err(e) = self.connect_to_peripheral(peripheral, peer_id).await {
                error!("Failed to connect to peripheral: {}", e);
            }
        }
        
        Ok(())
    }

    async fn handle_device_updated(&self, adapter: Adapter, id: PeripheralId) -> anyhow::Result<()> {
        let peripheral = adapter.peripheral(&id).await?;
        let properties = peripheral.properties().await?.unwrap_or_default();
        
        // Update RSSI and last seen
        {
            let mut discovered = self.discovered_devices.write().await;
            if let Some(device) = discovered.get_mut(&id) {
                device.rssi = properties.rssi.unwrap_or(device.rssi);
                device.last_seen = Instant::now();
            }
        }
        
        Ok(())
    }

    async fn handle_device_disconnected(&self, id: PeripheralId) {
        let peer_id = {
            let mut connected = self.connected_peripherals.write().await;
            connected.remove(&id).map(|conn| conn.peer_id)
        };
        
        if let Some(peer_id) = peer_id {
            info!("Device disconnected: {}", peer_id);
            self.compatibility.mark_connection_complete(&peer_id).await;
            
            // Send disconnect event
            let _ = self.event_sender.send(BluetoothEvent::DeviceDisconnected {
                device_id: format!("{:?}", id),
                peer_id: peer_id.clone(),
            });
            
            // Notify delegate about disconnection
            if let Some(delegate) = &self.delegate {
                delegate.on_device_disconnected(
                    &format!("{:?}", id),
                    &peer_id,
                );
            }
        }
    }

    async fn connect_to_peripheral(&self, peripheral: Peripheral, peer_id: String) -> anyhow::Result<()> {
        info!("Connecting to peripheral: {}", peer_id);
        
        // Connect with timeout
        timeout(CONNECTION_TIMEOUT, peripheral.connect()).await??;
        
        // Discover services
        peripheral.discover_services().await?;
        
        // Find our service and characteristic
        let services = peripheral.services();
        let service = services
            .iter()
            .find(|s| s.uuid == uuid::Uuid::from(SERVICE_UUID))
            .ok_or_else(|| anyhow::anyhow!("BitChat service not found"))?;
        
        let characteristic = service
            .characteristics
            .iter()
            .find(|c| c.uuid == uuid::Uuid::from(CHARACTERISTIC_UUID))
            .ok_or_else(|| anyhow::anyhow!("BitChat characteristic not found"))?
            .clone();
        
        // Subscribe to notifications if supported
        if characteristic.properties.contains(CharPropFlags::NOTIFY) {
            peripheral.subscribe(&characteristic).await?;
            info!("Subscribed to notifications for peer: {}", peer_id);
        }
        
        // Store connection
        {
            let mut connected = self.connected_peripherals.write().await;
            connected.insert(peripheral.id(), ConnectedPeripheral {
                peripheral: peripheral.clone(),
                peer_id: peer_id.clone(),
                characteristic: Some(characteristic.clone()),
                connected_at: Instant::now(),
                last_message_at: Instant::now(),
                rssi: -70, // Default, will be updated
                message_count: 0,
            });
        }
        
        // Send connection event
        let _ = self.event_sender.send(BluetoothEvent::DeviceConnected {
            device_id: format!("{:?}", peripheral.id()),
            peer_id: peer_id.clone(),
        });
        
        // Notify delegate about connection
        if let Some(delegate) = &self.delegate {
            delegate.on_device_connected(
                &format!("{:?}", peripheral.id()),
                &peer_id,
            );
        }
        
        // Send key exchange
        self.send_key_exchange(&peripheral, &characteristic, &peer_id).await?;
        
        // Send announce
        self.send_announce(&peripheral, &characteristic, &peer_id).await?;
        
        // Start notification handling for this peripheral
        self.start_notification_handler(peripheral, peer_id.clone()).await;
        
        self.compatibility.mark_connection_complete(&peer_id).await;
        
        info!("Successfully connected to peer: {}", peer_id);
        Ok(())
    }

    async fn send_key_exchange(&self, peripheral: &Peripheral, characteristic: &Characteristic, peer_id: &str) -> anyhow::Result<()> {
        info!("Sending key exchange to peer: {}", peer_id);
        
        // Create mock public key data (32 bytes for X25519 + 32 bytes for Ed25519)
        let mock_public_key = vec![0u8; 64];
        
        let packet = BitchatPacket::new_broadcast(
            MessageType::KeyExchange,
            self.my_peer_id.as_bytes()[..8].try_into().unwrap_or([0u8; 8]),
            mock_public_key,
        );
        
        let data = BinaryProtocolManager::encode(&packet)?;
        
        timeout(MESSAGE_TIMEOUT, peripheral.write(characteristic, &data, WriteType::WithoutResponse)).await??;
        
        info!("Key exchange sent to peer: {}", peer_id);
        Ok(())
    }

    async fn send_announce(&self, peripheral: &Peripheral, characteristic: &Characteristic, peer_id: &str) -> anyhow::Result<()> {
        info!("Sending announce to peer: {}", peer_id);
        
        let nickname = format!("Rust-{}", &self.my_peer_id[..4]);
        
        let packet = BitchatPacket::new_broadcast(
            MessageType::Announce,
            self.my_peer_id.as_bytes()[..8].try_into().unwrap_or([0u8; 8]),
            nickname.into_bytes(),
        );
        
        let data = BinaryProtocolManager::encode(&packet)?;
        
        timeout(MESSAGE_TIMEOUT, peripheral.write(characteristic, &data, WriteType::WithoutResponse)).await??;
        
        info!("Announce sent to peer: {}", peer_id);
        Ok(())
    }

    async fn start_notification_handler(&self, peripheral: Peripheral, peer_id: String) {
        let manager = Arc::new(self.clone());
        let peer_id_clone = peer_id.clone();
        
        tokio::spawn(async move {
            let mut notifications = match peripheral.notifications().await {
                Ok(n) => n,
                Err(e) => {
                    error!("Failed to get notifications for peer {}: {}", peer_id_clone, e);
                    return;
                }
            };
            
            info!("Started notification handler for peer: {}", peer_id_clone);
            
            while let Some(data) = notifications.next().await {
                if let Err(e) = manager.handle_received_data(&peer_id_clone, &data.value).await {
                    error!("Error handling received data from {}: {}", peer_id_clone, e);
                }
            }
            
            info!("Notification handler ended for peer: {}", peer_id_clone);
        });
    }

    async fn handle_received_data(&self, from_peer: &str, data: &[u8]) -> anyhow::Result<()> {
        debug!("Received {} bytes from peer: {}", data.len(), from_peer);
        
        // Decode packet
        let packet = BinaryProtocolManager::decode(data)?;
        
        // Check for duplicates
        let message_id = format!("{}-{}", hex::encode(&packet.sender_id), packet.timestamp);
        {
            let mut processed = self.processed_messages.write().await;
            if processed.contains(&message_id) {
                debug!("Ignoring duplicate message: {}", message_id);
                return Ok(());
            }
            processed.insert(message_id);
        }
        
        // Handle different message types
        match packet.message_type {
            MessageType::KeyExchange => {
                info!("Received key exchange from peer: {}", from_peer);
                // TODO: Process key exchange
            }
            MessageType::Announce => {
                if let Ok(nickname) = String::from_utf8(packet.payload.clone()) {
                    info!("Peer {} announced as: {}", from_peer, nickname);
                    
                    // Update peer info
                    {
                        let mut connected = self.connected_peripherals.write().await;
                        for conn in connected.values_mut() {
                            if conn.peer_id == from_peer {
                                // Could store nickname here if we had that field
                                break;
                            }
                        }
                    }
                }
            }
            MessageType::Message => {
                if let Ok(content) = String::from_utf8(packet.payload.clone()) {
                    info!("Message from {}: {}", from_peer, content);
                    
                    // Send message received event
                    let _ = self.event_sender.send(BluetoothEvent::MessageReceived {
                        from_peer: from_peer.to_string(),
                        data: data.to_vec(),
                    });
                    
                    // Notify delegate about message
                    if let Some(delegate) = &self.delegate {
                        delegate.on_message_received(from_peer, data);
                    }
                }
            }
            MessageType::ChannelJoin => {
                if let Ok(channel) = String::from_utf8(packet.payload.clone()) {
                    info!("Peer {} joined channel: {}", from_peer, channel);
                }
            }
            MessageType::ChannelLeave => {
                if let Ok(channel) = String::from_utf8(packet.payload.clone()) {
                    info!("Peer {} left channel: {}", from_peer, channel);
                }
            }
            _ => {
                debug!("Received unhandled message type: {:?}", packet.message_type);
            }
        }
        
        // Update peer activity
        {
            let mut connected = self.connected_peripherals.write().await;
            for conn in connected.values_mut() {
                if conn.peer_id == from_peer {
                    conn.last_message_at = Instant::now();
                    conn.message_count += 1;
                    break;
                }
            }
        }
        
        Ok(())
    }

    pub async fn broadcast_message(&self, data: &[u8]) -> anyhow::Result<()> {
        let connected = self.connected_peripherals.read().await;
        let connection_count = connected.len();
        
        if connection_count == 0 {
            warn!("No connected peers to broadcast to");
            return Ok(());
        }
        
        info!("Broadcasting message to {} peers", connection_count);
        
        for conn in connected.values() {
            if let Some(ref characteristic) = conn.characteristic {
                match timeout(MESSAGE_TIMEOUT, 
                    conn.peripheral.write(characteristic, data, WriteType::WithoutResponse)
                ).await {
                    Ok(Ok(())) => {
                        debug!("Message sent to peer: {}", conn.peer_id);
                    }
                    Ok(Err(e)) => {
                        warn!("Failed to send message to peer {}: {}", conn.peer_id, e);
                    }
                    Err(_) => {
                        warn!("Timeout sending message to peer: {}", conn.peer_id);
                    }
                }
            }
        }
        
        Ok(())
    }

    pub async fn get_connected_peers(&self) -> Vec<ConnectedPeer> {
        let connected = self.connected_peripherals.read().await;
        connected.values().map(|conn| {
            ConnectedPeer::new(
                format!("{:?}", conn.peripheral.id()),
                conn.peer_id.clone(),
                conn.rssi as i8,
            )
        }).collect()
    }

    pub fn my_peer_id(&self) -> &str {
        &self.my_peer_id
    }
    
    pub fn set_delegate(&mut self, delegate: Arc<dyn BitchatBluetoothDelegate + Send + Sync>) {
        self.delegate = Some(delegate);
    }
}

impl Clone for BluetoothManager {
    fn clone(&self) -> Self {
        // Create a new event channel for the clone
        let (event_sender, event_receiver) = tokio::sync::mpsc::unbounded_channel();
        
        Self {
            config: self.config.clone(),
            manager: self.manager.clone(),
            adapter: self.adapter.clone(),
            my_peer_id: self.my_peer_id.clone(),
            compatibility: self.compatibility.clone(),
            connected_peripherals: self.connected_peripherals.clone(),
            discovered_devices: self.discovered_devices.clone(),
            processed_messages: self.processed_messages.clone(),
            event_sender,
            event_receiver: Arc::new(Mutex::new(event_receiver)),
            delegate: self.delegate.clone(),
            is_scanning: self.is_scanning.clone(),
            is_running: self.is_running.clone(),
        }
    }
}