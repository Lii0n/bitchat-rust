// Create crates/core/src/bluetooth/windows.rs

//! Windows-specific Bluetooth implementation using WinRT APIs
//! Provides full dual-role support (Central + Peripheral) for BitChat mesh networking

#[cfg(windows)]
use windows::{
    core::*,
    Devices::Bluetooth::{
        Advertisement::*,
        GenericAttributeProfile::*,
        BluetoothAdapter, BluetoothDevice, BluetoothLEDevice,
    },
    Foundation::{Collections::*, EventRegistrationToken, TypedEventHandler},
    Storage::Streams::*,
};

use crate::bluetooth::{BluetoothConfig, BluetoothEvent, compatibility::CompatibilityManager};
use crate::protocol::{BitchatPacket, BinaryProtocolManager, peer_utils};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock, Mutex};
use tracing::{debug, info, warn, error};
use uuid::Uuid;

// BitChat service and characteristic UUIDs (must match iOS/Android)
pub const BITCHAT_SERVICE_UUID: Uuid = uuid::uuid!("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");
pub const BITCHAT_CHARACTERISTIC_UUID: Uuid = uuid::uuid!("A1B2C3D4-E5F6-4A5B-8C9D-0E1F2A3B4C5D");

/// Connected peer information
#[derive(Debug, Clone)]
pub struct ConnectedPeer {
    pub peer_id: String,
    pub device: Option<BluetoothLEDevice>,
    pub gatt_session: Option<GattSession>,
    pub characteristic: Option<GattCharacteristic>,
    pub connected_at: Instant,
    pub last_seen: Instant,
    pub rssi: Option<i16>,
}

/// Windows Bluetooth manager with full dual-role support
pub struct WindowsBluetoothManager {
    config: BluetoothConfig,
    compatibility: CompatibilityManager,
    
    // Central role (client side)
    watcher: Option<BluetoothLEAdvertisementWatcher>,
    
    // Peripheral role (server side)
    publisher: Option<BluetoothLEAdvertisementPublisher>,
    gatt_service_provider: Option<GattServiceProvider>,
    characteristic: Option<GattLocalCharacteristic>,
    
    // Connection management
    connected_peers: Arc<RwLock<HashMap<String, ConnectedPeer>>>,
    connection_attempts: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
    discovered_devices: Arc<RwLock<HashMap<String, (BluetoothLEDevice, i16, Instant)>>>,
    
    // Event handling
    event_sender: mpsc::UnboundedSender<BluetoothEvent>,
    _event_receiver: Arc<Mutex<mpsc::UnboundedReceiver<BluetoothEvent>>>,
    
    // Event tokens for cleanup
    watcher_received_token: Option<EventRegistrationToken>,
    characteristic_write_token: Option<EventRegistrationToken>,
    
    // Runtime state
    is_scanning: Arc<RwLock<bool>>,
    is_advertising: Arc<RwLock<bool>>,
}

impl std::fmt::Debug for WindowsBluetoothManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WindowsBluetoothManager")
            .field("config", &self.config)
            .field("compatibility", &"CompatibilityManager")
            .field("is_scanning", &"Arc<RwLock<bool>>")
            .field("is_advertising", &"Arc<RwLock<bool>>")
            .finish()
    }
}

#[cfg(windows)]
impl WindowsBluetoothManager {
    /// Create new Windows Bluetooth manager
    pub async fn new(config: BluetoothConfig) -> Result<Self> {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        // Create compatibility manager
        let peer_id = peer_utils::bytes_to_peer_id_string(&config.peer_id);
        let compatibility = CompatibilityManager::new(peer_id);
        
        info!("Initializing Windows Bluetooth manager with peer ID: {}", compatibility.get_peer_id());
        info!("Advertisement name: {}", compatibility.create_advertisement_name());
        
        Ok(Self {
            config,
            compatibility,
            watcher: None,
            publisher: None,
            gatt_service_provider: None,
            characteristic: None,
            connected_peers: Arc::new(RwLock::new(HashMap::new())),
            connection_attempts: Arc::new(RwLock::new(HashMap::new())),
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            _event_receiver: Arc::new(Mutex::new(event_receiver)),
            watcher_received_token: None,
            characteristic_write_token: None,
            is_scanning: Arc::new(RwLock::new(false)),
            is_advertising: Arc::new(RwLock::new(false)),
        })
    }
    
    /// Start both scanning and advertising
    pub async fn start(&mut self) -> Result<()> {
        info!("Starting Windows Bluetooth dual-role manager...");
        
        // Start peripheral role (advertising + GATT server)
        self.start_peripheral().await?;
        
        // Start central role (scanning + connecting)
        self.start_central().await?;
        
        info!("Windows Bluetooth manager started successfully");
        Ok(())
    }
    
    /// Stop all Bluetooth operations
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping Windows Bluetooth manager...");
        
        self.stop_central().await?;
        self.stop_peripheral().await?;
        self.disconnect_all_peers().await?;
        
        info!("Windows Bluetooth manager stopped");
        Ok(())
    }
    
    /// Start peripheral role (advertising + GATT server)
    async fn start_peripheral(&mut self) -> Result<()> {
        info!("Starting peripheral role (GATT server)...");
        
        // Create GATT service
        self.create_gatt_service().await?;
        
        // Start advertising
        self.start_advertising().await?;
        
        *self.is_advertising.write().await = true;
        info!("Peripheral role started successfully");
        Ok(())
    }
    
    /// Create GATT service and characteristic
    async fn create_gatt_service(&mut self) -> Result<()> {
        // Convert UUID to Windows GUID
        let service_uuid = uuid_to_guid(&BITCHAT_SERVICE_UUID)?;
        let char_uuid = uuid_to_guid(&BITCHAT_CHARACTERISTIC_UUID)?;
        
        // Create GATT service provider
        let service_provider = GattServiceProvider::CreateAsync(&service_uuid)?.await?;
        
        // Create characteristic parameters
        let char_params = GattLocalCharacteristicParameters::new()?;
        char_params.SetCharacteristicProperties(
            GattCharacteristicProperties::Write | 
            GattCharacteristicProperties::Notify |
            GattCharacteristicProperties::WriteWithoutResponse
        )?;
        char_params.SetReadProtectionLevel(GattProtectionLevel::Plain)?;
        char_params.SetWriteProtectionLevel(GattProtectionLevel::Plain)?;
        
        // Create characteristic
        let characteristic = service_provider.Service()?
            .CreateCharacteristicAsync(&char_uuid, &char_params)?.await?;
        
        // Set up write request handler
        let event_sender = self.event_sender.clone();
        let connected_peers = self.connected_peers.clone();
        let compatibility = self.compatibility.clone();
        
        let write_handler = TypedEventHandler::new(move |sender, args| {
            if let (Ok(sender), Ok(args)) = (sender.as_ref(), args.as_ref()) {
                let event_sender = event_sender.clone();
                let connected_peers = connected_peers.clone();
                let compatibility = compatibility.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_characteristic_write_request(
                        sender, args, &event_sender, &connected_peers, &compatibility
                    ).await {
                        error!("Error handling write request: {}", e);
                    }
                });
            }
            Ok(())
        });
        
        let write_token = characteristic.WriteRequested(&write_handler)?;
        self.characteristic_write_token = Some(write_token);
        
        // Start the service
        service_provider.StartAsync()?.await?;
        
        self.gatt_service_provider = Some(service_provider);
        self.characteristic = Some(characteristic.Characteristic()?);
        
        info!("GATT service created successfully");
        Ok(())
    }
    
    /// Start BLE advertising
    async fn start_advertising(&mut self) -> Result<()> {
        let publisher = BluetoothLEAdvertisementPublisher::new()?;
        
        // Create advertisement
        let advertisement = publisher.Advertisement()?;
        
        // Set local name (8-character peer ID)
        let device_name = self.compatibility.create_advertisement_name();
        advertisement.SetLocalName(&HSTRING::from(&device_name))?;
        
        // Add service UUID
        let service_uuid = uuid_to_guid(&BITCHAT_SERVICE_UUID)?;
        advertisement.ServiceUuids()?.Append(&service_uuid)?;
        
        // Set advertisement flags
        advertisement.SetFlags(BluetoothLEAdvertisementFlags::GeneralDiscoverableMode)?;
        
        // Configure publisher
        publisher.SetScanResponse(&advertisement)?;
        
        // Start advertising
        publisher.Start()?;
        
        self.publisher = Some(publisher);
        info!("Started advertising as: {}", device_name);
        Ok(())
    }
    
    /// Start central role (scanning)
    async fn start_central(&mut self) -> Result<()> {
        info!("Starting central role (scanning)...");
        
        let watcher = BluetoothLEAdvertisementWatcher::new()?;
        
        // Set scan filter
        let service_uuid = uuid_to_guid(&BITCHAT_SERVICE_UUID)?;
        watcher.ScanningMode()?.SetTo(BluetoothLEScanningMode::Active)?;
        watcher.ServiceUuids()?.Append(&service_uuid)?;
        
        // Set up advertisement received handler
        let event_sender = self.event_sender.clone();
        let discovered_devices = self.discovered_devices.clone();
        let connected_peers = self.connected_peers.clone();
        let connection_attempts = self.connection_attempts.clone();
        let compatibility = self.compatibility.clone();
        let config = self.config.clone();
        
        let received_handler = TypedEventHandler::new(move |sender, args| {
            if let (Ok(_sender), Ok(args)) = (sender.as_ref(), args.as_ref()) {
                let event_sender = event_sender.clone();
                let discovered_devices = discovered_devices.clone();
                let connected_peers = connected_peers.clone();
                let connection_attempts = connection_attempts.clone();
                let compatibility = compatibility.clone();
                let config = config.clone();
                
                tokio::spawn(async move {
                    if let Err(e) = Self::handle_advertisement_received(
                        args, &event_sender, &discovered_devices, &connected_peers,
                        &connection_attempts, &compatibility, &config
                    ).await {
                        error!("Error handling advertisement: {}", e);
                    }
                });
            }
            Ok(())
        });
        
        let received_token = watcher.Received(&received_handler)?;
        self.watcher_received_token = Some(received_token);
        
        // Start scanning
        watcher.Start()?;
        
        self.watcher = Some(watcher);
        *self.is_scanning.write().await = true;
        
        info!("Started scanning for BitChat devices");
        Ok(())
    }
    
    /// Handle advertisement received
    async fn handle_advertisement_received(
        args: &BluetoothLEAdvertisementReceivedEventArgs,
        event_sender: &mpsc::UnboundedSender<BluetoothEvent>,
        discovered_devices: &Arc<RwLock<HashMap<String, (BluetoothLEDevice, i16, Instant)>>>,
        connected_peers: &Arc<RwLock<HashMap<String, ConnectedPeer>>>,
        connection_attempts: &Arc<RwLock<HashMap<String, (u32, Instant)>>>,
        compatibility: &CompatibilityManager,
        config: &BluetoothConfig,
    ) -> Result<()> {
        let device_address = args.BluetoothAddress()?;
        let device_id = format!("{:012X}", device_address);
        let local_name = args.LocalName()?.to_string();
        let rssi = args.RawSignalStrengthInDBm()?;
        
        debug!("Advertisement received: {} ({}), RSSI: {} dBm", 
               local_name, device_id, rssi);
        
        // Filter by RSSI threshold
        if rssi < config.rssi_threshold {
            debug!("Signal too weak: {} dBm", rssi);
            return Ok(());
        }
        
        // Extract peer ID from local name
        let peer_id = match peer_utils::extract_peer_id_from_device_name(&local_name) {
            Some(id) => id,
            None => {
                debug!("No valid peer ID in device name: {}", local_name);
                return Ok(());
            }
        };
        
        // Get Bluetooth LE device
        let ble_device = BluetoothLEDevice::FromBluetoothAddressAsync(device_address)?.await?;
        
        // Store discovered device
        {
            let mut discovered = discovered_devices.write().await;
            discovered.insert(device_id.clone(), (ble_device.clone(), rssi, Instant::now()));
        }
        
        // Send discovery event
        let _ = event_sender.send(BluetoothEvent::DeviceDiscovered {
            device_id: device_id.clone(),
            peer_id: Some(peer_id.clone()),
            device_name: Some(local_name),
            rssi,
        });
        
        // Check connection limits
        let current_connections = connected_peers.read().await.len();
        
        // Use compatibility manager to decide on connection
        if let Some(decided_peer_id) = compatibility.handle_discovered_device(
            device_id.clone(),
            Some(local_name),
            rssi as i8,
            current_connections,
            config.max_connections,
        ).await {
            // Attempt connection
            Self::attempt_connection(
                ble_device,
                decided_peer_id,
                connection_attempts,
                connected_peers,
                event_sender,
            ).await;
        }
        
        Ok(())
    }
    
    /// Attempt connection to a peer
    async fn attempt_connection(
        ble_device: BluetoothLEDevice,
        peer_id: String,
        connection_attempts: &Arc<RwLock<HashMap<String, (u32, Instant)>>>,
        connected_peers: &Arc<RwLock<HashMap<String, ConnectedPeer>>>,
        event_sender: &mpsc::UnboundedSender<BluetoothEvent>,
    ) {
        // Check retry limits
        {
            let attempts = connection_attempts.read().await;
            if let Some((count, last_attempt)) = attempts.get(&peer_id) {
                if *count >= 3 && last_attempt.elapsed() < Duration::from_secs(60) {
                    debug!("Retry limit reached for {}", peer_id);
                    return;
                }
            }
        }
        
        info!("Attempting connection to peer: {}", peer_id);
        
        // Update attempt counter
        {
            let mut attempts = connection_attempts.write().await;
            let (count, _) = attempts.get(&peer_id).unwrap_or(&(0, Instant::now()));
            attempts.insert(peer_id.clone(), (count + 1, Instant::now()));
        }
        
        // Attempt GATT connection
        match Self::connect_to_device(&ble_device, &peer_id).await {
            Ok((gatt_session, characteristic)) => {
                info!("Successfully connected to {}", peer_id);
                
                // Store connected peer
                let peer = ConnectedPeer {
                    peer_id: peer_id.clone(),
                    device: Some(ble_device),
                    gatt_session: Some(gatt_session),
                    characteristic: Some(characteristic),
                    connected_at: Instant::now(),
                    last_seen: Instant::now(),
                    rssi: None,
                };
                
                {
                    let mut peers = connected_peers.write().await;
                    peers.insert(peer_id.clone(), peer);
                }
                
                let _ = event_sender.send(BluetoothEvent::PeerConnected { peer_id });
            }
            Err(e) => {
                warn!("Failed to connect to {}: {}", peer_id, e);
                let _ = event_sender.send(BluetoothEvent::ConnectionFailed {
                    peer_id,
                    error: e.to_string(),
                });
            }
        }
    }
    
    /// Connect to a Bluetooth LE device and set up GATT
    async fn connect_to_device(
        ble_device: &BluetoothLEDevice,
        peer_id: &str,
    ) -> Result<(GattSession, GattCharacteristic)> {
        // Connect GATT session
        let gatt_session = GattSession::FromDeviceIdAsync(&ble_device.DeviceId()?)?.await?;
        
        // Get GATT services
        let service_uuid = uuid_to_guid(&BITCHAT_SERVICE_UUID)?;
        let services_result = ble_device.GetGattServicesForUuidAsync(&service_uuid)?.await?;
        
        if services_result.Status()? != GattCommunicationStatus::Success {
            return Err(anyhow!("Failed to get GATT services"));
        }
        
        let services = services_result.Services()?;
        if services.Size()? == 0 {
            return Err(anyhow!("No BitChat service found"));
        }
        
        let service = services.GetAt(0)?;
        
        // Get characteristics
        let char_uuid = uuid_to_guid(&BITCHAT_CHARACTERISTIC_UUID)?;
        let chars_result = service.GetCharacteristicsForUuidAsync(&char_uuid)?.await?;
        
        if chars_result.Status()? != GattCommunicationStatus::Success {
            return Err(anyhow!("Failed to get characteristics"));
        }
        
        let characteristics = chars_result.Characteristics()?;
        if characteristics.Size()? == 0 {
            return Err(anyhow!("No BitChat characteristic found"));
        }
        
        let characteristic = characteristics.GetAt(0)?;
        
        // Subscribe to notifications if supported
        let properties = characteristic.CharacteristicProperties()?;
        if properties & GattCharacteristicProperties::Notify != GattCharacteristicProperties::None {
            let status = characteristic.WriteClientCharacteristicConfigurationDescriptorAsync(
                GattClientCharacteristicConfigurationDescriptorValue::Notify
            )?.await?;
            
            if status != GattCommunicationStatus::Success {
                warn!("Failed to subscribe to notifications for {}", peer_id);
            }
        }
        
        info!("Successfully set up GATT connection to {}", peer_id);
        Ok((gatt_session, characteristic))
    }
    
    /// Handle characteristic write request (from central devices)
    async fn handle_characteristic_write_request(
        _characteristic: &GattLocalCharacteristic,
        args: &GattWriteRequestedEventArgs,
        event_sender: &mpsc::UnboundedSender<BluetoothEvent>,
        connected_peers: &Arc<RwLock<HashMap<String, ConnectedPeer>>>,
        _compatibility: &CompatibilityManager,
    ) -> Result<()> {
        let request = args.GetRequestAsync()?.await?;
        let value = request.Value()?;
        
        // Read data from buffer
        let data = read_buffer_data(&value)?;
        
        // Parse BitChat packet
        match BinaryProtocolManager::decode(&data) {
            Ok(packet) => {
                let sender_peer_id = peer_utils::bytes_to_peer_id_string(&packet.sender_id);
                
                debug!("Received packet from {}: {:?}", sender_peer_id, packet.message_type);
                
                // Update last seen time
                {
                    let mut peers = connected_peers.write().await;
                    if let Some(peer) = peers.get_mut(&sender_peer_id) {
                        peer.last_seen = Instant::now();
                    }
                }
                
                // Send packet received event
                let _ = event_sender.send(BluetoothEvent::PacketReceived {
                    peer_id: sender_peer_id,
                    packet,
                });
                
                // Respond with success
                request.Respond(GattRequestState::Success)?;
            }
            Err(e) => {
                warn!("Failed to parse packet: {}", e);
                request.Respond(GattRequestState::ProtocolError)?;
            }
        }
        
        Ok(())
    }
    
    /// Send packet to specific peer
    pub async fn send_packet(&self, peer_id: &str, packet: &BitchatPacket) -> Result<()> {
        let peers = self.connected_peers.read().await;
        let peer = peers.get(peer_id)
            .ok_or_else(|| anyhow!("Peer {} not connected", peer_id))?;
        
        let characteristic = peer.characteristic.as_ref()
            .ok_or_else(|| anyhow!("No characteristic for peer {}", peer_id))?;
        
        // Encode packet
        let data = BinaryProtocolManager::encode(packet)?;
        
        // Create data buffer
        let buffer = create_data_buffer(&data)?;
        
        // Send data
        let result = characteristic.WriteValueWithOptionAsync(
            &buffer,
            GattWriteOption::WriteWithoutResponse
        )?.await?;
        
        if result != GattCommunicationStatus::Success {
            return Err(anyhow!("Failed to send packet to {}: {:?}", peer_id, result));
        }
        
        debug!("Sent packet to {}: {:?}", peer_id, packet.message_type);
        Ok(())
    }
    
    /// Send packet to all connected peers
    pub async fn broadcast_packet(&self, packet: &BitchatPacket) -> Result<()> {
        let peers = self.connected_peers.read().await;
        
        for (peer_id, _) in peers.iter() {
            if let Err(e) = self.send_packet(peer_id, packet).await {
                warn!("Failed to send to {}: {}", peer_id, e);
            }
        }
        
        Ok(())
    }
    
    /// Get list of connected peers
    pub async fn get_connected_peers(&self) -> Vec<String> {
        self.connected_peers.read().await.keys().cloned().collect()
    }
    
    /// Stop central role
    async fn stop_central(&mut self) -> Result<()> {
        if let Some(watcher) = &self.watcher {
            watcher.Stop()?;
        }
        
        if let Some(token) = self.watcher_received_token.take() {
            if let Some(watcher) = &self.watcher {
                watcher.RemoveReceived(&token)?;
            }
        }
        
        self.watcher = None;
        *self.is_scanning.write().await = false;
        
        info!("Stopped central role");
        Ok(())
    }
    
    /// Stop peripheral role
    async fn stop_peripheral(&mut self) -> Result<()> {
        if let Some(publisher) = &self.publisher {
            publisher.Stop()?;
        }
        
        if let Some(token) = self.characteristic_write_token.take() {
            if let Some(characteristic) = &self.characteristic {
                characteristic.RemoveWriteRequested(&token)?;
            }
        }
        
        self.publisher = None;
        self.gatt_service_provider = None;
        self.characteristic = None;
        *self.is_advertising.write().await = false;
        
        info!("Stopped peripheral role");
        Ok(())
    }
    
    /// Disconnect all peers
    async fn disconnect_all_peers(&self) -> Result<()> {
        let peers = self.connected_peers.read().await;
        
        for (peer_id, peer) in peers.iter() {
            if let Some(session) = &peer.gatt_session {
                if let Err(e) = session.Close() {
                    warn!("Failed to close GATT session for {}: {}", peer_id, e);
                }
            }
        }
        
        Ok(())
    }
    
    /// Get debug information
    pub async fn get_debug_info(&self) -> String {
        let connected = self.connected_peers.read().await;
        let discovered = self.discovered_devices.read().await;
        let compatibility_info = self.compatibility.get_debug_info().await;
        
        format!(
            "Windows Bluetooth Manager Status:\n\
             ==============================\n\
             Scanning: {}\n\
             Advertising: {}\n\
             Connected Peers: {}\n\
             Discovered Devices: {}\n\
             \n\
             Connected Peers:\n\
             {}\n\
             \n\
             {}",
            *self.is_scanning.read().await,
            *self.is_advertising.read().await,
            connected.len(),
            discovered.len(),
            connected.keys().collect::<Vec<_>>().join(", "),
            compatibility_info
        )
    }
}

// Helper functions for Windows API conversion

#[cfg(windows)]
fn uuid_to_guid(uuid: &Uuid) -> Result<windows::core::GUID> {
    let bytes = uuid.as_bytes();
    Ok(windows::core::GUID::from_values(
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]),
        [bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]],
    ))
}

#[cfg(windows)]
fn create_data_buffer(data: &[u8]) -> Result<IBuffer> {
    let writer = DataWriter::new()?;
    writer.WriteBytes(data)?;
    Ok(writer.DetachBuffer()?)
}

#[cfg(windows)]
fn read_buffer_data(buffer: &IBuffer) -> Result<Vec<u8>> {
    let reader = DataReader::FromBuffer(buffer)?;
    let length = buffer.Length()? as usize;
    let mut data = vec![0u8; length];
    reader.ReadBytes(&mut data)?;
    Ok(data)
}

#[cfg(windows)]
impl crate::bluetooth::BluetoothManagerTrait for WindowsBluetoothManager {
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
}

// Stub for non-Windows platforms
#[cfg(not(windows))]
pub struct WindowsBluetoothManager;

#[cfg(not(windows))]
impl WindowsBluetoothManager {
    pub async fn new(_config: BluetoothConfig) -> Result<Self> {
        Err(anyhow!("Windows Bluetooth manager only available on Windows"))
    }
}