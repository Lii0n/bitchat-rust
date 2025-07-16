//! Windows-specific Bluetooth adapter using WinRT APIs
//! 
//! This module implements the PlatformBluetoothAdapter trait for Windows
//! using native WinRT APIs for optimal performance and full feature support.

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

use super::{PlatformBluetoothAdapter, ConnectedPeer, DiscoveredDevice, PlatformPeerData, PlatformDeviceData};
use crate::{BluetoothConfig, constants::service_uuids};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tracing::{debug, info, warn, error};

/// Windows Bluetooth adapter using WinRT APIs
#[cfg(windows)]
pub struct WindowsBluetoothAdapter {
    config: BluetoothConfig,
    
    // Central role (client/scanner)
    watcher: Option<BluetoothLEAdvertisementWatcher>,
    watcher_received_token: Option<EventRegistrationToken>,
    
    // Peripheral role (server/advertiser)
    publisher: Option<BluetoothLEAdvertisementPublisher>,
    gatt_service_provider: Option<GattServiceProvider>,
    characteristic: Option<GattLocalCharacteristic>,
    characteristic_write_token: Option<EventRegistrationToken>,
    
    // Device tracking
    discovered_devices: Arc<RwLock<HashMap<String, (BluetoothLEDevice, i16)>>>,
    
    // Event notifications
    device_discovered_sender: Option<mpsc::UnboundedSender<DiscoveredDevice>>,
}

#[cfg(windows)]
impl WindowsBluetoothAdapter {
    /// Create new Windows Bluetooth adapter
    pub async fn new(config: BluetoothConfig) -> Result<Self> {
        info!("Creating Windows Bluetooth adapter");
        
        Ok(Self {
            config,
            watcher: None,
            watcher_received_token: None,
            publisher: None,
            gatt_service_provider: None,
            characteristic: None,
            characteristic_write_token: None,
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
            device_discovered_sender: None,
        })
    }
    
    /// Set up GATT service for peripheral role
    async fn setup_gatt_service(&mut self) -> Result<()> {
        info!("Setting up GATT service...");
        
        // Convert UUID to Windows GUID
        let service_uuid = uuid_to_guid(&service_uuids::BITCHAT_SERVICE)?;
        let char_uuid = uuid_to_guid(&service_uuids::BITCHAT_CHARACTERISTIC)?;
        
        // Create GATT service provider
        let service_provider = GattServiceProvider::CreateAsync(&service_uuid)?.await?;
        
        // Create characteristic parameters
        let char_params = GattLocalCharacteristicParameters::new()?;
        char_params.SetCharacteristicProperties(
            GattCharacteristicProperties::Write | 
            GattCharacteristicProperties::Notify |
            GattCharacteristicProperties::WriteWithoutResponse
        )?;
        
        // Set permissions
        char_params.SetWriteProtectionLevel(GattProtectionLevel::Plain)?;
        
        // Create the characteristic
        let characteristic_result = service_provider.Service()?
            .CreateCharacteristicAsync(&char_uuid, &char_params)?.await?;
        
        if characteristic_result.Error() != BluetoothError::Success {
            return Err(anyhow!("Failed to create characteristic: {:?}", characteristic_result.Error()));
        }
        
        let characteristic = characteristic_result.Characteristic()?;
        
        // Set up write request handler
        let write_handler = TypedEventHandler::new({
            let sender = self.device_discovered_sender.clone();
            move |_: &Option<GattLocalCharacteristic>, args: &Option<GattWriteRequestedEventArgs>| {
                if let Some(args) = args {
                    if let Err(e) = Self::handle_write_request(args, sender.as_ref()) {
                        error!("Error handling write request: {}", e);
                    }
                }
                Ok(())
            }
        });
        
        let write_token = characteristic.WriteRequested(&write_handler)?;
        
        // Start the service
        let start_result = service_provider.StartAsync()?.await?;
        if start_result.Error() != BluetoothError::Success {
            return Err(anyhow!("Failed to start GATT service: {:?}", start_result.Error()));
        }
        
        self.gatt_service_provider = Some(service_provider);
        self.characteristic = Some(characteristic);
        self.characteristic_write_token = Some(write_token);
        
        info!("GATT service started successfully");
        Ok(())
    }
    
    /// Handle incoming write requests on our characteristic
    fn handle_write_request(
        args: &GattWriteRequestedEventArgs,
        _sender: Option<&mpsc::UnboundedSender<DiscoveredDevice>>
    ) -> Result<()> {
        let deferral = args.GetDeferral()?;
        
        // Get the request
        let request = args.Request()?;
        let value = request.Value()?;
        
        // Read the data
        let data = read_buffer_data(&value)?;
        debug!("Received {} bytes from peer", data.len());
        
        // TODO: Process the received packet and send to main manager
        // This would integrate with the unified manager's packet processing
        
        // Respond with success
        request.Respond(GattRequestState::Succeeded)?;
        deferral.Complete()?;
        
        Ok(())
    }
    
    /// Set up advertisement watcher for central role
    async fn setup_watcher(&mut self) -> Result<()> {
        info!("Setting up advertisement watcher...");
        
        let watcher = BluetoothLEAdvertisementWatcher::new()?;
        
        // Set scan mode for active scanning
        watcher.SetScanningMode(BluetoothLEScanningMode::Active)?;
        
        // Filter for BitChat service UUID
        let service_uuid = uuid_to_guid(&service_uuids::BITCHAT_SERVICE)?;
        watcher.ServiceUuids()?.Append(&service_uuid)?;
        
        // Set up received handler
        let received_handler = TypedEventHandler::new({
            let devices = self.discovered_devices.clone();
            let sender = self.device_discovered_sender.clone();
            move |_: &Option<BluetoothLEAdvertisementWatcher>, args: &Option<BluetoothLEAdvertisementReceivedEventArgs>| {
                if let Some(args) = args {
                    if let Err(e) = Self::handle_advertisement_received(args, &devices, sender.as_ref()) {
                        error!("Error handling advertisement: {}", e);
                    }
                }
                Ok(())
            }
        });
        
        let received_token = watcher.Received(&received_handler)?;
        
        self.watcher = Some(watcher);
        self.watcher_received_token = Some(received_token);
        
        info!("Advertisement watcher set up successfully");
        Ok(())
    }
    
    /// Handle received advertisement
    fn handle_advertisement_received(
        args: &BluetoothLEAdvertisementReceivedEventArgs,
        devices: &Arc<RwLock<HashMap<String, (BluetoothLEDevice, i16)>>>,
        sender: Option<&mpsc::UnboundedSender<DiscoveredDevice>>
    ) -> Result<()> {
        let address = args.BluetoothAddress()?;
        let rssi = args.RawSignalStrengthInDBm()?;
        let device_id = format!("{:012X}", address);
        
        debug!("Discovered BitChat device: {} (RSSI: {})", device_id, rssi);
        
        // Extract peer ID from advertisement data
        let peer_id = Self::extract_peer_id_from_advertisement(args)?;
        
        // Create discovered device
        let discovered = DiscoveredDevice {
            device_id: device_id.clone(),
            peer_id,
            rssi,
            last_seen: std::time::Instant::now(),
            connection_attempts: 0,
            platform_data: PlatformDeviceData::Windows {
                device: BluetoothLEDevice::FromBluetoothAddressAsync(address)?.get()?,
            },
        };
        
        // Store in discovered devices
        tokio::spawn(async move {
            if let PlatformDeviceData::Windows { device } = &discovered.platform_data {
                devices.write().await.insert(device_id, (device.clone(), rssi));
            }
        });
        
        // Notify main manager
        if let Some(sender) = sender {
            let _ = sender.send(discovered);
        }
        
        Ok(())
    }
    
    /// Extract peer ID from advertisement data
    fn extract_peer_id_from_advertisement(args: &BluetoothLEAdvertisementReceivedEventArgs) -> Result<Option<String>> {
        let advertisement = args.Advertisement()?;
        let local_name = advertisement.LocalName()?;
        
        // Check if local name contains peer ID (format: "BC_a1b2c3d4")
        if let Ok(name) = local_name.to_string() {
            if name.starts_with("BC_") && name.len() == 11 {
                let peer_id = &name[3..];
                if crate::bluetooth::constants::peer_id::is_valid_peer_id_string(peer_id) {
                    return Ok(Some(peer_id.to_string()));
                }
            }
        }
        
        // Try to extract from service data
        let service_data = advertisement.ServiceData()?;
        for i in 0..service_data.Size()? {
            let data_entry = service_data.GetAt(i)?;
            let uuid = data_entry.Key()?;
            
            // Check if this is our service UUID
            if uuid == uuid_to_guid(&service_uuids::BITCHAT_SERVICE)? {
                let data_buffer = data_entry.Value()?;
                let data = read_buffer_data(&data_buffer)?;
                
                // Extract peer ID from service data (first 4 bytes after service UUID)
                if data.len() >= 4 {
                    let peer_bytes: [u8; 4] = data[0..4].try_into().unwrap();
                    let peer_id = crate::bluetooth::constants::peer_id::bytes_to_string(&peer_bytes);
                    return Ok(Some(peer_id));
                }
            }
        }
        
        Ok(None)
    }
}

#[cfg(windows)]
#[async_trait::async_trait]
impl PlatformBluetoothAdapter for WindowsBluetoothAdapter {
    async fn initialize(&mut self) -> Result<()> {
        info!("Initializing Windows Bluetooth adapter...");
        
        // Check if Bluetooth is available
        let adapter = BluetoothAdapter::GetDefaultAsync()?.await?;
        if adapter.IsLowEnergySupported()? != true {
            return Err(anyhow!("Bluetooth Low Energy not supported"));
        }
        
        // Set up GATT service for peripheral role
        self.setup_gatt_service().await?;
        
        // Set up watcher for central role
        self.setup_watcher().await?;
        
        info!("Windows Bluetooth adapter initialized successfully");
        Ok(())
    }
    
    async fn start_scanning(&mut self) -> Result<()> {
        info!("Starting BLE scanning...");
        
        if let Some(watcher) = &self.watcher {
            watcher.Start()?;
            info!("BLE scanning started");
        } else {
            return Err(anyhow!("Watcher not initialized"));
        }
        
        Ok(())
    }
    
    async fn stop_scanning(&mut self) -> Result<()> {
        info!("Stopping BLE scanning...");
        
        if let Some(watcher) = &self.watcher {
            watcher.Stop()?;
            info!("BLE scanning stopped");
        }
        
        Ok(())
    }
    
    async fn start_advertising(&mut self, advertisement_data: &[u8]) -> Result<()> {
        info!("Starting BLE advertising...");
        
        let publisher = BluetoothLEAdvertisementPublisher::new()?;
        let advertisement = publisher.Advertisement()?;
        
        // Set local name with peer ID
        let device_name = format!("BC_{}", 
            &String::from_utf8_lossy(&advertisement_data[16..20]).chars()
                .map(|c| format!("{:02x}", c as u8))
                .collect::<String>()[..8]
        );
        advertisement.SetLocalName(&HSTRING::from(device_name))?;
        
        // Add service UUID
        let service_uuid = uuid_to_guid(&service_uuids::BITCHAT_SERVICE)?;
        advertisement.ServiceUuids()?.Append(&service_uuid)?;
        
        // Add service data with peer ID
        let service_data = advertisement.ServiceData()?;
        let data_buffer = create_data_buffer(&advertisement_data[16..20])?; // Peer ID bytes
        let service_data_entry = BluetoothLEAdvertisementDataSection::Create(
            BluetoothLEAdvertisementDataTypes::ServiceData128BitUuids(),
            &data_buffer
        )?;
        service_data.Append(&service_data_entry)?;
        
        // Start advertising
        publisher.Start()?;
        
        self.publisher = Some(publisher);
        info!("BLE advertising started");
        Ok(())
    }
    
    async fn stop_advertising(&mut self) -> Result<()> {
        info!("Stopping BLE advertising...");
        
        if let Some(publisher) = &self.publisher {
            publisher.Stop()?;
            info!("BLE advertising stopped");
        }
        
        Ok(())
    }
    
    async fn connect_to_device(&mut self, device: &DiscoveredDevice) -> Result<ConnectedPeer> {
        info!("Connecting to device: {}", device.device_id);
        
        let ble_device = if let PlatformDeviceData::Windows { device } = &device.platform_data {
            device.clone()
        } else {
            return Err(anyhow!("Invalid platform data for Windows adapter"));
        };
        
        // Connect to GATT server
        let gatt_result = ble_device.GetGattServicesForUuidAsync(
            &uuid_to_guid(&service_uuids::BITCHAT_SERVICE)?
        )?.await?;
        
        if gatt_result.Status()? != GattCommunicationStatus::Success {
            return Err(anyhow!("Failed to connect to GATT services"));
        }
        
        let services = gatt_result.Services()?;
        if services.Size()? == 0 {
            return Err(anyhow!("No BitChat services found"));
        }
        
        let service = services.GetAt(0)?;
        
        // Get the characteristic
        let char_result = service.GetCharacteristicsForUuidAsync(
            &uuid_to_guid(&service_uuids::BITCHAT_CHARACTERISTIC)?
        )?.await?;
        
        if char_result.Status()? != GattCommunicationStatus::Success {
            return Err(anyhow!("Failed to get characteristics"));
        }
        
        let characteristics = char_result.Characteristics()?;
        if characteristics.Size()? == 0 {
            return Err(anyhow!("No BitChat characteristics found"));
        }
        
        let characteristic = characteristics.GetAt(0)?;
        
        // Create GATT session
        let session = GattSession::FromDeviceIdAsync(&ble_device.DeviceId()?)?.await?;
        
        let peer = ConnectedPeer {
            peer_id: device.peer_id.clone().unwrap_or_else(|| device.device_id.clone()),
            connected_at: std::time::Instant::now(),
            last_seen: std::time::Instant::now(),
            rssi: Some(device.rssi),
            message_count: 0,
            platform_data: PlatformPeerData::Windows {
                device: Some(ble_device),
                gatt_session: Some(session),
                characteristic: Some(characteristic),
            },
        };
        
        info!("Successfully connected to peer: {}", peer.peer_id);
        Ok(peer)
    }
    
    async fn disconnect_from_peer(&mut self, peer: &ConnectedPeer) -> Result<()> {
        info!("Disconnecting from peer: {}", peer.peer_id);
        
        if let PlatformPeerData::Windows { gatt_session, .. } = &peer.platform_data {
            if let Some(session) = gatt_session {
                session.Close()?;
            }
        }
        
        info!("Disconnected from peer: {}", peer.peer_id);
        Ok(())
    }
    
    async fn send_to_peer(&self, peer: &ConnectedPeer, data: &[u8]) -> Result<()> {
        debug!("Sending {} bytes to peer: {}", data.len(), peer.peer_id);
        
        if let PlatformPeerData::Windows { characteristic, .. } = &peer.platform_data {
            if let Some(char) = characteristic {
                let buffer = create_data_buffer(data)?;
                let result = char.WriteValueAsync(&buffer)?.await?;
                
                if result != GattCommunicationStatus::Success {
                    return Err(anyhow!("Failed to send data: {:?}", result));
                }
                
                debug!("Successfully sent data to peer: {}", peer.peer_id);
                Ok(())
            } else {
                Err(anyhow!("No characteristic available for peer"))
            }
        } else {
            Err(anyhow!("Invalid platform data for Windows adapter"))
        }
    }
    
    async fn is_available(&self) -> bool {
        // Check if Bluetooth adapter is available and powered on
        match BluetoothAdapter::GetDefaultAsync() {
            Ok(future) => {
                match future.await {
                    Ok(adapter) => {
                        adapter.IsLowEnergySupported().unwrap_or(false)
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        }
    }
    
    async fn get_platform_debug_info(&self) -> String {
        let discovered_count = self.discovered_devices.read().await.len();
        
        format!(
            "Windows WinRT Bluetooth Adapter:\n\
             ===============================\n\
             Watcher Active: {}\n\
             Publisher Active: {}\n\
             GATT Service: {}\n\
             Discovered Devices: {}\n\
             Adapter Available: {}",
            self.watcher.is_some(),
            self.publisher.is_some(),
            self.gatt_service_provider.is_some(),
            discovered_count,
            self.is_available().await
        )
    }
}

// Helper functions for Windows API conversion

#[cfg(windows)]
fn uuid_to_guid(uuid: &uuid::Uuid) -> Result<windows::core::GUID> {
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

// Stub implementation for non-Windows platforms
#[cfg(not(windows))]
pub struct WindowsBluetoothAdapter;

#[cfg(not(windows))]
impl WindowsBluetoothAdapter {
    pub async fn new(_config: BluetoothConfig) -> Result<Self> {
        Err(anyhow!("Windows Bluetooth adapter only available on Windows"))
    }
}

#[cfg(not(windows))]
#[async_trait::async_trait]
impl PlatformBluetoothAdapter for WindowsBluetoothAdapter {
    async fn initialize(&mut self) -> Result<()> {
        Err(anyhow!("Windows adapter not available on this platform"))
    }
    
    async fn start_scanning(&mut self) -> Result<()> {
        Err(anyhow!("Windows adapter not available on this platform"))
    }
    
    async fn stop_scanning(&mut self) -> Result<()> {
        Err(anyhow!("Windows adapter not available on this platform"))
    }
    
    async fn start_advertising(&mut self, _advertisement_data: &[u8]) -> Result<()> {
        Err(anyhow!("Windows adapter not available on this platform"))
    }
    
    async fn stop_advertising(&mut self) -> Result<()> {
        Err(anyhow!("Windows adapter not available on this platform"))
    }
    
    async fn connect_to_device(&mut self, _device: &DiscoveredDevice) -> Result<ConnectedPeer> {
        Err(anyhow!("Windows adapter not available on this platform"))
    }
    
    async fn disconnect_from_peer(&mut self, _peer: &ConnectedPeer) -> Result<()> {
        Err(anyhow!("Windows adapter not available on this platform"))
    }
    
    async fn send_to_peer(&self, _peer: &ConnectedPeer, _data: &[u8]) -> Result<()> {
        Err(anyhow!("Windows adapter not available on this platform"))
    }
    
    async fn is_available(&self) -> bool {
        false
    }
    
    async fn get_platform_debug_info(&self) -> String {
        "Windows adapter not available on this platform".to_string()
    }
}