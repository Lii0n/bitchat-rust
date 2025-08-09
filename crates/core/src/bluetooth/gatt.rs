// ==============================================================================
// GATT Connection Implementation for BitChat
// ==============================================================================

//! This module implements real GATT (Generic Attribute Profile) connections
//! for BitChat peer-to-peer communication over Bluetooth LE.
//! 
//! GATT Hierarchy:
//! - Device -> GATT Server -> Service -> Characteristics
//! - BitChat Service UUID: F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C
//! - TX Characteristic: Write data TO remote device  
//! - RX Characteristic: Read data FROM remote device

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{RwLock, mpsc};
use tracing::{error, info, warn};
use uuid::Uuid;

#[cfg(windows)]
use {
    windows::{
        core::HSTRING,
        Devices::Bluetooth::{
            BluetoothLEDevice,
            GenericAttributeProfile::{
                GattDeviceService,
                GattCharacteristic,
                GattCommunicationStatus,
                GattValueChangedEventArgs,
            },
        },
        Storage::Streams::DataReader,  
        Foundation::TypedEventHandler,
    },
};

#[cfg(not(windows))]
use {
    btleplug::api::{
        Central, Manager as _, Peripheral, ScanFilter, Characteristic, WriteType,
        CharPropFlags, NotificationHandler,
    },
    btleplug::platform::{Manager, Adapter},
    std::pin::Pin,
    futures::Stream,
    futures::StreamExt,
};

// BitChat GATT Service and Characteristic UUIDs
pub const BITCHAT_SERVICE_UUID: &str = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C";
pub const BITCHAT_TX_CHARACTERISTIC_UUID: &str = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5D"; // TX (write to remote)
pub const BITCHAT_RX_CHARACTERISTIC_UUID: &str = "F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5E"; // RX (read from remote)

/// GATT connection to a remote BitChat device
#[derive(Debug)]
pub struct GattConnection {
    pub peer_id: String,
    pub device_id: String, 
    pub connected_at: Instant,
    
    #[cfg(windows)]
    ble_device: Option<BluetoothLEDevice>,
    #[cfg(windows)] 
    gatt_service: Option<GattDeviceService>,
    #[cfg(windows)]
    tx_characteristic: Option<GattCharacteristic>, // For sending data
    #[cfg(windows)]
    rx_characteristic: Option<GattCharacteristic>, // For receiving data
    
    #[cfg(not(windows))]
    peripheral: Option<btleplug::platform::Peripheral>,
    #[cfg(not(windows))]
    tx_characteristic: Option<btleplug::api::Characteristic>,
    #[cfg(not(windows))]
    rx_characteristic: Option<btleplug::api::Characteristic>,
    
    // Connection state
    is_connected: bool,
    last_activity: Instant,
    bytes_sent: u64,
    bytes_received: u64,
}

/// GATT connection manager for BitChat
pub struct GattManager {
    connections: Arc<RwLock<HashMap<String, GattConnection>>>,
    incoming_data_tx: mpsc::Sender<(String, Vec<u8>)>, // (peer_id, data)
}

impl GattManager {
    /// Create a new GATT manager
    pub fn new() -> (Self, mpsc::Receiver<(String, Vec<u8>)>) {
        let (tx, rx) = mpsc::channel(100);
        
        let manager = Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            incoming_data_tx: tx,
        };
        
        (manager, rx)
    }
    
    /// Establish GATT connection to a discovered device
    pub async fn connect_to_device(&self, device_id: &str, peer_id: &str) -> Result<()> {
        info!("🔌 Establishing GATT connection to peer: {}", peer_id);
        
        #[cfg(windows)]
        {
            // Step 1: Get BluetoothLEDevice from device ID
            let ble_device = self.get_ble_device(device_id).await?;
            info!("✅ Got BLE device for: {}", device_id);
            
            // Step 2: Connect to GATT server and discover BitChat service
            let gatt_service = self.discover_bitchat_service(&ble_device).await?;
            info!("✅ Discovered BitChat GATT service");
            
            // Step 3: Discover TX/RX characteristics
            let (tx_char, rx_char) = self.discover_characteristics(&gatt_service).await?;
            info!("✅ Discovered TX/RX characteristics");
            
            // Step 4: Subscribe to RX characteristic notifications
            self.subscribe_to_notifications(&rx_char, peer_id).await?;
            info!("✅ Subscribed to RX notifications");
            
            // Step 5: Store the connection
            let connection = GattConnection {
                peer_id: peer_id.to_string(),
                device_id: device_id.to_string(),
                connected_at: Instant::now(),
                ble_device: Some(ble_device),
                gatt_service: Some(gatt_service),
                tx_characteristic: Some(tx_char),
                rx_characteristic: Some(rx_char),
                is_connected: true,
                last_activity: Instant::now(),
                bytes_sent: 0,
                bytes_received: 0,
            };
            
            let mut connections = self.connections.write().await;
            connections.insert(peer_id.to_string(), connection);
            
            info!("🎉 GATT connection established to peer: {}", peer_id);
            Ok(())
        }
        
        #[cfg(not(windows))]
        {
            // Step 1: Get Bluetooth manager and adapter
            let manager = Manager::new().await?;
            let adapters = manager.adapters().await?;
            if adapters.is_empty() {
                return Err(anyhow!("No Bluetooth adapters found"));
            }
            let adapter = adapters.into_iter().next().unwrap();
            
            // Step 2: Find the peripheral by device ID/peer ID
            let peripheral = self.find_peripheral(&adapter, device_id, peer_id).await?;
            info!("✅ Found peripheral for peer: {}", peer_id);
            
            // Step 3: Connect to the peripheral
            peripheral.connect().await?;
            info!("✅ Connected to peripheral: {}", peer_id);
            
            // Step 4: Discover services and characteristics
            peripheral.discover_services().await?;
            let (tx_char, rx_char) = self.discover_bitchat_characteristics(&peripheral).await?;
            info!("✅ Discovered TX/RX characteristics");
            
            // Step 5: Subscribe to RX characteristic notifications
            peripheral.subscribe(&rx_char).await?;
            info!("✅ Subscribed to RX notifications");
            
            // Step 6: Set up notification handler
            let peer_id_clone = peer_id.to_string();
            let incoming_tx = self.incoming_data_tx.clone();
            
            let mut notification_stream = peripheral.notifications().await?;
            tokio::spawn(async move {
                while let Some(data) = notification_stream.next().await {
                    if data.uuid == Uuid::parse_str(BITCHAT_RX_CHARACTERISTIC_UUID).unwrap() {
                        info!("📥 Received {} bytes from peer: {}", data.value.len(), peer_id_clone);
                        
                        if let Err(e) = incoming_tx.send((peer_id_clone.clone(), data.value)).await {
                            error!("Failed to send incoming data: {}", e);
                            break;
                        }
                    }
                }
            });
            
            // Step 7: Store the connection
            let connection = GattConnection {
                peer_id: peer_id.to_string(),
                device_id: device_id.to_string(),
                connected_at: Instant::now(),
                peripheral: Some(peripheral),
                tx_characteristic: Some(tx_char),
                rx_characteristic: Some(rx_char),
                is_connected: true,
                last_activity: Instant::now(),
                bytes_sent: 0,
                bytes_received: 0,
            };
            
            let mut connections = self.connections.write().await;
            connections.insert(peer_id.to_string(), connection);
            
            info!("🎉 GATT connection established to peer: {}", peer_id);
            Ok(())
        }
    }
    
    /// Send data to a connected peer via GATT
    pub async fn send_data(&self, peer_id: &str, data: &[u8]) -> Result<()> {
        info!("📤 Sending {} bytes to peer: {}", data.len(), peer_id);
        
        #[cfg(windows)]
        {
            let mut connections = self.connections.write().await;
            let connection = connections.get_mut(peer_id)
                .ok_or_else(|| anyhow!("No GATT connection to peer: {}", peer_id))?;
            
            if !connection.is_connected {
                return Err(anyhow!("GATT connection to {} is not active", peer_id));
            }
            
            let tx_char = connection.tx_characteristic.as_ref()
                .ok_or_else(|| anyhow!("No TX characteristic for peer: {}", peer_id))?;
            
            // Write data to TX characteristic
            let _result = self.write_characteristic_data(tx_char, data).await?;
            
            // Update connection stats
            connection.bytes_sent += data.len() as u64;
            connection.last_activity = Instant::now();
            
            info!("✅ Successfully sent {} bytes to peer: {}", data.len(), peer_id);
            Ok(())
        }
        
        #[cfg(not(windows))]
        {
            let mut connections = self.connections.write().await;
            let connection = connections.get_mut(peer_id)
                .ok_or_else(|| anyhow!("No GATT connection to peer: {}", peer_id))?;
            
            if !connection.is_connected {
                return Err(anyhow!("GATT connection to {} is not active", peer_id));
            }
            
            let peripheral = connection.peripheral.as_ref()
                .ok_or_else(|| anyhow!("No peripheral for peer: {}", peer_id))?;
            let tx_char = connection.tx_characteristic.as_ref()
                .ok_or_else(|| anyhow!("No TX characteristic for peer: {}", peer_id))?;
            
            // Write data to TX characteristic
            peripheral.write(tx_char, data, WriteType::WithoutResponse).await?;
            
            // Update connection stats
            connection.bytes_sent += data.len() as u64;
            connection.last_activity = Instant::now();
            
            info!("✅ Successfully sent {} bytes to peer: {}", data.len(), peer_id);
            Ok(())
        }
    }
    
    /// Get list of connected peers
    pub async fn get_connected_peers(&self) -> Vec<String> {
        let connections = self.connections.read().await;
        connections.keys().cloned().collect()
    }
    
    /// Check if peer is connected via GATT
    pub async fn is_connected(&self, peer_id: &str) -> bool {
        let connections = self.connections.read().await;
        connections.get(peer_id)
            .map(|conn| conn.is_connected)
            .unwrap_or(false)
    }
    
    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: &str) -> Result<()> {
        info!("🔌 Disconnecting from peer: {}", peer_id);
        
        let mut connections = self.connections.write().await;
        if let Some(mut connection) = connections.remove(peer_id) {
            connection.is_connected = false;
            info!("✅ Disconnected from peer: {}", peer_id);
        }
        
        Ok(())
    }
}

// Windows-specific GATT implementation
#[cfg(windows)]
impl GattManager {
    /// Get BluetoothLEDevice from device ID
    async fn get_ble_device(&self, device_id: &str) -> Result<BluetoothLEDevice> {
        use windows::Devices::Bluetooth::BluetoothLEDevice;
        
        // Convert device ID to HSTRING
        let device_id_hstring = HSTRING::from(device_id);
        
        // Get BLE device asynchronously
        let async_op = BluetoothLEDevice::FromIdAsync(&device_id_hstring)?;
        let ble_device = async_op.await?;
        
        Ok(ble_device)
    }
    
    /// Discover BitChat GATT service on the device
    async fn discover_bitchat_service(&self, ble_device: &BluetoothLEDevice) -> Result<GattDeviceService> {
        use windows::Devices::Bluetooth::GenericAttributeProfile::GattDeviceServicesResult;
        
        // Parse BitChat service UUID
        let service_uuid = Uuid::parse_str(BITCHAT_SERVICE_UUID)?;
        let service_uuid_guid = windows::core::GUID::from_u128(service_uuid.as_u128());
        
        // Get GATT services
        let services_result: GattDeviceServicesResult = ble_device.GetGattServicesForUuidAsync(service_uuid_guid)?.await?;
        
        // Check if BitChat service was found
        let services = services_result.Services()?;
        if services.Size()? == 0 {
            return Err(anyhow!("BitChat GATT service not found on device"));
        }
        
        let bitchat_service = services.GetAt(0)?;
        info!("🔍 Found BitChat GATT service");
        
        Ok(bitchat_service)
    }
    
    /// Discover TX and RX characteristics
    async fn discover_characteristics(&self, service: &GattDeviceService) -> Result<(GattCharacteristic, GattCharacteristic)> {
        use windows::Devices::Bluetooth::GenericAttributeProfile::GattCharacteristicsResult;
        
        // Get all characteristics for this service
        let chars_result: GattCharacteristicsResult = service.GetCharacteristicsAsync()?.await?;
        let characteristics = chars_result.Characteristics()?;
        
        let mut tx_char: Option<GattCharacteristic> = None;
        let mut rx_char: Option<GattCharacteristic> = None;
        
        // Find TX and RX characteristics by UUID
        for i in 0..characteristics.Size()? {
            let characteristic = characteristics.GetAt(i)?;
            let uuid = characteristic.Uuid()?;
            let uuid_str = format!("{:?}", uuid); // Convert GUID to string
            
            if uuid_str.contains("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5D") {
                tx_char = Some(characteristic);
                info!("🔍 Found TX characteristic");
            } else if uuid_str.contains("F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5E") {
                rx_char = Some(characteristic);
                info!("🔍 Found RX characteristic");
            }
        }
        
        let tx = tx_char.ok_or_else(|| anyhow!("TX characteristic not found"))?;
        let rx = rx_char.ok_or_else(|| anyhow!("RX characteristic not found"))?;
        
        Ok((tx, rx))
    }
    
    /// Subscribe to RX characteristic notifications
    async fn subscribe_to_notifications(&self, rx_char: &GattCharacteristic, peer_id: &str) -> Result<()> {
        use windows::Devices::Bluetooth::GenericAttributeProfile::GattClientCharacteristicConfigurationDescriptorValue;
        
        // Enable notifications
        let status = rx_char.WriteClientCharacteristicConfigurationDescriptorAsync(
            GattClientCharacteristicConfigurationDescriptorValue::Notify
        )?.await?;
        
        if status != GattCommunicationStatus::Success {
            return Err(anyhow!("Failed to enable notifications"));
        }
        
        // Set up notification handler
        let peer_id_clone = peer_id.to_string();
        let incoming_tx = self.incoming_data_tx.clone();
        
        let handler = TypedEventHandler::new(move |_sender: &Option<GattCharacteristic>, args: &Option<GattValueChangedEventArgs>| {
            let peer_id = peer_id_clone.clone();
            let tx = incoming_tx.clone();
            
            // Extract data synchronously to avoid lifetime issues
            let mut data: Option<Vec<u8>> = None;
            if let Some(args) = args {
                if let Ok(value) = args.CharacteristicValue() {
                    if let Ok(reader) = DataReader::FromBuffer(&value) {
                        if let Ok(length) = reader.UnconsumedBufferLength() {
                            let mut buffer = vec![0u8; length as usize];
                            if reader.ReadBytes(&mut buffer).is_ok() {
                                data = Some(buffer);
                            }
                        }
                    }
                }
            }
            
            // Process data asynchronously if we have it
            if let Some(buffer) = data {
                tokio::spawn(async move {
                    info!("📥 Received {} bytes from peer: {}", buffer.len(), peer_id);
                    
                    // Send to incoming data channel
                    if let Err(e) = tx.send((peer_id, buffer)).await {
                        error!("Failed to send incoming data: {}", e);
                    }
                });
            }
            
            Ok(())
        });
        
        rx_char.ValueChanged(&handler)?;
        info!("✅ Notification handler set up for peer: {}", peer_id);
        
        Ok(())
    }
    
    /// Write data to a GATT characteristic
    async fn write_characteristic_data(&self, characteristic: &GattCharacteristic, data: &[u8]) -> Result<()> {
        use windows::Storage::Streams::{DataWriter, InMemoryRandomAccessStream};
        
        // Create data writer
        let stream = InMemoryRandomAccessStream::new()?;
        let writer = DataWriter::CreateDataWriter(&stream)?;
        
        // Write data
        writer.WriteBytes(data)?;
        let buffer = writer.DetachBuffer()?;
        
        // Write to characteristic
        let status = characteristic.WriteValueAsync(&buffer)?.await?;
        
        if status != GattCommunicationStatus::Success {
            return Err(anyhow!("Failed to write to characteristic: {:?}", status));
        }
        
        Ok(())
    }
}

// Non-Windows (btleplug) implementation
#[cfg(not(windows))]
impl GattManager {
    /// Find peripheral by device ID or peer ID
    async fn find_peripheral(&self, adapter: &Adapter, device_id: &str, peer_id: &str) -> Result<btleplug::platform::Peripheral> {
        // Start scanning for devices
        adapter.start_scan(ScanFilter::default()).await?;
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await; // Scan for 5 seconds
        adapter.stop_scan().await?;
        
        let peripherals = adapter.peripherals().await?;
        
        // Look for device by ID or by BitChat service advertisement
        for peripheral in peripherals {
            let peripheral_id = peripheral.id().to_string();
            
            // Try to match by device ID first
            if peripheral_id.contains(device_id) {
                return Ok(peripheral);
            }
            
            // Try to get peripheral properties to check name
            if let Ok(properties) = peripheral.properties().await {
                if let Some(properties) = properties {
                    if let Some(name) = properties.local_name {
                        // Check if name contains peer ID or BitChat identifier
                        if name.contains(peer_id) || name.contains("BC_") {
                            return Ok(peripheral);
                        }
                    }
                }
            }
        }
        
        Err(anyhow!("Peripheral not found for device: {} / peer: {}", device_id, peer_id))
    }
    
    /// Discover BitChat characteristics on the peripheral
    async fn discover_bitchat_characteristics(&self, peripheral: &btleplug::platform::Peripheral) -> Result<(btleplug::api::Characteristic, btleplug::api::Characteristic)> {
        let services = peripheral.services();
        
        let tx_uuid = Uuid::parse_str(BITCHAT_TX_CHARACTERISTIC_UUID)?;
        let rx_uuid = Uuid::parse_str(BITCHAT_RX_CHARACTERISTIC_UUID)?;
        
        let mut tx_char: Option<btleplug::api::Characteristic> = None;
        let mut rx_char: Option<btleplug::api::Characteristic> = None;
        
        // Search through all services and characteristics
        for service in services {
            for characteristic in &service.characteristics {
                if characteristic.uuid == tx_uuid {
                    tx_char = Some(characteristic.clone());
                    info!("🔍 Found TX characteristic");
                } else if characteristic.uuid == rx_uuid {
                    rx_char = Some(characteristic.clone());
                    info!("🔍 Found RX characteristic");
                }
            }
        }
        
        let tx = tx_char.ok_or_else(|| anyhow!("TX characteristic not found"))?;
        let rx = rx_char.ok_or_else(|| anyhow!("RX characteristic not found"))?;
        
        Ok((tx, rx))
    }
}

impl Default for GattManager {
    fn default() -> Self {
        let (manager, _) = Self::new();
        manager
    }
}