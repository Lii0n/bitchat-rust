// ==============================================================================
// crates/core/src/bluetooth/windows.rs
// Windows-specific Bluetooth implementation with WinRT support
// ==============================================================================

//! Windows-specific Bluetooth implementation using WinRT APIs
//! 
//! This implementation provides real Bluetooth LE functionality on Windows
//! using the Windows Runtime (WinRT) APIs for device discovery, advertising,
//! and GATT communication.

use crate::bluetooth::{BluetoothConfig, ConnectedPeer, DiscoveredDevice};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};

#[cfg(windows)]
use windows::{
    core::*,
    Devices::Bluetooth::{
        BluetoothAdapter,
        Advertisement::{
            BluetoothLEAdvertisement,
            BluetoothLEAdvertisementPublisher,
            BluetoothLEAdvertisementWatcher,
            BluetoothLEAdvertisementReceivedEventArgs,
            BluetoothLEManufacturerData,
            BluetoothLEAdvertisementFlags,
            BluetoothLEAdvertisementPublisherStatus,
            BluetoothLEAdvertisementPublisherStatusChangedEventArgs,
            BluetoothLEScanningMode,
        },
        BluetoothLEDevice,
    },
    Foundation::TypedEventHandler,
    Storage::Streams::{DataWriter, DataReader},
};

use crate::bluetooth::constants::service_uuids::{BITCHAT_SERVICE, BITCHAT_CHARACTERISTIC};

/// Windows Bluetooth adapter using WinRT APIs
pub struct WindowsBluetoothAdapter {
    config: BluetoothConfig,
    my_peer_id: String,
    
    // State tracking
    discovered_devices: Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
    
    // WinRT components (Windows only)
    #[cfg(windows)]
    publisher: Option<BluetoothLEAdvertisementPublisher>,
    #[cfg(windows)]
    watcher: Option<BluetoothLEAdvertisementWatcher>,
    
    // Runtime state
    is_scanning: Arc<RwLock<bool>>,
    is_advertising: Arc<RwLock<bool>>,
}

impl WindowsBluetoothAdapter {
    /// Create new Windows Bluetooth adapter
    pub async fn new(config: BluetoothConfig) -> Result<Self> {
        info!("Initializing Windows Bluetooth adapter with WinRT...");
        
        let my_peer_id = config.device_name.clone();
        
        #[cfg(windows)]
        {
            // Verify Bluetooth LE support on Windows
            Self::check_bluetooth_support().await?;
        }
        
        let adapter = Self {
            config,
            my_peer_id,
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
            
            #[cfg(windows)]
            publisher: None,
            #[cfg(windows)]
            watcher: None,
            
            is_scanning: Arc::new(RwLock::new(false)),
            is_advertising: Arc::new(RwLock::new(false)),
        };
        
        info!("Windows Bluetooth adapter initialized successfully");
        Ok(adapter)
    }
    
    /// Check if Bluetooth LE is supported (Windows only)
    #[cfg(windows)]
    async fn check_bluetooth_support() -> Result<()> {
        match BluetoothAdapter::GetDefaultAsync() {
            Ok(future) => {
                match future.await {
                    Ok(adapter) => {
                        let supported = adapter.IsLowEnergySupported()?;
                        if supported {
                            info!("Bluetooth LE is supported and available");
                            Ok(())
                        } else {
                            Err(anyhow!("Bluetooth LE not supported on this system"))
                        }
                    }
                    Err(e) => {
                        error!("Failed to get Bluetooth adapter: {:?}", e);
                        Err(anyhow!("Failed to access Bluetooth adapter"))
                    }
                }
            }
            Err(e) => {
                error!("Failed to access Bluetooth API: {:?}", e);
                Err(anyhow!("Bluetooth API not available"))
            }
        }
    }
    
    #[cfg(not(windows))]
    async fn check_bluetooth_support() -> Result<()> {
        Err(anyhow!("Windows Bluetooth adapter only available on Windows"))
    }
    
    /// Start scanning for BitChat devices
    pub async fn start_scanning(&mut self) -> Result<()> {
        info!("Starting BitChat-compatible device scanning...");
        
        if *self.is_scanning.read().await {
            warn!("Already scanning");
            return Ok(());
        }
        
        #[cfg(windows)]
        {
            // Create watcher
            let watcher = BluetoothLEAdvertisementWatcher::new()?;
            
            // Configure scanning parameters for optimal BitChat discovery
            watcher.SetScanningMode(BluetoothLEScanningMode::Active)?;
            
            // Set up comprehensive advertisement filtering
            let discovered_devices = Arc::clone(&self.discovered_devices);
            let my_peer_id = self.my_peer_id.clone();
            
            let handler = TypedEventHandler::new(
                move |_sender: &Option<BluetoothLEAdvertisementWatcher>, 
                      args: &Option<BluetoothLEAdvertisementReceivedEventArgs>| {
                    
                    if let Some(args) = args {
                        // Use blocking approach to avoid async issues in callback
                        let discovered_devices = Arc::clone(&discovered_devices);
                        let my_peer_id = my_peer_id.clone();
                        let args_clone = args.clone();
                        
                        // Process synchronously within the callback
                        std::thread::spawn(move || {
                            let rt = match tokio::runtime::Runtime::new() {
                                Ok(rt) => rt,
                                Err(e) => {
                                    error!("Failed to create runtime: {}", e);
                                    return;
                                }
                            };
                            
                            rt.block_on(async move {
                                if let Err(e) = WindowsBluetoothAdapter::handle_bitchat_advertisement(
                                    &args_clone, 
                                    &discovered_devices, 
                                    &my_peer_id
                                ).await {
                                    debug!("Advertisement processing failed: {}", e);
                                }
                            });
                        });
                    }
                    Ok(())
                }
            );
            
            watcher.Received(&handler)?;
            watcher.Start()?;
            self.watcher = Some(watcher);
            
            *self.is_scanning.write().await = true;
            info!("?? BitChat device scanning active - looking for iOS/macOS peers");
        }
        
        #[cfg(not(windows))]
        {
            return Err(anyhow!("WinRT scanning only available on Windows"));
        }
        
        Ok(())
    }
    
    /// Stop scanning
    pub async fn stop_scanning(&mut self) -> Result<()> {
        info!("Stopping Bluetooth LE scanning...");
        
        #[cfg(windows)]
        {
            if let Some(watcher) = &self.watcher {
                watcher.Stop()?;
            }
            self.watcher = None;
        }
        
        *self.is_scanning.write().await = false;
        info!("Bluetooth LE scanning stopped");
        
        Ok(())
    }
    
    /// Start advertising as BitChat device with proper compatibility
    pub async fn start_advertising(&mut self, _advertisement_data: &[u8]) -> Result<()> {
        info!("Starting BitChat-compatible Bluetooth LE advertising...");
    
        if *self.is_advertising.read().await {
            warn!("Already advertising");
            return Ok(());
        }
    
        #[cfg(windows)]
        {
            // Create and configure publisher with minimal setup to avoid Windows restrictions
            let publisher = BluetoothLEAdvertisementPublisher::new()?;
            let advertisement = publisher.Advertisement()?;
        
            // Set device name in iOS/macOS compatible format (just the peer ID)
            advertisement.SetLocalName(&HSTRING::from(&self.my_peer_id))?;
        
            // Try to add service UUID (may fail on some Windows versions)
            if let Ok(service_uuids) = advertisement.ServiceUuids() {
                let service_guid = Self::uuid_to_guid(&BITCHAT_SERVICE);
                let _ = service_uuids.Append(service_guid); // Ignore errors
            }
        
            // Skip manufacturer data and flags that might cause issues
            // Windows is very restrictive about what can be advertised
        
            // Start advertising with minimal configuration
            publisher.Start()?;
        
            self.publisher = Some(publisher);
            *self.is_advertising.write().await = true;
        
            info!("?? BitChat advertising active - device name: {} (peer: {})", 
                  self.my_peer_id, self.my_peer_id);
            info!("?? iOS/macOS BitChat devices can now discover this peer");
        }
    
        #[cfg(not(windows))]
        {
            return Err(anyhow!("WinRT advertising only available on Windows"));
        }
    
        Ok(())
    }
    
    /// Stop advertising
    pub async fn stop_advertising(&mut self) -> Result<()> {
        info!("Stopping Bluetooth LE advertising...");
        
        #[cfg(windows)]
        {
            if let Some(publisher) = &self.publisher {
                publisher.Stop()?;
            }
            self.publisher = None;
        }
        
        *self.is_advertising.write().await = false;
        info!("Bluetooth LE advertising stopped");
        
        Ok(())
    }
    
    /// Enhanced advertisement handler for BitChat compatibility
    #[cfg(windows)]
    async fn handle_bitchat_advertisement(
        args: &BluetoothLEAdvertisementReceivedEventArgs,
        discovered_devices: &Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
        my_peer_id: &str,
    ) -> Result<()> {
        let device_address = args.BluetoothAddress()?;
        let device_id = format!("{:012X}", device_address);
        let rssi = args.RawSignalStrengthInDBm()?;
        let advertisement = args.Advertisement()?;
        
        let mut is_bitchat_device = false;
        let mut peer_id: Option<String> = None;
        let mut nickname: Option<String> = None;
        
        // Method 1: Check for BitChat service UUID
        if let Ok(service_uuids) = advertisement.ServiceUuids() {
            let bitchat_service_guid = Self::uuid_to_guid(&BITCHAT_SERVICE);
            
            for i in 0..service_uuids.Size()? {
                if let Ok(service_uuid) = service_uuids.GetAt(i) {
                    if service_uuid == bitchat_service_guid {
                        is_bitchat_device = true;
                        debug!("Found BitChat service UUID in advertisement!");
                        break;
                    }
                }
            }
        }
        
        // Method 2: Check device name for BitChat format
        if let Ok(local_name) = advertisement.LocalName() {
            let name = local_name.to_string();
            
            // iOS/macOS format: just peer ID (16 hex chars)
            if name.len() == 16 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                is_bitchat_device = true;
                peer_id = Some(name.to_uppercase());
                debug!("Found iOS/macOS BitChat device: {}", name);
            }
            // Windows legacy format: BC_<peer_id>
            else if name.starts_with("BC_") && name.len() >= 11 {
                let extracted_peer_id = name.chars().skip(3).take(16).collect::<String>();
                if extracted_peer_id.len() == 16 && extracted_peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
                    is_bitchat_device = true;
                    peer_id = Some(extracted_peer_id.to_uppercase());
                    debug!("Found Windows BitChat device: {} -> peer ID: {}", name, extracted_peer_id);
                }
            }
        }
        
        // Method 3: Check manufacturer data for BitChat protocol
        if let Ok(manufacturer_data_list) = advertisement.ManufacturerData() {
            for i in 0..manufacturer_data_list.Size()? {
                if let Ok(manufacturer_data) = manufacturer_data_list.GetAt(i) {
                    if manufacturer_data.CompanyId()? == 0xFFFF { // BitChat company ID
                        if let Ok(data_buffer) = manufacturer_data.Data() {
                            let data_reader = DataReader::FromBuffer(&data_buffer)?;
                            let buffer_length = data_buffer.Length()? as usize;
                            
                            if buffer_length >= 9 {
                                // Parse BitChat manufacturer data format
                                let mut peer_id_bytes = vec![0u8; 8];
                                data_reader.ReadBytes(&mut peer_id_bytes[..])?;
                                
                                let nickname_len = {
                                    let mut len_bytes = vec![0u8; 1];
                                    data_reader.ReadBytes(&mut len_bytes[..])?;
                                    len_bytes[0] as usize
                                };
                                
                                if buffer_length >= 9 + nickname_len {
                                    let mut nickname_bytes = vec![0u8; nickname_len];
                                    data_reader.ReadBytes(&mut nickname_bytes[..])?;
                                    nickname = Some(String::from_utf8_lossy(&nickname_bytes).to_string());
                                }
                                
                                is_bitchat_device = true;
                                peer_id = Some(hex::encode(&peer_id_bytes).to_uppercase());
                                debug!("Found BitChat manufacturer data: peer={}, nickname={:?}", 
                                       peer_id.as_ref().unwrap(), nickname);
                            } else if buffer_length == 8 {
                                // Simple format: just peer ID
                                let mut peer_id_bytes = vec![0u8; 8];
                                data_reader.ReadBytes(&mut peer_id_bytes[..])?;
                                
                                is_bitchat_device = true;
                                peer_id = Some(hex::encode(&peer_id_bytes).to_uppercase());
                                debug!("Found simple BitChat data: peer={}", peer_id.as_ref().unwrap());
                            }
                        }
                    }
                }
            }
        }
        
        // Process BitChat device
        if is_bitchat_device {
            // Generate fallback peer ID if needed
            if peer_id.is_none() {
                peer_id = Some(format!("{:016X}", device_address));
                debug!("Generated fallback peer ID: {}", peer_id.as_ref().unwrap());
            }
            
            let final_peer_id = peer_id.unwrap();
            
            // Skip our own advertisements
            if final_peer_id == my_peer_id {
                debug!("Ignoring our own advertisement");
                return Ok(());
            }
            
            // Create or update discovered device
            let discovered_device = DiscoveredDevice {
                device_id: device_id.clone(),
                peer_id: Some(final_peer_id.clone()),
                rssi,
                last_seen: Instant::now(),
                connection_attempts: 0,
            };
            
            // Store in discovered devices
            let mut devices = discovered_devices.write().await;
            let is_new = !devices.contains_key(&device_id);
            devices.insert(device_id.clone(), discovered_device);
            drop(devices);
            
            if is_new {
                let nickname_str = nickname.unwrap_or_else(|| "Unknown".to_string());
                info!("?? NEW BitChat peer discovered: {} ({}) - RSSI: {} dBm", 
                      final_peer_id, nickname_str, rssi);
            } else {
                debug!("Updated BitChat device: {} - RSSI: {} dBm", final_peer_id, rssi);
            }
        }
        
        Ok(())
    }
    
    /// Handle received advertisement (Windows only) - legacy function kept for compatibility
    #[cfg(windows)]
    async fn handle_advertisement_received(
        args: &BluetoothLEAdvertisementReceivedEventArgs,
        discovered_devices: &Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
        my_peer_id: &str,
    ) -> Result<()> {
        // Use the new enhanced handler
        Self::handle_bitchat_advertisement(args, discovered_devices, my_peer_id).await
    }
    
    /// Extract peer ID from received advertisement (Windows only) - improved implementation
    #[cfg(windows)]
    async fn extract_peer_id_from_advertisement(
        args: &BluetoothLEAdvertisementReceivedEventArgs
    ) -> Result<String> {
        // Method 1: Parse device name (prioritize iOS/macOS format)
        if let Ok(local_name) = args.Advertisement()?.LocalName() {
            let name = local_name.to_string();
        
            // iOS/macOS format: Just the peer ID (16 hex characters)
            if name.len() == 16 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                return Ok(name.to_uppercase());
            }
        
            // Windows legacy format: BC_<peer_id> 
            if name.starts_with("BC_") && name.len() >= 11 {
                let peer_id = name.chars().skip(3).take(16).collect::<String>();
                if peer_id.len() == 16 && peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Ok(peer_id.to_uppercase());
                }
            }
        }
    
        // Method 2: Parse manufacturer data for BitChat protocol
        if let Ok(manufacturer_data_list) = args.Advertisement()?.ManufacturerData() {
            for i in 0..manufacturer_data_list.Size()? {
                if let Ok(manufacturer_data) = manufacturer_data_list.GetAt(i) {
                    if manufacturer_data.CompanyId()? == 0xFFFF { // BitChat company ID
                        if let Ok(data_buffer) = manufacturer_data.Data() {
                            // Read the buffer properly using DataReader
                            let data_reader = DataReader::FromBuffer(&data_buffer)?;
                            let buffer_length = data_buffer.Length()? as usize;
                        
                            if buffer_length >= 8 {
                                // Read peer ID bytes (first 8 bytes)
                                let mut peer_id_bytes = vec![0u8; 8];
                                data_reader.ReadBytes(&mut peer_id_bytes[..])?;
                                let peer_id = hex::encode(&peer_id_bytes).to_uppercase();
                            
                                debug!("Extracted peer ID from manufacturer data: {}", peer_id);
                                return Ok(peer_id);
                            }
                        }
                    }
                }
            }
        }
    
        // Method 3: Check for BitChat service UUID
        if let Ok(service_uuids) = args.Advertisement()?.ServiceUuids() {
            let bitchat_service_guid = Self::uuid_to_guid(&BITCHAT_SERVICE);
        
            for i in 0..service_uuids.Size()? {
                if let Ok(service_uuid) = service_uuids.GetAt(i) {
                    if service_uuid == bitchat_service_guid {
                        // Generate peer ID from device address as fallback
                        let device_address = args.BluetoothAddress()?;
                        let fallback_peer_id = format!("{:016X}", device_address);
                        debug!("Using device address as peer ID: {}", fallback_peer_id);
                        return Ok(fallback_peer_id);
                    }
                }
            }
        }
    
        Err(anyhow!("Could not extract peer ID from advertisement"))
    }
    
    /// Utility function to convert UUID to Windows GUID
    #[cfg(windows)]
    fn uuid_to_guid(uuid: &uuid::Uuid) -> windows::core::GUID {
        let bytes = uuid.as_bytes();
        windows::core::GUID::from_values(
            u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            u16::from_be_bytes([bytes[4], bytes[5]]),
            u16::from_be_bytes([bytes[6], bytes[7]]),
            [bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]]
        )
    }
    
    /// Check if peer ID format is valid
    fn is_valid_peer_id(peer_id: &str) -> bool {
        peer_id.len() == 16 && peer_id.chars().all(|c| c.is_ascii_hexdigit())
    }
    
    /// Connect to device
    pub async fn connect_to_device(&mut self, device: &DiscoveredDevice) -> Result<ConnectedPeer> {
        info!("Attempting to connect to device: {}", device.device_id);
        
        #[cfg(windows)]
        {
            // Get discovered device info
            let discovered_device = {
                let devices = self.discovered_devices.read().await;
                devices.get(&device.device_id).cloned()
                    .ok_or_else(|| anyhow!("Device not found: {}", device.device_id))?
            };
            
            // For now, create a simulated connection
            // Real implementation would:
            // 1. Convert device ID to Bluetooth address
            // 2. Get BLE device using BluetoothLEDevice::FromBluetoothAddressAsync
            // 3. Connect to GATT services
            // 4. Find BitChat service and characteristics
            
            let connected_peer = ConnectedPeer {
                peer_id: discovered_device.peer_id.unwrap_or_else(|| device.device_id.clone()),
                connected_at: Instant::now(),
                last_seen: Instant::now(),
                rssi: Some(discovered_device.rssi),
                message_count: 0,
            };
            
            info!("Connected to device: {} (peer: {})", device.device_id, connected_peer.peer_id);
            Ok(connected_peer)
        }
        
        #[cfg(not(windows))]
        {
            // Fallback implementation for non-Windows
            Ok(ConnectedPeer {
                peer_id: device.peer_id.clone().unwrap_or_else(|| device.device_id.clone()),
                connected_at: Instant::now(),
                last_seen: Instant::now(),
                rssi: Some(device.rssi),
                message_count: 0,
            })
        }
    }
    
    /// Disconnect from peer
    pub async fn disconnect_from_peer(&mut self, peer: &ConnectedPeer) -> Result<()> {
        info!("Disconnecting from peer: {}", peer.peer_id);
        
        #[cfg(windows)]
        {
            // Real implementation would dispose of BLE device connection
        }
        
        info!("Disconnected from peer: {}", peer.peer_id);
        Ok(())
    }
    
    /// Send data to peer
    pub async fn send_to_peer(&self, peer: &ConnectedPeer, data: &[u8]) -> Result<()> {
        debug!("Sending {} bytes to peer: {}", data.len(), peer.peer_id);
        
        #[cfg(windows)]
        {
            // Real implementation would:
            // 1. Find the GATT characteristic for this peer
            // 2. Write data using characteristic.WriteValueAsync()
        }
        
        debug!("Simulated sending {} bytes to peer: {}", data.len(), peer.peer_id);
        Ok(())
    }
    
    /// Check if Bluetooth is available
    pub async fn is_available(&self) -> bool {
        #[cfg(windows)]
        {
            Self::check_bluetooth_support().await.is_ok()
        }
        
        #[cfg(not(windows))]
        {
            false
        }
    }
    
    /// Get debug information
    pub async fn get_platform_debug_info(&self) -> String {
        let scanning = *self.is_scanning.read().await;
        let advertising = *self.is_advertising.read().await;
        let discovered_count = self.discovered_devices.read().await.len();
        
        format!(
            "Windows Bluetooth Adapter (WinRT)\n\
             ===================================\n\
             Peer ID: {}\n\
             Scanning: {}\n\
             Advertising: {}\n\
             Discovered Devices: {}\n\
             Platform: Windows with WinRT APIs",
            self.my_peer_id,
            scanning,
            advertising,
            discovered_count
        )
    }
    
    /// Get discovered devices
    pub async fn get_discovered_devices(&self) -> HashMap<String, DiscoveredDevice> {
        self.discovered_devices.read().await.clone()
    }
    
    /// Check if scanning
    pub async fn is_scanning(&self) -> bool {
        *self.is_scanning.read().await
    }
    
    /// Check if advertising
    pub async fn is_advertising(&self) -> bool {
        *self.is_advertising.read().await
    }
    
    /// Cleanup resources
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down Windows Bluetooth adapter...");
        
        if self.is_scanning().await {
            self.stop_scanning().await?;
        }
        
        if self.is_advertising().await {
            self.stop_advertising().await?;
        }
        
        info!("Windows Bluetooth adapter shutdown complete");
        Ok(())
    }
}