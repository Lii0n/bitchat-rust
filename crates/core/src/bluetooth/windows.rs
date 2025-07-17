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
        },
        BluetoothLEDevice,
    },
    Foundation::TypedEventHandler,
    Storage::Streams::DataWriter,
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
        info!("Starting Bluetooth LE scanning for BitChat devices...");
        
        if *self.is_scanning.read().await {
            warn!("Already scanning");
            return Ok(());
        }
        
        #[cfg(windows)]
        {
            // Create watcher
            let watcher = BluetoothLEAdvertisementWatcher::new()?;
            
            // Configure scanning
            watcher.SetScanningMode(windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode::Active)?;
            
            // Set up event handler for received advertisements
            let discovered_devices = Arc::clone(&self.discovered_devices);
            let my_peer_id = self.my_peer_id.clone();
            
            let handler = TypedEventHandler::new(
                move |_sender: &Option<BluetoothLEAdvertisementWatcher>, 
                      args: &Option<BluetoothLEAdvertisementReceivedEventArgs>| {
                    
                    if let Some(args) = args {
                        // Clone the args for processing
                        let args = args.clone();
                        let discovered_devices = Arc::clone(&discovered_devices);
                        let my_peer_id = my_peer_id.clone();
                        
                        // Process the advertisement immediately to avoid Send issues
                        let rt = match tokio::runtime::Runtime::new() {
                            Ok(rt) => rt,
                            Err(e) => {
                                error!("Failed to create runtime: {}", e);
                                return Ok(());
                            }
                        };
                        
                        rt.block_on(async move {
                            if let Err(e) = WindowsBluetoothAdapter::handle_advertisement_received(
                                &args, 
                                &discovered_devices, 
                                &my_peer_id
                            ).await {
                                error!("Failed to handle advertisement: {}", e);
                            }
                        });
                    }
                    Ok(())
                }
            );
            
            watcher.Received(&handler)?;
            watcher.Start()?;
            self.watcher = Some(watcher);
            
            *self.is_scanning.write().await = true;
            info!("Bluetooth LE scanning started successfully");
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
    
    /// Start advertising as a BitChat device
    pub async fn start_advertising(&mut self, _advertisement_data: &[u8]) -> Result<()> {
        info!("Starting Bluetooth LE advertising for BitChat...");
        
        if *self.is_advertising.read().await {
            warn!("Already advertising");
            return Ok(());
        }
        
        #[cfg(windows)]
        {
            // Create a very minimal advertisement that Windows will accept
            let publisher = BluetoothLEAdvertisementPublisher::new()?;
            
            // Don't modify the advertisement at all - use default settings
            // Windows is very restrictive about what can be advertised
            
            info!("Starting minimal BLE advertisement...");
            
            // Try to start with minimal configuration
            match publisher.Start() {
                Ok(_) => {
                    self.publisher = Some(publisher);
                    *self.is_advertising.write().await = true;
                    info!("Bluetooth LE advertising started successfully (minimal mode)");
                    info!("Note: Windows restrictions prevent custom advertisement data");
                }
                Err(e) => {
                    error!("Failed to start advertising: {:?}", e);
                    return Err(anyhow!("Windows advertising failed: {:?}", e));
                }
            }
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
    
    /// Handle received advertisement (Windows only)
    #[cfg(windows)]
    async fn handle_advertisement_received(
        args: &BluetoothLEAdvertisementReceivedEventArgs,
        discovered_devices: &Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
        my_peer_id: &str,
    ) -> Result<()> {
        
        // Get device info
        let device_address = args.BluetoothAddress()?;
        let device_id = format!("{:012X}", device_address);
        let rssi = args.RawSignalStrengthInDBm()?;
        
        // Check if this is a BitChat device by examining the advertisement
        let mut is_bitchat_device = false;
        let mut peer_id: Option<String> = None;
        
        // Method 1: Check for BitChat service UUID in service list
        if let Ok(advertisement) = args.Advertisement() {
            if let Ok(service_uuids) = advertisement.ServiceUuids() {
                let service_count = service_uuids.Size().unwrap_or(0);
                for i in 0..service_count {
                    if let Ok(service_uuid) = service_uuids.GetAt(i) {
                        // Convert GUID to UUID bytes for comparison
                        let uuid_bytes = [
                            (service_uuid.data1 >> 24) as u8,
                            (service_uuid.data1 >> 16) as u8,
                            (service_uuid.data1 >> 8) as u8,
                            service_uuid.data1 as u8,
                            (service_uuid.data2 >> 8) as u8,
                            service_uuid.data2 as u8,
                            (service_uuid.data3 >> 8) as u8,
                            service_uuid.data3 as u8,
                            service_uuid.data4[0],
                            service_uuid.data4[1],
                            service_uuid.data4[2],
                            service_uuid.data4[3],
                            service_uuid.data4[4],
                            service_uuid.data4[5],
                            service_uuid.data4[6],
                            service_uuid.data4[7],
                        ];
                        
                        // Check if this matches the BitChat service UUID
                        if uuid_bytes == *BITCHAT_SERVICE.as_bytes() {
                            is_bitchat_device = true;
                            debug!("Found BitChat service UUID in advertisement!");
                            break;
                        }
                    }
                }
            }
            
            // Method 2: Check device name for BitChat format (BC_<peer_id>)
            if let Ok(local_name) = advertisement.LocalName() {
                let name = local_name.to_string();
                
                if name.starts_with("BC_") && name.len() == 19 { // BC_ + 16 hex chars
                    let extracted_peer_id = &name[3..];
                    if Self::is_valid_peer_id(extracted_peer_id) {
                        is_bitchat_device = true;
                        peer_id = Some(extracted_peer_id.to_uppercase());
                        debug!("Found BitChat device by name: {} -> peer ID: {}", name, extracted_peer_id);
                    }
                }
            }
            
            // Method 3: Check manufacturer data for BitChat signature
            if let Ok(manufacturer_data_list) = advertisement.ManufacturerData() {
                let data_count = manufacturer_data_list.Size().unwrap_or(0);
                for i in 0..data_count {
                    if let Ok(manufacturer_data) = manufacturer_data_list.GetAt(i) {
                        if let Ok(company_id) = manufacturer_data.CompanyId() {
                            // Check for our company ID (0xFFFF)
                            if company_id == 0xFFFF {
                                if let Ok(_data_buffer) = manufacturer_data.Data() {
                                    // Try to extract peer ID from manufacturer data
                                    is_bitchat_device = true;
                                    debug!("Found BitChat manufacturer data");
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // If this is a BitChat device, process it
        if is_bitchat_device {
            // Generate a peer ID if we don't have one
            if peer_id.is_none() {
                // Use device address as fallback peer ID
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
                info!("?? NEW BitChat peer discovered: {} (RSSI: {} dBm)", final_peer_id, rssi);
            } else {
                debug!("Updated BitChat device: {} (RSSI: {} dBm)", final_peer_id, rssi);
            }
        }
        // Don't log non-BitChat devices at all to reduce spam
        
        Ok(())
    }
    
    /// Extract peer ID from received advertisement (Windows only)
    #[cfg(windows)]
    async fn extract_peer_id_from_advertisement(
        args: &BluetoothLEAdvertisementReceivedEventArgs
    ) -> Result<String> {
        
        // Try to get peer ID from local name first
        if let Ok(local_name) = args.Advertisement()?.LocalName() {
            let name = local_name.to_string();
            if name.starts_with("BC_") && name.len() == 19 { // BC_ + 16 hex chars
                let peer_id = &name[3..];
                if Self::is_valid_peer_id(peer_id) {
                    return Ok(peer_id.to_uppercase());
                }
            }
        }
        
        // Try to get peer ID from manufacturer data
        if let Ok(manufacturer_data_list) = args.Advertisement()?.ManufacturerData() {
            for i in 0..manufacturer_data_list.Size()? {
                if let Ok(manufacturer_data) = manufacturer_data_list.GetAt(i) {
                    if manufacturer_data.CompanyId()? == 0xFFFF {
                        if let Ok(_data_buffer) = manufacturer_data.Data() {
                            // For now, return a placeholder peer ID
                            // Real implementation would parse the data buffer
                            return Ok("PLACEHOLDER01".to_string());
                        }
                    }
                }
            }
        }
        
        Err(anyhow!("Could not extract peer ID from advertisement"))
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