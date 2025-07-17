// ==============================================================================
// crates/core/src/bluetooth/windows/winrt_discovery.rs
// WinRT Device Discovery for BitChat - Simple Integration
// ==============================================================================

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use anyhow::{Result, anyhow};

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

use crate::bluetooth::{
    BluetoothConfig, BluetoothEvent, DiscoveredDevice, ConnectedPeer,
    constants::service_uuids::{BITCHAT_SERVICE, BITCHAT_CHARACTERISTIC},
};

/// Simple WinRT device discovery that integrates with existing BitChat manager
pub struct WinRTDeviceDiscovery {
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

impl WinRTDeviceDiscovery {
    /// Create new WinRT device discovery instance
    pub async fn new(config: BluetoothConfig, my_peer_id: String) -> Result<Self> {
        info!("Initializing WinRT device discovery for peer: {}", my_peer_id);
        
        #[cfg(windows)]
        {
            // Verify Bluetooth LE support on Windows
            Self::check_bluetooth_support().await?;
        }
        
        let discovery = Self {
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
        
        info!("WinRT device discovery initialized successfully");
        Ok(discovery)
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
        Err(anyhow!("WinRT only supported on Windows"))
    }
    
    /// Start advertising as a BitChat device
    pub async fn start_advertising(&mut self) -> Result<()> {
        info!("Starting Bluetooth LE advertising for BitChat...");
        
        if *self.is_advertising.read().await {
            warn!("Already advertising");
            return Ok(());
        }
        
        #[cfg(windows)]
        {
            // Create advertisement
            let advertisement = BluetoothLEAdvertisement::new()?;
            
            // Set device name
            advertisement.SetLocalName(&HSTRING::from(&self.my_peer_id))?;
            
            // Add BitChat service UUID
            let service_uuid_bytes = BITCHAT_SERVICE.as_bytes();
            let service_guid = windows::core::GUID::from_values(
                u32::from_be_bytes([service_uuid_bytes[0], service_uuid_bytes[1], service_uuid_bytes[2], service_uuid_bytes[3]]),
                u16::from_be_bytes([service_uuid_bytes[4], service_uuid_bytes[5]]),
                u16::from_be_bytes([service_uuid_bytes[6], service_uuid_bytes[7]]),
                [service_uuid_bytes[8], service_uuid_bytes[9], service_uuid_bytes[10], service_uuid_bytes[11], service_uuid_bytes[12], service_uuid_bytes[13], service_uuid_bytes[14], service_uuid_bytes[15]]
            );
            
            advertisement.ServiceUuids()?.Append(&service_guid)?;
            
            // Add manufacturer data with peer ID
            let manufacturer_data = BluetoothLEManufacturerData::new()?;
            manufacturer_data.SetCompanyId(0xFFFF)?; // Use unassigned company ID
            
            let peer_id_bytes = self.my_peer_id.as_bytes();
            let data_writer = DataWriter::new()?;
            data_writer.WriteBytes(peer_id_bytes)?;
            manufacturer_data.SetData(&data_writer.DetachBuffer()?)?;
            advertisement.ManufacturerData()?.Append(&manufacturer_data)?;
            
            // Create and start publisher - pass advertisement to constructor
            let publisher = BluetoothLEAdvertisementPublisher::CreateBluetoothLEAdvertisementPublisher(advertisement)?;
            publisher.Start()?;
            publisher.Start()?;
            
            self.publisher = Some(publisher);
            *self.is_advertising.write().await = true;
            info!("Bluetooth LE advertising started successfully");
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
            
            // Configure scanning with filtering
            watcher.SetScanningMode(windows::Devices::Bluetooth::Advertisement::BluetoothLEScanningMode::Active)?;
            
            // Since ServiceUuids is read-only on advertisement filter, we'll filter in the handler
            // For now, just scan for all devices and filter by device name in the handler
            
            // Set up event handler for received advertisements
            let discovered_devices = Arc::clone(&self.discovered_devices);
            let my_peer_id = self.my_peer_id.clone();
            
            let handler = TypedEventHandler::new(
                move |_sender: &Option<BluetoothLEAdvertisementWatcher>, 
                      args: &Option<BluetoothLEAdvertisementReceivedEventArgs>| {
                    
                    if let Some(args) = args {
                        let rt = tokio::runtime::Handle::current();
                        let discovered_devices = Arc::clone(&discovered_devices);
                        let my_peer_id = my_peer_id.clone();
                        
                        rt.spawn(async move {
                            if let Err(e) = Self::handle_advertisement_received(
                                args, 
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
        
        debug!("Advertisement received from device: {} (RSSI: {} dBm)", device_id, rssi);
        
        // Extract peer ID from advertisement
        let peer_id = Self::extract_peer_id_from_advertisement(args).await?;
        
        // Skip our own advertisements
        if peer_id == my_peer_id {
            debug!("Ignoring our own advertisement");
            return Ok(());
        }
        
        // Create or update discovered device
        let discovered_device = DiscoveredDevice {
            device_id: device_id.clone(),
            peer_id: Some(peer_id.clone()),
            rssi,
            last_seen: Instant::now(),
            connection_attempts: 0,
        };
        
        // Store in discovered devices
        let mut devices = discovered_devices.write().await;
        devices.insert(device_id.clone(), discovered_device);
        drop(devices);
        
        info!("Discovered BitChat device: {} (peer: {}, RSSI: {} dBm)", 
              device_id, peer_id, rssi);
        
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
                        if let Ok(data_buffer) = manufacturer_data.Data() {
                            // Simple extraction - this would need proper DataReader implementation
                            // For now, return a placeholder
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
    
    /// Connect to a discovered device (stub for integration)
    pub async fn connect_to_device(&mut self, device_id: &str) -> Result<ConnectedPeer> {
        info!("Attempting to connect to device: {}", device_id);
        
        // Get discovered device info
        let discovered_device = {
            let devices = self.discovered_devices.read().await;
            devices.get(device_id).cloned()
                .ok_or_else(|| anyhow!("Device not found: {}", device_id))?
        };
        
        // For now, create a simulated connection
        // Real implementation would use GATT services
        let connected_peer = ConnectedPeer {
            peer_id: discovered_device.peer_id.unwrap_or_else(|| device_id.to_string()),
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            rssi: Some(discovered_device.rssi),
            message_count: 0,
        };
        
        info!("Simulated connection to device: {} (peer: {})", device_id, connected_peer.peer_id);
        Ok(connected_peer)
    }
    
    /// Send data to a connected device (stub for integration)
    pub async fn send_to_device(&self, device_id: &str, data: &[u8]) -> Result<()> {
        debug!("Simulated sending {} bytes to device: {}", data.len(), device_id);
        // Real implementation would write to GATT characteristic
        Ok(())
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
        info!("Shutting down WinRT device discovery...");
        
        if self.is_scanning().await {
            self.stop_scanning().await?;
        }
        
        if self.is_advertising().await {
            self.stop_advertising().await?;
        }
        
        info!("WinRT device discovery shutdown complete");
        Ok(())
    }
}

impl Drop for WinRTDeviceDiscovery {
    fn drop(&mut self) {
        info!("Dropping WinRT device discovery instance");
    }
}