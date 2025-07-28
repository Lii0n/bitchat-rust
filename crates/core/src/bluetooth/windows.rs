// ==============================================================================
// crates/core/src/bluetooth/windows.rs - FIXED FOR iOS COMPATIBILITY
// ==============================================================================

//! Windows-specific Bluetooth LE implementation with iOS BitChat compatibility
//! 
//! This module provides native Windows WinRT BLE support that properly advertises
//! in the format expected by iOS BitChat clients. Includes fallback strategies
//! for Windows systems that have advertising restrictions.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[cfg(windows)]
use {
    windows::{
        core::HSTRING,
        Devices::Bluetooth::{
            Advertisement::{
                BluetoothLEAdvertisement,
                BluetoothLEAdvertisementPublisher,
                BluetoothLEAdvertisementReceivedEventArgs,
                BluetoothLEAdvertisementWatcher,
                BluetoothLEManufacturerData,
                BluetoothLEScanningMode,
            },
            BluetoothAdapter,
        },
        Storage::Streams::{DataReader, DataWriter},
        Foundation::TypedEventHandler,
    },
};

use crate::bluetooth::constants::{
    BITCHAT_SERVICE, BITCHAT_COMPANY_ID, messaging::MAX_MESSAGE_SIZE,
};

/// Discovered device information
#[derive(Clone, Debug)]
pub struct DiscoveredDevice {
    pub device_id: String,
    pub peer_id: String,
    pub rssi: i8,
    pub last_seen: Instant,
    pub nickname: Option<String>,
}

/// Windows Bluetooth adapter with iOS compatibility focus
pub struct WindowsBluetoothAdapter {
    pub my_peer_id: String,
    pub is_scanning: Arc<RwLock<bool>>,
    pub is_advertising: Arc<RwLock<bool>>,
    pub discovered_devices: Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
    
    #[cfg(windows)]
    pub watcher: Option<BluetoothLEAdvertisementWatcher>,
    #[cfg(windows)]
    pub publisher: Option<BluetoothLEAdvertisementPublisher>,
}

impl WindowsBluetoothAdapter {
    /// Create new Windows Bluetooth adapter
    pub fn new(peer_id: String) -> Self {
        // Ensure peer ID is exactly 16 hex chars (iOS format)
        let formatted_peer_id = if peer_id.len() == 16 && peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
            peer_id.to_uppercase()
        } else if peer_id.len() == 8 && peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
            // Pad 8-char ID to 16 chars
            format!("{:0<16}", peer_id.to_uppercase())
        } else {
            // Generate new 16-char peer ID
            format!("{:016X}", rand::random::<u64>())
        };

        info!("🆔 Windows adapter initialized with iOS-compatible peer ID: {}", formatted_peer_id);

        Self {
            my_peer_id: formatted_peer_id,
            is_scanning: Arc::new(RwLock::new(false)),
            is_advertising: Arc::new(RwLock::new(false)),
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
            
            #[cfg(windows)]
            watcher: None,
            #[cfg(windows)]
            publisher: None,
        }
    }

    /// Start advertising with iOS compatibility (multiple strategies)
    pub async fn start_advertising(&mut self, _advertisement_data: &[u8]) -> Result<()> {
        info!("🚀 Starting iOS-compatible BitChat advertising on Windows...");

        if *self.is_advertising.read().await {
            warn!("Already advertising");
            return Ok(());
        }

        #[cfg(windows)]
        {
            // STRATEGY 1: iOS-compatible device name only (preferred)
            match self.try_ios_compatible_advertising().await {
                Ok(_) => {
                    info!("✅ SUCCESS: iOS-compatible advertising active!");
                    info!("📱 Device name: {} (discoverable by iOS BitChat)", self.my_peer_id);
                    return Ok(());
                }
                Err(e) => {
                    warn!("iOS-compatible advertising failed: {}", e);
                }
            }

            // STRATEGY 2: Enhanced advertising with service UUID
            match self.try_enhanced_advertising().await {
                Ok(_) => {
                    info!("✅ SUCCESS: Enhanced advertising active!");
                    return Ok(());
                }
                Err(e) => {
                    warn!("Enhanced advertising failed: {}", e);
                }
            }

            // STRATEGY 3: Manufacturer data approach
            match self.try_manufacturer_data_advertising().await {
                Ok(_) => {
                    info!("✅ SUCCESS: Manufacturer data advertising active!");
                    return Ok(());
                }
                Err(e) => {
                    warn!("Manufacturer data advertising failed: {}", e);
                }
            }

            // STRATEGY 4: Minimal advertising (last resort)
            match self.try_minimal_advertising().await {
                Ok(_) => {
                    info!("⚠️  PARTIAL SUCCESS: Minimal advertising active");
                    info!("   May not be discoverable by all iOS devices");
                    return Ok(());
                }
                Err(e) => {
                    error!("All advertising strategies failed: {}", e);
                }
            }

            // If all strategies fail, provide detailed diagnostics
            self.log_advertising_diagnostics().await;
            return Err(anyhow!("Windows BLE advertising not supported on this system"));
        }

        #[cfg(not(windows))]
        {
            return Err(anyhow!("WinRT advertising only available on Windows"));
        }
    }

    /// STRATEGY 1: Pure iOS-compatible advertising (device name only)
    #[cfg(windows)]
    async fn try_ios_compatible_advertising(&mut self) -> Result<()> {
        let publisher = BluetoothLEAdvertisementPublisher::new()?;
        let advertisement = publisher.Advertisement()?;

        // Set device name to pure peer ID (iOS format)
        advertisement.SetLocalName(&HSTRING::from(&self.my_peer_id))?;
        
        // Minimal advertisement flags
        let flags = vec![0x06u8]; // LE General Discoverable + BR/EDR Not Supported
        let data_writer = DataWriter::new()?;
        data_writer.WriteBytes(&flags)?;
        
        publisher.Start()?;
        self.publisher = Some(publisher);
        *self.is_advertising.write().await = true;
        
        info!("📱 iOS-compatible advertising started (device name: {})", self.my_peer_id);
        Ok(())
    }

    /// STRATEGY 2: Enhanced advertising with BitChat service UUID
    #[cfg(windows)]
    async fn try_enhanced_advertising(&mut self) -> Result<()> {
        let publisher = BluetoothLEAdvertisementPublisher::new()?;
        let advertisement = publisher.Advertisement()?;

        // Set iOS-compatible device name
        advertisement.SetLocalName(&HSTRING::from(&self.my_peer_id))?;

        // Add BitChat service UUID
        if let Ok(service_uuids) = advertisement.ServiceUuids() {
            if let Ok(bitchat_guid) = Self::uuid_to_guid(BITCHAT_SERVICE) {
                service_uuids.Append(&bitchat_guid)?;
                info!("Added BitChat service UUID to advertisement");
            }
        }

        publisher.Start()?;
        self.publisher = Some(publisher);
        *self.is_advertising.write().await = true;
        
        info!("🔧 Enhanced advertising started with service UUID");
        Ok(())
    }

    /// STRATEGY 3: Manufacturer data advertising
    #[cfg(windows)]
    async fn try_manufacturer_data_advertising(&mut self) -> Result<()> {
        let publisher = BluetoothLEAdvertisementPublisher::new()?;
        let advertisement = publisher.Advertisement()?;

        // Set iOS-compatible device name
        advertisement.SetLocalName(&HSTRING::from(&self.my_peer_id))?;

        // Add manufacturer data with peer ID
        if let Ok(mfg_data_list) = advertisement.ManufacturerData() {
            let mfg_data = BluetoothLEManufacturerData::new()?;
            mfg_data.SetCompanyId(BITCHAT_COMPANY_ID)?;
            
            // Encode peer ID in manufacturer data
            let data_writer = DataWriter::new()?;
            data_writer.WriteBytes(&[0xBC, 0x01])?; // BitChat v1 signature
            
            if let Ok(peer_id_bytes) = hex::decode(&self.my_peer_id) {
                data_writer.WriteBytes(&peer_id_bytes)?;
            }
            
            mfg_data.SetData(&data_writer.DetachBuffer()?)?;
            mfg_data_list.Append(&mfg_data)?;
        }

        publisher.Start()?;
        self.publisher = Some(publisher);
        *self.is_advertising.write().await = true;
        
        info!("🏭 Manufacturer data advertising started");
        Ok(())
    }

    /// STRATEGY 4: Minimal advertising (fallback)
    #[cfg(windows)]
    async fn try_minimal_advertising(&mut self) -> Result<()> {
        let publisher = BluetoothLEAdvertisementPublisher::new()?;
        
        // Don't add anything extra, just start basic advertising
        publisher.Start()?;
        self.publisher = Some(publisher);
        *self.is_advertising.write().await = true;
        
        warn!("⚠️  Using minimal advertising - may not be BitChat discoverable");
        Ok(())
    }

    /// Convert UUID string to Windows GUID
    #[cfg(windows)]
    fn uuid_to_guid(uuid_str: &str) -> Result<windows::core::GUID> {
        // Remove dashes and convert to bytes
        let uuid_clean = uuid_str.replace('-', "");
        if uuid_clean.len() != 32 {
            return Err(anyhow!("Invalid UUID format"));
        }

        let uuid_bytes = hex::decode(uuid_clean)?;
        if uuid_bytes.len() != 16 {
            return Err(anyhow!("Invalid UUID byte length"));
        }

        Ok(windows::core::GUID::from_values(
            u32::from_be_bytes([uuid_bytes[0], uuid_bytes[1], uuid_bytes[2], uuid_bytes[3]]),
            u16::from_be_bytes([uuid_bytes[4], uuid_bytes[5]]),
            u16::from_be_bytes([uuid_bytes[6], uuid_bytes[7]]),
            [
                uuid_bytes[8], uuid_bytes[9], uuid_bytes[10], uuid_bytes[11],
                uuid_bytes[12], uuid_bytes[13], uuid_bytes[14], uuid_bytes[15]
            ]
        ))
    }

    /// Stop advertising
    pub async fn stop_advertising(&mut self) -> Result<()> {
        info!("⏹️  Stopping Bluetooth LE advertising...");
        
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
        info!("🔍 Starting enhanced BitChat device scanning...");
        
        if *self.is_scanning.read().await {
            warn!("Already scanning");
            return Ok(());
        }

        #[cfg(windows)]
        {
            let watcher = BluetoothLEAdvertisementWatcher::new()?;
            
            // Configure for optimal discovery
            watcher.SetScanningMode(BluetoothLEScanningMode::Active)?;
            
            // Set up event handler for discovered devices
            let discovered_devices = Arc::clone(&self.discovered_devices);
            let my_peer_id = self.my_peer_id.clone();
            
            let handler = TypedEventHandler::new(move |_sender, args: &Option<BluetoothLEAdvertisementReceivedEventArgs>| {
                if let Some(args) = args {
                    let discovered_devices_clone = Arc::clone(&discovered_devices);
                    let my_peer_id_clone = my_peer_id.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_discovered_device(args, &discovered_devices_clone, &my_peer_id_clone).await {
                            debug!("Error handling discovered device: {}", e);
                        }
                    });
                }
                Ok(())
            });
            
            watcher.Received(&handler)?;
            watcher.Start()?;
            
            self.watcher = Some(watcher);
            *self.is_scanning.write().await = true;
            info!("✅ BitChat scanning active");
        }
        
        #[cfg(not(windows))]
        {
            return Err(anyhow!("WinRT scanning only available on Windows"));
        }
        
        Ok(())
    }

    /// Enhanced advertisement handler for maximum BitChat compatibility
    #[cfg(windows)]
    async fn handle_discovered_device(
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
        
        // METHOD 1: Check device name for BitChat patterns (prioritize iOS format)
        if let Ok(local_name) = advertisement.LocalName() {
            let name = local_name.to_string();
            
            // PRIORITY: iOS/macOS format - exactly 16 hex characters
            if name.len() == 16 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                is_bitchat_device = true;
                peer_id = Some(name.to_uppercase());
                debug!("🍎 Found iOS/macOS BitChat device: {}", name);
            }
            // COMPATIBILITY: Windows legacy format
            else if name.starts_with("BC_") && name.len() >= 11 {
                let extracted_peer_id = name.chars().skip(3).collect::<String>();
                if extracted_peer_id.len() >= 8 && extracted_peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
                    is_bitchat_device = true;
                    let normalized_peer_id = if extracted_peer_id.len() >= 16 {
                        extracted_peer_id.chars().take(16).collect::<String>()
                    } else {
                        format!("{:0<16}", extracted_peer_id)
                    };
                    peer_id = Some(normalized_peer_id.to_uppercase());
                    debug!("🪟 Found Windows BitChat device: {} -> {}", name, peer_id.as_ref().unwrap());
                }
            }
            // COMPATIBILITY: Raspberry Pi or other formats
            else if name.contains("_") {
                if let Some(extracted_peer_id) = name.split('_').last() {
                    if extracted_peer_id.len() >= 8 && extracted_peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
                        is_bitchat_device = true;
                        let normalized_peer_id = if extracted_peer_id.len() >= 16 {
                            extracted_peer_id.chars().take(16).collect::<String>()
                        } else {
                            format!("{:0<16}", extracted_peer_id)
                        };
                        peer_id = Some(normalized_peer_id.to_uppercase());
                        debug!("🥧 Found Pi BitChat device: {} -> {}", name, peer_id.as_ref().unwrap());
                    }
                }
            }
        }

        // METHOD 2: Check for BitChat service UUID
        if let Ok(service_uuids) = advertisement.ServiceUuids() {
            if let Ok(bitchat_service_guid) = Self::uuid_to_guid(BITCHAT_SERVICE) {
                for i in 0..service_uuids.Size().unwrap_or(0) {
                    if let Ok(service_uuid) = service_uuids.GetAt(i) {
                        if service_uuid == bitchat_service_guid {
                            is_bitchat_device = true;
                            debug!("🔵 Found BitChat service UUID in advertisement!");
                            break;
                        }
                    }
                }
            }
        }

        // METHOD 3: Check manufacturer data for BitChat signature
        if let Ok(manufacturer_data_list) = advertisement.ManufacturerData() {
            for i in 0..manufacturer_data_list.Size().unwrap_or(0) {
                if let Ok(manufacturer_data) = manufacturer_data_list.GetAt(i) {
                    if manufacturer_data.CompanyId().unwrap_or(0) == BITCHAT_COMPANY_ID {
                        if let Ok(data_buffer) = manufacturer_data.Data() {
                            if let Ok(data_reader) = DataReader::FromBuffer(&data_buffer) {
                                let buffer_length = data_buffer.Length().unwrap_or(0) as usize;
                                
                                if buffer_length >= 10 { // 2 bytes signature + 8 bytes peer ID minimum
                                    let mut signature_bytes = vec![0u8; 2];
                                    data_reader.ReadBytes(&mut signature_bytes)?;
                                    
                                    if signature_bytes == [0xBC, 0x01] { // BitChat v1 signature
                                        is_bitchat_device = true;
                                        
                                        // Read peer ID if not already found
                                        if peer_id.is_none() && buffer_length >= 10 {
                                            let mut peer_id_bytes = vec![0u8; 8];
                                            data_reader.ReadBytes(&mut peer_id_bytes)?;
                                            peer_id = Some(hex::encode(peer_id_bytes).to_uppercase());
                                        }
                                        
                                        debug!("🏭 Found BitChat manufacturer data signature!");
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Only process if it's a BitChat device and not ourselves
        if is_bitchat_device {
            if let Some(found_peer_id) = peer_id {
                if found_peer_id != my_peer_id {
                    let discovered_device = DiscoveredDevice {
                        device_id: device_id.clone(),
                        peer_id: found_peer_id.clone(),
                        rssi,
                        last_seen: Instant::now(),
                        nickname,
                    };
                    
                    let mut devices = discovered_devices.write().await;
                    devices.insert(device_id.clone(), discovered_device);
                    drop(devices);
                    
                    info!("🎯 Discovered BitChat peer: {} (RSSI: {} dBm)", found_peer_id, rssi);
                } else {
                    debug!("Ignoring our own advertisement");
                }
            }
        }

        Ok(())
    }

    /// Stop scanning
    pub async fn stop_scanning(&mut self) -> Result<()> {
        info!("⏹️  Stopping Bluetooth LE scanning...");
        
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

    /// Log detailed advertising diagnostics
    #[cfg(windows)]
    async fn log_advertising_diagnostics(&self) {
        error!("🚨 WINDOWS BLUETOOTH ADVERTISING DIAGNOSTICS:");
        error!("   Current peer ID: {}", self.my_peer_id);
        error!("   Expected iOS format: 16 hex characters (✅ correct format)");
        error!("");
        error!("   💡 POSSIBLE SOLUTIONS:");
        error!("   1. Run as Administrator");
        error!("   2. Update Windows and Bluetooth drivers");
        error!("   3. Enable 'Allow Bluetooth devices to find this PC' in Windows Settings");
        error!("   4. Try a different Bluetooth adapter (USB dongles often work better)");
        error!("   5. Use a Raspberry Pi for reliable advertising");
        error!("");
        error!("   📱 iOS DISCOVERY TROUBLESHOOTING:");
        error!("   - Your device name should appear as: '{}'", self.my_peer_id);
        error!("   - iOS BitChat should detect this automatically");
        error!("   - If not working, the issue is Windows BLE driver limitations");
    }

    /// Get discovered devices
    pub async fn get_discovered_devices(&self) -> HashMap<String, DiscoveredDevice> {
        self.discovered_devices.read().await.clone()
    }

    /// Check if advertising
    pub async fn is_advertising(&self) -> bool {
        *self.is_advertising.read().await
    }

    /// Check if scanning
    pub async fn is_scanning(&self) -> bool {
        *self.is_scanning.read().await
    }

    /// Get our peer ID
    pub fn get_peer_id(&self) -> &str {
        &self.my_peer_id
    }
}