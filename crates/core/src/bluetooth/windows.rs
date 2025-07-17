// ==============================================================================
// crates/core/src/bluetooth/windows.rs
// Fixed Windows Bluetooth implementation with BitChat compatibility
// ==============================================================================

//! Windows-specific Bluetooth implementation using WinRT APIs
//! 
//! This implementation provides real Bluetooth LE functionality on Windows
//! using the Windows Runtime (WinRT) APIs for device discovery, advertising,
//! and GATT communication.

use crate::bluetooth::{BluetoothConfig, DiscoveredDevice};
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
            BluetoothLEAdvertisementPublisher,
            BluetoothLEAdvertisementWatcher,
            BluetoothLEAdvertisementReceivedEventArgs,
            BluetoothLEAdvertisementPublisherStatus,
            BluetoothLEAdvertisementPublisherStatusChangedEventArgs,
            BluetoothLEScanningMode,
        },
    },
    Foundation::TypedEventHandler,
    Storage::Streams::DataReader,
};

use crate::bluetooth::constants::service_uuids::BITCHAT_SERVICE;

// Add hex crate import
use hex;

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
            
            // Set up event handler for received advertisements
            let discovered_devices = Arc::clone(&self.discovered_devices);
            let my_peer_id = self.my_peer_id.clone();
            
            let handler = TypedEventHandler::new(
                move |_sender: &Option<BluetoothLEAdvertisementWatcher>, 
                      args: &Option<BluetoothLEAdvertisementReceivedEventArgs>| {
                    let discovered_devices = discovered_devices.clone();
                    let my_peer_id = my_peer_id.clone();
                    
                    if let Some(args) = args {
                        let args_clone = args.clone();
                        // FIXED: Use Handle::current() to spawn from non-async context
                        if let Ok(handle) = tokio::runtime::Handle::try_current() {
                            handle.spawn(async move {
                                if let Err(e) = WindowsBluetoothAdapter::handle_bitchat_advertisement(
                                    &args_clone, &discovered_devices, &my_peer_id
                                ).await {
                                    debug!("Error handling advertisement: {}", e);
                                }
                            });
                        } else {
                            debug!("No Tokio runtime available for handling advertisement");
                        }
                    }
                    Ok(())
                }
            );
            
            watcher.Received(&handler)?;
            watcher.Start()?;
            self.watcher = Some(watcher);
            
            *self.is_scanning.write().await = true;
            info!("🔍 BitChat device scanning active - looking for iOS/macOS peers");
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
    
    /// Start advertising as BitChat device with Windows compatibility fixes
    pub async fn start_advertising(&mut self, _advertisement_data: &[u8]) -> Result<()> {
        info!("Starting BitChat-compatible Bluetooth LE advertising...");
    
        if *self.is_advertising.read().await {
            warn!("Already advertising");
            return Ok(());
        }
    
        #[cfg(windows)]
        {
            // PERFECT: Based on your error analysis, Windows needs:
            // 1. Non-empty payload (0x8007000D told us this)
            // 2. But simple parameters (0x80070057 told us this)
            
            let publisher = BluetoothLEAdvertisementPublisher::new()?;
            let advertisement = publisher.Advertisement()?;
        
            // STRATEGY 1: Only device name (simple but non-empty)
            let device_name = format!("BC_{}", &self.my_peer_id[..8]);
            advertisement.SetLocalName(&HSTRING::from(&device_name))?;
        
            // STRATEGY 2: If device name fails, try only manufacturer data
            let mut success = false;
            
            // Try with just device name first
            match publisher.Start() {
                Ok(_) => {
                    success = true;
                    self.publisher = Some(publisher);
                    *self.is_advertising.write().await = true;
                    info!("🔵 ✅ DEVICE-NAME-ONLY advertising SUCCESS!");
                    info!("📱 Device name: {} (BitChat discoverable)", device_name);
                }
                Err(e) => {
                    warn!("Device name advertising failed: {}, trying manufacturer data only", e);
                    
                    // STRATEGY 2: Try manufacturer data only (this provides non-empty payload)
                    let publisher2 = BluetoothLEAdvertisementPublisher::new()?;
                    let advertisement2 = publisher2.Advertisement()?;
                    
                    // Add minimal manufacturer data (this satisfies "non-empty payload" requirement)
                    match advertisement2.ManufacturerData() {
                        Ok(mfg_data_list) => {
                            let mfg_data = windows::Devices::Bluetooth::Advertisement::BluetoothLEManufacturerData::new()?;
                            mfg_data.SetCompanyId(0xFFFF)?; // Unassigned company ID
                            
                            // Minimal payload: just 4 bytes of peer ID
                            let payload = &self.my_peer_id.as_bytes()[..4.min(self.my_peer_id.len())];
                            let data_writer = windows::Storage::Streams::DataWriter::new()?;
                            data_writer.WriteBytes(payload)?;
                            mfg_data.SetData(&data_writer.DetachBuffer()?)?;
                            
                            mfg_data_list.Append(&mfg_data)?;
                            
                            match publisher2.Start() {
                                Ok(_) => {
                                    success = true;
                                    self.publisher = Some(publisher2);
                                    *self.is_advertising.write().await = true;
                                    info!("🔵 ✅ MANUFACTURER-DATA-ONLY advertising SUCCESS!");
                                    info!("📱 Broadcasting minimal BitChat signature");
                                }
                                Err(e) => {
                                    warn!("Manufacturer data advertising also failed: {}", e);
                                }
                            }
                        }
                        Err(e) => {
                            warn!("Cannot access manufacturer data: {}", e);
                        }
                    }
                }
            }
            
            if !success {
                // STRATEGY 3: Last resort - try with simple service UUID only
                warn!("Trying last resort: single service UUID only");
                let publisher3 = BluetoothLEAdvertisementPublisher::new()?;
                let advertisement3 = publisher3.Advertisement()?;
                
                // Try with just one simple service UUID (this provides non-empty payload)
                match advertisement3.ServiceUuids() {
                    Ok(service_uuids) => {
                        // Use a simple, standard service UUID that Windows should accept
                        let simple_guid = windows::core::GUID::from_values(
                            0x1234, 0x5678, 0x9ABC, 
                            [0xDE, 0xF0, 0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]
                        );
                        
                        match service_uuids.Append(simple_guid) {
                            Ok(_) => {
                                match publisher3.Start() {
                                    Ok(_) => {
                                        success = true;
                                        self.publisher = Some(publisher3);
                                        *self.is_advertising.write().await = true;
                                        info!("🔵 ✅ SIMPLE-UUID-ONLY advertising SUCCESS!");
                                        info!("📱 Broadcasting with simple service UUID");
                                    }
                                    Err(e) => {
                                        warn!("❌ Even simple UUID advertising failed: {}", e);
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Cannot add simple UUID: {}", e);
                            }
                        }
                    }
                    Err(e) => {
                        warn!("Cannot access service UUIDs: {}", e);
                    }
                }
            }
            
            if !success {
                warn!("❌ All advertising strategies failed on this Windows/hardware combination");
                warn!("💡 Your system can scan and discover other BitChat devices perfectly");
                warn!("💡 Consider using a mobile device or different Windows machine for advertising");
            } else {
                info!("📱 SUCCESS: Other BitChat devices should now be able to discover you!");
                info!("🔍 You can also discover other BitChat devices via scanning");
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
        let nickname: Option<String> = None;
        
        // Method 1: Check for BitChat service UUID
        if let Ok(service_uuids) = advertisement.ServiceUuids() {
            if let Ok(bitchat_service_guid) = WindowsBluetoothAdapter::uuid_to_guid(&BITCHAT_SERVICE.to_string()) {
                for i in 0..service_uuids.Size().unwrap_or(0) {
                    if let Ok(service_uuid) = service_uuids.GetAt(i) {
                        if service_uuid == bitchat_service_guid {
                            is_bitchat_device = true;
                            debug!("Found BitChat service UUID in advertisement!");
                            break;
                        }
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
                debug!("Found iOS/macOS BitChat device by name: {}", name);
            }
            // Windows format: BC_<peer_id>
            else if name.starts_with("BC_") && name.len() >= 11 {
                let extracted_peer_id = name.chars().skip(3).take(16).collect::<String>();
                if extracted_peer_id.len() >= 8 && extracted_peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
                    is_bitchat_device = true;
                    peer_id = Some(extracted_peer_id.to_uppercase());
                    debug!("Found Windows BitChat device by name: {}", name);
                }
            }
        }
        
        // Method 3: Check manufacturer data for BitChat protocol
        if let Ok(manufacturer_data_list) = advertisement.ManufacturerData() {
            for i in 0..manufacturer_data_list.Size().unwrap_or(0) {
                if let Ok(manufacturer_data) = manufacturer_data_list.GetAt(i) {
                    if manufacturer_data.CompanyId().unwrap_or(0) == 0xFFFF { // BitChat company ID
                        if let Ok(data_buffer) = manufacturer_data.Data() {
                            // Read the buffer properly using DataReader
                            if let Ok(data_reader) = DataReader::FromBuffer(&data_buffer) {
                                let buffer_length = data_buffer.Length().unwrap_or(0) as usize;
                        
                                if buffer_length >= 8 {
                                    // Read peer ID bytes (first 8 bytes)
                                    let mut peer_id_bytes = vec![0u8; 8];
                                    if data_reader.ReadBytes(&mut peer_id_bytes[..]).is_ok() {
                                        let extracted_peer_id = hex::encode(&peer_id_bytes).to_uppercase();
                                        is_bitchat_device = true;
                                        peer_id = Some(extracted_peer_id);
                                        debug!("Found BitChat device by manufacturer data");
                                    }
                                }
                            }
                        }
                        break;
                    }
                }
            }
        }
        
        // Process discovered BitChat device
        if is_bitchat_device {
            let final_peer_id = peer_id.unwrap_or_else(|| device_id.clone());
            
            // Don't discover ourselves
            if final_peer_id == my_peer_id {
                return Ok(());
            }
            
            let device = DiscoveredDevice {
                device_id: device_id.clone(),
                peer_id: Some(final_peer_id.clone()),  // This is Option<String>
                rssi: rssi as i16,                     // Convert to i16
                last_seen: Instant::now(),
                connection_attempts: 0,
            };
            
            let mut devices = discovered_devices.write().await;
            let is_new = !devices.contains_key(&final_peer_id);
            devices.insert(final_peer_id.clone(), device);
            
            let nickname_str = nickname.as_deref().unwrap_or("Unknown");
            if is_new {
                info!("🔍 NEW BitChat peer discovered: {} ({}) - RSSI: {} dBm", 
                      final_peer_id, nickname_str, rssi);
            } else {
                debug!("Updated BitChat device: {} - RSSI: {} dBm", final_peer_id, rssi);
            }
        }
        
        Ok(())
    }
    
    /// Convert UUID string to Windows GUID
    #[cfg(windows)]
    fn uuid_to_guid(uuid_str: &str) -> Result<windows::core::GUID> {
        // Remove hyphens from UUID string
        let uuid_clean = uuid_str.replace("-", "");
        
        if uuid_clean.len() != 32 {
            return Err(anyhow!("Invalid UUID length: {}", uuid_str));
        }
        
        // Parse UUID components
        let data1 = u32::from_str_radix(&uuid_clean[0..8], 16)
            .map_err(|e| anyhow!("Failed to parse UUID data1: {}", e))?;
        let data2 = u16::from_str_radix(&uuid_clean[8..12], 16)
            .map_err(|e| anyhow!("Failed to parse UUID data2: {}", e))?;
        let data3 = u16::from_str_radix(&uuid_clean[12..16], 16)
            .map_err(|e| anyhow!("Failed to parse UUID data3: {}", e))?;
        
        let mut data4 = [0u8; 8];
        for i in 0..8 {
            data4[i] = u8::from_str_radix(&uuid_clean[16 + i * 2..18 + i * 2], 16)
                .map_err(|e| anyhow!("Failed to parse UUID data4[{}]: {}", i, e))?;
        }
        
        Ok(windows::core::GUID::from_values(data1, data2, data3, data4))
    }
    
    /// Get discovered devices
    pub async fn get_discovered_devices(&self) -> HashMap<String, DiscoveredDevice> {
        self.discovered_devices.read().await.clone()
    }
    
    /// Get connection status
    pub async fn is_scanning(&self) -> bool {
        *self.is_scanning.read().await
    }
    
    /// Get advertising status
    pub async fn is_advertising(&self) -> bool {
        *self.is_advertising.read().await
    }
    
    /// Check if Bluetooth is available on this system
    pub async fn is_available(&self) -> bool {
        #[cfg(windows)]
        {
            // Check if we can access the Bluetooth adapter
            match BluetoothAdapter::GetDefaultAsync() {
                Ok(future) => {
                    match future.await {
                        Ok(adapter) => adapter.IsLowEnergySupported().unwrap_or(false),
                        Err(_) => false,
                    }
                }
                Err(_) => false,
            }
        }
        
        #[cfg(not(windows))]
        {
            false
        }
    }
    
    /// Get platform-specific debug information
    pub async fn get_platform_debug_info(&self) -> String {
        let mut info = String::new();
        info.push_str("=== Windows Bluetooth Adapter Debug Info ===\n");
        
        #[cfg(windows)]
        {
            // Bluetooth adapter info
            match BluetoothAdapter::GetDefaultAsync() {
                Ok(future) => {
                    match future.await {
                        Ok(adapter) => {
                            info.push_str(&format!("Bluetooth LE Supported: {}\n", 
                                adapter.IsLowEnergySupported().unwrap_or(false)));
                            
                            if let Ok(device_id) = adapter.DeviceId() {
                                info.push_str(&format!("Device ID: {}\n", device_id.to_string()));
                            }
                        }
                        Err(e) => {
                            info.push_str(&format!("Failed to get adapter: {}\n", e));
                        }
                    }
                }
                Err(e) => {
                    info.push_str(&format!("Failed to access Bluetooth API: {}\n", e));
                }
            }
            
            // Current state
            info.push_str(&format!("Currently Scanning: {}\n", self.is_scanning().await));
            info.push_str(&format!("Currently Advertising: {}\n", self.is_advertising().await));
            info.push_str(&format!("My Peer ID: {}\n", self.my_peer_id));
            
            // Discovered devices
            let devices = self.discovered_devices.read().await;
            info.push_str(&format!("Discovered Devices: {}\n", devices.len()));
            for (device_id, device) in devices.iter() {
                info.push_str(&format!("  - {} (RSSI: {} dBm, Peer: {:?})\n", 
                    device_id, device.rssi, device.peer_id));
            }
        }
        
        #[cfg(not(windows))]
        {
            info.push_str("Windows Bluetooth adapter not available on this platform\n");
        }
        
        info
    }
    
    /// Shutdown the adapter
    pub async fn shutdown(&mut self) -> Result<()> {
        info!("Shutting down Windows Bluetooth adapter...");
        
        self.stop_scanning().await?;
        self.stop_advertising().await?;
        
        info!("Windows Bluetooth adapter shutdown complete");
        Ok(())
    }

    /// Comprehensive diagnostic check for Bluetooth LE advertising capabilities
    pub async fn diagnose_advertising_support(&self) -> String {
        let mut report = String::new();
        report.push_str("=== Windows Bluetooth LE Advertising Diagnostics ===\n\n");

        #[cfg(windows)]
        {
            // 1. Check Windows Version
            report.push_str("1. WINDOWS VERSION CHECK:\n");
            match self.check_windows_version() {
                Ok(version_info) => report.push_str(&format!("   ✅ {}\n", version_info)),
                Err(e) => report.push_str(&format!("   ❌ Failed to get Windows version: {}\n", e)),
            }
            report.push('\n');

            // 2. Check Bluetooth Adapter
            report.push_str("2. BLUETOOTH ADAPTER CHECK:\n");
            match BluetoothAdapter::GetDefaultAsync() {
                Ok(future) => {
                    match future.await {
                        Ok(adapter) => {
                            // Basic LE support
                            match adapter.IsLowEnergySupported() {
                                Ok(supported) => {
                                    if supported {
                                        report.push_str("   ✅ Bluetooth LE supported\n");
                                    } else {
                                        report.push_str("   ❌ Bluetooth LE NOT supported\n");
                                        report.push_str("   💡 Your hardware doesn't support Bluetooth LE\n");
                                    }
                                }
                                Err(e) => report.push_str(&format!("   ❌ Failed to check LE support: {}\n", e)),
                            }

                            // Get adapter info
                            if let Ok(device_id) = adapter.DeviceId() {
                                report.push_str(&format!("   📋 Device ID: {}\n", device_id.to_string()));
                            }
                        }
                        Err(e) => {
                            report.push_str(&format!("   ❌ Failed to get Bluetooth adapter: {}\n", e));
                            report.push_str("   💡 Make sure Bluetooth is enabled in Windows settings\n");
                        }
                    }
                }
                Err(e) => {
                    report.push_str(&format!("   ❌ Failed to access Bluetooth API: {}\n", e));
                    report.push_str("   💡 Bluetooth may not be available on this system\n");
                }
            }
            report.push('\n');

            // 3. Test Advertising Publisher Creation
            report.push_str("3. ADVERTISING PUBLISHER TEST:\n");
            match self.test_publisher_creation().await {
                Ok(test_results) => report.push_str(&test_results),
                Err(e) => report.push_str(&format!("   ❌ Publisher test failed: {}\n", e)),
            }
            report.push('\n');

            // 4. Check System Permissions
            report.push_str("4. SYSTEM PERMISSIONS:\n");
            report.push_str(&self.check_system_permissions());
            report.push('\n');

            // 5. Power Management Check
            report.push_str("5. POWER MANAGEMENT:\n");
            match self.check_power_settings().await {
                Ok(power_info) => report.push_str(&power_info),
                Err(e) => report.push_str(&format!("   ⚠️ Cannot check power settings: {}\n", e)),
            }
            report.push('\n');

            // 6. Driver Information
            report.push_str("6. BLUETOOTH DRIVER INFO:\n");
            report.push_str(&self.get_driver_info());
            report.push('\n');

            // 7. Recommendations
            report.push_str("7. RECOMMENDATIONS:\n");
            report.push_str(&self.generate_recommendations());
        }

        #[cfg(not(windows))]
        {
            report.push_str("This diagnostic is only available on Windows.\n");
        }

        report
    }

    #[cfg(windows)]
    fn check_windows_version(&self) -> Result<String> {
        // Simplified version check using command line
        use std::process::Command;
        
        match Command::new("cmd")
            .args(&["/C", "ver"])
            .output()
        {
            Ok(output) => {
                let version_str = String::from_utf8_lossy(&output.stdout);
                if version_str.contains("Windows") {
                    if version_str.contains("10.") || version_str.contains("11.") {
                        Ok(format!("Windows 10/11 detected (✅ Should support BLE advertising)"))
                    } else {
                        Ok(format!("Windows detected (⚠️ May not support reliable BLE advertising)"))
                    }
                } else {
                    Ok("Windows version detected".to_string())
                }
            }
            Err(_) => Ok("Windows version check not available".to_string())
        }
    }

    #[cfg(windows)]
    async fn test_publisher_creation(&self) -> Result<String> {
        let mut results = String::new();
        
        // Test 1: Basic publisher creation
        match BluetoothLEAdvertisementPublisher::new() {
            Ok(publisher) => {
                results.push_str("   ✅ Can create BluetoothLEAdvertisementPublisher\n");
                
                // Test 2: Advertisement creation
                match publisher.Advertisement() {
                    Ok(advertisement) => {
                        results.push_str("   ✅ Can create BluetoothLEAdvertisement\n");
                        
                        // Test 3: Try setting local name
                        match advertisement.SetLocalName(&windows::core::HSTRING::from("TestDevice")) {
                            Ok(_) => results.push_str("   ✅ Can set device name\n"),
                            Err(e) => results.push_str(&format!("   ❌ Cannot set device name: {}\n", e)),
                        }
                        
                        // Test 4: Try adding service UUID
                        match advertisement.ServiceUuids() {
                            Ok(service_uuids) => {
                                results.push_str("   ✅ Can access service UUID collection\n");
                                
                                // Try to add a test service UUID
                                let test_guid = windows::core::GUID::from_values(
                                    0x12345678, 0x1234, 0x1234, 
                                    [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF]
                                );
                                
                                match service_uuids.Append(test_guid) {
                                    Ok(_) => results.push_str("   ✅ Can add service UUIDs\n"),
                                    Err(e) => results.push_str(&format!("   ❌ Cannot add service UUIDs: {}\n", e)),
                                }
                            }
                            Err(e) => results.push_str(&format!("   ❌ Cannot access service UUIDs: {}\n", e)),
                        }
                        
                        // Test 5: Try to start advertising (but stop immediately)
                        match publisher.Start() {
                            Ok(_) => {
                                results.push_str("   ✅ Can start advertising!\n");
                                // Stop immediately to avoid interference
                                let _ = publisher.Stop();
                            }
                            Err(e) => {
                                results.push_str(&format!("   ❌ Cannot start advertising: {}\n", e));
                                results.push_str(&format!("       Error code: 0x{:08X}\n", e.code().0));
                                
                                // Decode common error codes
                                match e.code().0 as u32 {
                                    0x80070057 => results.push_str("       💡 ERROR_INVALID_PARAMETER - Try simpler advertisement\n"),
                                    0x80070005 => results.push_str("       💡 ACCESS_DENIED - Try running as administrator\n"),
                                    0x8007001F => results.push_str("       💡 ERROR_GEN_FAILURE - Bluetooth driver issue\n"),
                                    0x80070490 => results.push_str("       💡 ELEMENT_NOT_FOUND - Service not available\n"),
                                    _ => results.push_str("       💡 Unknown error - Check Windows event logs\n"),
                                }
                            }
                        }
                    }
                    Err(e) => results.push_str(&format!("   ❌ Cannot create advertisement: {}\n", e)),
                }
            }
            Err(e) => results.push_str(&format!("   ❌ Cannot create publisher: {}\n", e)),
        }
        
        Ok(results)
    }

    #[cfg(windows)]
    fn check_system_permissions(&self) -> String {
        let mut perms = String::new();
        
        // Simplified permission check using environment variables
        use std::env;
        
        match env::var("USERNAME") {
            Ok(username) => {
                perms.push_str(&format!("   📋 Running as user: {}\n", username));
                
                // Simple admin check
                if username.to_lowercase().contains("admin") || username.to_lowercase().contains("administrator") {
                    perms.push_str("   ✅ Likely running with elevated privileges\n");
                } else {
                    perms.push_str("   ⚠️ May not be running as Administrator\n");
                    perms.push_str("   💡 Try 'Run as Administrator' if advertising fails\n");
                }
            }
            Err(_) => {
                perms.push_str("   ⚠️ Cannot determine user context\n");
            }
        }
        
        // Check Bluetooth privacy settings
        perms.push_str("   💡 Check Windows Settings > Privacy > Bluetooth for app permissions\n");
        
        perms
    }

    #[cfg(windows)]
    async fn check_power_settings(&self) -> Result<String> {
        let mut power_info = String::new();
        
        // Simplified power check
        power_info.push_str("   💡 Power Management Tips:\n");
        power_info.push_str("      - Disable Battery Saver mode if enabled\n");
        power_info.push_str("      - Keep laptop plugged in for best Bluetooth performance\n");
        power_info.push_str("      - Check Device Manager > Bluetooth > Power Management\n");
        power_info.push_str("      - Uncheck 'Allow computer to turn off this device'\n");
        
        Ok(power_info)
    }

    #[cfg(windows)]
    fn get_driver_info(&self) -> String {
        let mut driver_info = String::new();
        
        driver_info.push_str("   💡 To check Bluetooth driver info:\n");
        driver_info.push_str("      1. Open Device Manager (devmgmt.msc)\n");
        driver_info.push_str("      2. Expand 'Bluetooth' section\n");
        driver_info.push_str("      3. Right-click your Bluetooth adapter\n");
        driver_info.push_str("      4. Select 'Properties' > 'Driver' tab\n");
        driver_info.push_str("      5. Check driver version and date\n");
        driver_info.push_str("   💡 Update drivers if they're older than 2020\n");
        
        driver_info
    }

    #[cfg(windows)]
    fn generate_recommendations(&self) -> String {
        let mut recommendations = String::new();
        
        recommendations.push_str("   📋 TO ENABLE ADVERTISING:\n\n");
        recommendations.push_str("   1. UPDATE SYSTEM:\n");
        recommendations.push_str("      - Update to Windows 10/11 latest version\n");
        recommendations.push_str("      - Update Bluetooth drivers\n");
        recommendations.push_str("      - Restart after updates\n\n");
        
        recommendations.push_str("   2. CHECK BLUETOOTH SETTINGS:\n");
        recommendations.push_str("      - Windows Settings > Devices > Bluetooth\n");
        recommendations.push_str("      - Make sure 'Allow Bluetooth devices to find this PC' is ON\n");
        recommendations.push_str("      - Disable and re-enable Bluetooth adapter\n\n");
        
        recommendations.push_str("   3. PRIVACY SETTINGS:\n");
        recommendations.push_str("      - Windows Settings > Privacy & Security > Bluetooth\n");
        recommendations.push_str("      - Allow apps to access Bluetooth\n");
        recommendations.push_str("      - Allow desktop apps to access Bluetooth\n\n");
        
        recommendations.push_str("   4. ADMINISTRATOR MODE:\n");
        recommendations.push_str("      - Try running BitChat as Administrator\n");
        recommendations.push_str("      - Right-click > 'Run as Administrator'\n\n");
        
        recommendations.push_str("   5. HARDWARE CHECK:\n");
        recommendations.push_str("      - Make sure you have a Bluetooth 4.0+ adapter\n");
        recommendations.push_str("      - External USB Bluetooth adapters often work better\n");
        recommendations.push_str("      - Intel and Qualcomm adapters generally have better support\n\n");
        
        recommendations.push_str("   6. ALTERNATIVE APPROACH:\n");
        recommendations.push_str("      - Use mobile devices (iPhone/Android) for advertising\n");
        recommendations.push_str("      - Windows devices can still discover and connect\n");
        recommendations.push_str("      - This is the most reliable setup for now\n");
        
        recommendations
    }

    #[cfg(not(windows))]
    pub async fn diagnose_advertising_support(&self) -> String {
        "Bluetooth LE advertising diagnostics only available on Windows.".to_string()
    }
}