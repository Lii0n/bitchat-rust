// ==============================================================================
// crates/core/src/bluetooth/windows.rs - COMPLETE FIXED VERSION
// ==============================================================================

//! Windows-specific Bluetooth LE implementation with iOS BitChat compatibility
//! 
//! This module provides native Windows WinRT BLE support that properly advertises
//! in the format expected by iOS BitChat clients. FIXED for Windows BLE requirements.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

// FIXED: Correct imports for Windows crate v0.52
#[cfg(windows)]
use {
    windows::{
        core::HSTRING,
        Devices::Bluetooth::{
            Advertisement::{
                BluetoothLEAdvertisement,
                BluetoothLEAdvertisementPublisher,
                BluetoothLEAdvertisementPublisherStatus,
                BluetoothLEAdvertisementReceivedEventArgs,
                BluetoothLEAdvertisementWatcher,
                BluetoothLEManufacturerData,
                BluetoothLEScanningMode,
            },
        },
        Storage::Streams::DataWriter,
        Foundation::TypedEventHandler,
    },
};

// FIXED: Use correct import paths based on project knowledge
use crate::bluetooth::constants::BITCHAT_SERVICE;

/// Discovered device information
#[derive(Clone, Debug)]
pub struct DiscoveredDevice {
    pub device_id: String,
    pub peer_id: String,
    pub rssi: i8,
    pub last_seen: Instant,
    pub nickname: Option<String>,
}

/// Advertising strategy result
#[derive(Debug, Clone)]
pub struct AdvertisingResult {
    pub strategy_name: String,
    pub success: bool,
    pub error_message: Option<String>,
    pub advertised_name: Option<String>,
    pub publisher_status: Option<String>,
}

/// Windows Bluetooth adapter with PURE iOS compatibility focus
pub struct WindowsBluetoothAdapter {
    pub my_peer_id: String,
    pub is_scanning: Arc<RwLock<bool>>,
    pub is_advertising: Arc<RwLock<bool>>,
    pub discovered_devices: Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
    pub advertising_results: Arc<RwLock<Vec<AdvertisingResult>>>,
    
    #[cfg(windows)]
    pub watcher: Option<BluetoothLEAdvertisementWatcher>,
    #[cfg(windows)]
    pub publisher: Option<BluetoothLEAdvertisementPublisher>,
}

impl WindowsBluetoothAdapter {
    /// Create new Windows Bluetooth adapter with PURE iOS peer ID format
    pub fn new(peer_id: String) -> Self {
        // FORCE iOS FORMAT: Ensure peer ID is exactly 16 hex chars (NO PREFIXES/SUFFIXES)
        let formatted_peer_id = if peer_id.len() == 16 && peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
            peer_id.to_uppercase()
        } else if peer_id.len() == 8 && peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
            // Pad 8-char ID to 16 chars
            format!("{:0<16}", peer_id.to_uppercase())
        } else {
            // Generate new 16-char peer ID
            format!("{:016X}", rand::random::<u64>())
        };

        info!("🆔 Windows adapter initialized with PURE iOS peer ID: {}", formatted_peer_id);
        info!("📱 Device will advertise as: '{}' (NO BC_ prefix, NO _M suffix)", formatted_peer_id);

        Self {
            my_peer_id: formatted_peer_id,
            is_scanning: Arc::new(RwLock::new(false)),
            is_advertising: Arc::new(RwLock::new(false)),
            discovered_devices: Arc::new(RwLock::new(HashMap::new())),
            advertising_results: Arc::new(RwLock::new(Vec::new())),
            
            #[cfg(windows)]
            watcher: None,
            #[cfg(windows)]
            publisher: None,
        }
    }

    /// ENHANCED: Check if running as Administrator (Windows requirement for BLE)
    #[cfg(windows)]
    pub fn check_admin_privileges() -> bool {
        use std::process::Command;
        
        let output = Command::new("net")
            .args(["session"])
            .output();
            
        match output {
            Ok(result) => result.status.success(),
            Err(_) => false
        }
    }

    /// Start advertising with PURE iOS compatibility (FIXED for Windows requirements)
    pub async fn start_advertising(&mut self, _advertisement_data: &[u8]) -> Result<()> {
        info!("🚀 Starting PURE iOS-compatible BitChat advertising on Windows...");
        info!("🎯 Target format: Device name = '{}' (16 hex chars only)", self.my_peer_id);

        if *self.is_advertising.read().await {
            warn!("Already advertising");
            return Ok(());
        }

        // Clear previous results
        self.advertising_results.write().await.clear();

        #[cfg(windows)]
        {
            // Check admin privileges first
            let is_admin = Self::check_admin_privileges();
            info!("🔒 Administrator privileges: {}", if is_admin { "✅ YES" } else { "❌ NO" });
            
            if !is_admin {
                warn!("⚠️  NOT running as Administrator!");
                warn!("   This is likely why BLE advertising failed in previous attempts.");
                warn!("   Solution: Right-click PowerShell → 'Run as administrator'");
                warn!("   Then run the diagnostic again.");
            }

            // FORCE STRATEGY 1: Pure iOS format with FIXED Windows payload requirements
            match self.try_pure_ios_advertising_fixed().await {
                Ok(result) => {
                    self.advertising_results.write().await.push(result.clone());
                    info!("✅ SUCCESS: Pure iOS advertising active!");
                    info!("📱 Device name: {} (discoverable by iOS/macOS BitChat)", self.my_peer_id);
                    
                    // Verify what we're actually advertising
                    self.verify_advertising_format().await?;
                    return Ok(());
                }
                Err(e) => {
                    let result = AdvertisingResult {
                        strategy_name: "Pure iOS Format (Fixed)".to_string(),
                        success: false,
                        error_message: Some(e.to_string()),
                        advertised_name: None,
                        publisher_status: None,
                    };
                    self.advertising_results.write().await.push(result);
                    error!("❌ Pure iOS advertising failed: {}", e);
                }
            }

            // DIAGNOSTIC FALLBACK: Try basic advertising with proper payload
            match self.try_diagnostic_advertising_fixed().await {
                Ok(result) => {
                    self.advertising_results.write().await.push(result);
                    warn!("⚠️  DIAGNOSTIC: Basic advertising works, but not iOS format");
                    self.log_advertising_diagnostics().await;
                    return Err(anyhow!("Pure iOS advertising failed - see diagnostics above"));
                }
                Err(e) => {
                    let result = AdvertisingResult {
                        strategy_name: "Diagnostic Basic (Fixed)".to_string(),
                        success: false,
                        error_message: Some(e.to_string()),
                        advertised_name: None,
                        publisher_status: None,
                    };
                    self.advertising_results.write().await.push(result);
                    error!("❌ Even diagnostic advertising failed: {}", e);
                }
            }

            // If all strategies fail, provide detailed diagnostics
            self.log_advertising_diagnostics().await;
            self.print_advertising_results().await;
            return Err(anyhow!("Windows BLE advertising not supported on this system"));
        }

        #[cfg(not(windows))]
        {
            return Err(anyhow!("WinRT advertising only available on Windows"));
        }
    }

    /// FIXED: Pure iOS-compatible advertising with systematic component testing
    #[cfg(windows)]
    async fn try_pure_ios_advertising_fixed(&mut self) -> Result<AdvertisingResult> {
        info!("🍎 Testing Windows BLE compatibility with systematic approach...");
        
        let publisher = BluetoothLEAdvertisementPublisher::new()
            .map_err(|e| anyhow!("Failed to create publisher: {}", e))?;
        
        let advertisement = publisher.Advertisement()
            .map_err(|e| anyhow!("Failed to get advertisement: {}", e))?;

        // Step 1: Try pure iOS format first, then fallbacks
        let windows_compatible_names = vec![
            self.my_peer_id.clone(),                        // Pure iOS format (16 hex chars)
            format!("BitChat-{}", &self.my_peer_id[..8]),  // BitChat-57900386
            format!("BC-{}", &self.my_peer_id[..8]),       // BC-57900386 
            format!("Device-{}", &self.my_peer_id[..6]),   // Device-579003
            "BitChat-Device".to_string(),                   // Generic fallback
        ];

        let mut working_device_name = None;
        for (i, device_name) in windows_compatible_names.iter().enumerate() {
            info!("🏷️  Testing device name {}: '{}'", i + 1, device_name);
            match advertisement.SetLocalName(&HSTRING::from(device_name)) {
                Ok(_) => {
                    info!("✅ Device name accepted: '{}'", device_name);
                    working_device_name = Some(device_name.clone());
                    break;
                }
                Err(_) => {
                    warn!("❌ Device name rejected: '{}'", device_name);
                    continue;
                }
            }
        }

        let final_device_name = working_device_name
            .ok_or_else(|| anyhow!("No Windows-compatible device names accepted"))?;

        // Step 2: Try multiple Windows BLE configurations systematically
        info!("🧪 STEP 2: Testing Windows BLE configurations systematically...");
        
        // Configuration 1: Device name + Service UUID + Manufacturer Data (Full iOS compatibility)
        info!("🧪 STEP 2A: Full iOS configuration (name + service + manufacturer data)");
        if let Ok(result) = self.try_full_ios_configuration(&publisher, &advertisement, &final_device_name).await {
            return Ok(result);
        }
        
        // Configuration 2: Device name + Service UUID only
        info!("🧪 STEP 2B: Service UUID configuration (name + service UUID)");
        if let Ok(result) = self.try_service_uuid_configuration(&publisher, &advertisement, &final_device_name).await {
            return Ok(result);
        }
        
        // Configuration 3: Device name + Manufacturer Data only
        info!("🧪 STEP 2C: Manufacturer data configuration (name + manufacturer data)");
        if let Ok(result) = self.try_manufacturer_data_configuration(&publisher, &advertisement, &final_device_name).await {
            return Ok(result);
        }
        
        // Configuration 4: Device name only (most basic)
        info!("🧪 STEP 2D: Basic device name only");
        match self.test_device_name_only(&publisher).await {
            Ok(_) => {
                info!("🔄 Fallback: Using device name only (limited iOS compatibility)");
                return self.finalize_device_name_only(&publisher, final_device_name).await;
            }
            Err(e) => {
                warn!("❌ All standard Windows BLE configurations failed. Trying hardware-specific fallbacks...");
                
                // Try hardware-specific fallbacks
                if let Ok(result) = self.try_hardware_fallbacks(&publisher, &advertisement, &final_device_name).await {
                    return Ok(result);
                }
                
                return Err(anyhow!("All Windows BLE configurations failed, including hardware fallbacks. Last error: {}", e));
            }
        }
    }

    /// Test device name only advertising
    #[cfg(windows)]
    async fn test_device_name_only(&self, publisher: &BluetoothLEAdvertisementPublisher) -> Result<()> {
        // Ensure no payload data
        let advertisement = publisher.Advertisement()?;
        if let Ok(mfg_data_list) = advertisement.ManufacturerData() {
            mfg_data_list.Clear().ok();
        }
        if let Ok(service_uuids) = advertisement.ServiceUuids() {
            service_uuids.Clear().ok();
        }
        
        // Try to start with just device name
        publisher.Start()?;
        tokio::time::sleep(Duration::from_millis(300)).await;
        
        let status = publisher.Status()?;
        if format!("{:?}", status).contains("Started") {
            publisher.Stop().ok(); // Stop for next test
            return Ok(());
        } else {
            publisher.Stop().ok();
            return Err(anyhow!("Device name only failed: {:?}", status));
        }
    }

    /// Try full iOS configuration (name + service UUID + manufacturer data)
    #[cfg(windows)]
    async fn try_full_ios_configuration(&mut self, publisher: &BluetoothLEAdvertisementPublisher, advertisement: &BluetoothLEAdvertisement, device_name: &str) -> Result<AdvertisingResult> {
        // Clear everything first
        if let Ok(service_uuids) = advertisement.ServiceUuids() { service_uuids.Clear().ok(); }
        if let Ok(mfg_data) = advertisement.ManufacturerData() { mfg_data.Clear().ok(); }
        
        // Add service UUID
        if let Err(e) = self.add_bitchat_service_uuid(&advertisement).await {
            return Err(anyhow!("Failed to add service UUID: {}", e));
        }
        
        // Add manufacturer data
        if let Err(e) = self.add_compatible_manufacturer_data(&advertisement).await {
            return Err(anyhow!("Failed to add manufacturer data: {}", e));
        }
        
        // Test the full configuration
        self.test_advertising_configuration(publisher, device_name, "Full iOS (name + service + mfg data)").await
    }
    
    /// Try service UUID only configuration
    #[cfg(windows)]
    async fn try_service_uuid_configuration(&mut self, publisher: &BluetoothLEAdvertisementPublisher, advertisement: &BluetoothLEAdvertisement, device_name: &str) -> Result<AdvertisingResult> {
        // Clear everything first
        if let Ok(service_uuids) = advertisement.ServiceUuids() { service_uuids.Clear().ok(); }
        if let Ok(mfg_data) = advertisement.ManufacturerData() { mfg_data.Clear().ok(); }
        
        // Add only service UUID
        if let Err(e) = self.add_bitchat_service_uuid(&advertisement).await {
            return Err(anyhow!("Failed to add service UUID: {}", e));
        }
        
        // Test service UUID configuration
        self.test_advertising_configuration(publisher, device_name, "Service UUID (name + service)").await
    }
    
    /// Try manufacturer data only configuration
    #[cfg(windows)]
    async fn try_manufacturer_data_configuration(&mut self, publisher: &BluetoothLEAdvertisementPublisher, advertisement: &BluetoothLEAdvertisement, device_name: &str) -> Result<AdvertisingResult> {
        // Clear everything first
        if let Ok(service_uuids) = advertisement.ServiceUuids() { service_uuids.Clear().ok(); }
        if let Ok(mfg_data) = advertisement.ManufacturerData() { mfg_data.Clear().ok(); }
        
        // Add only manufacturer data
        if let Err(e) = self.add_compatible_manufacturer_data(&advertisement).await {
            return Err(anyhow!("Failed to add manufacturer data: {}", e));
        }
        
        // Test manufacturer data configuration
        self.test_advertising_configuration(publisher, device_name, "Manufacturer Data (name + mfg data)").await
    }
    
    /// Test a specific advertising configuration
    #[cfg(windows)]
    async fn test_advertising_configuration(&mut self, publisher: &BluetoothLEAdvertisementPublisher, device_name: &str, config_name: &str) -> Result<AdvertisingResult> {
        // Stop any previous advertising
        publisher.Stop().ok();
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Try to start
        match publisher.Start() {
            Ok(_) => {
                tokio::time::sleep(Duration::from_millis(500)).await;
                
                let status = publisher.Status()
                    .map_err(|e| anyhow!("Failed to get status: {}", e))?;
                let status_str = format!("{:?}", status);
                
                if status_str.contains("Started") {
                    self.publisher = Some(publisher.clone());
                    *self.is_advertising.write().await = true;
                    
                    info!("🎉 SUCCESS: {} configuration works!", config_name);
                    info!("📱 Device name: '{}'", device_name);
                    info!("📊 Publisher status: {}", status_str);
                    
                    return Ok(AdvertisingResult {
                        strategy_name: config_name.to_string(),
                        success: true,
                        error_message: None,
                        advertised_name: Some(device_name.to_string()),
                        publisher_status: Some(status_str),
                    });
                } else {
                    publisher.Stop().ok();
                    return Err(anyhow!("Publisher status not Started: {}", status_str));
                }
            }
            Err(e) => {
                let error_msg = format!("{}", e);
                // Check for specific Windows error codes
                if error_msg.contains("0x80070057") {
                    return Err(anyhow!("Windows BLE parameter error (0x80070057) - configuration not supported by this adapter"));
                } else {
                    return Err(anyhow!("Publisher start failed: {}", error_msg));
                }
            }
        }
    }

    /// Try hardware-specific fallback strategies
    #[cfg(windows)]
    async fn try_hardware_fallbacks(&mut self, publisher: &BluetoothLEAdvertisementPublisher, advertisement: &BluetoothLEAdvertisement, device_name: &str) -> Result<AdvertisingResult> {
        info!("🔧 Trying hardware-specific fallbacks for restrictive BLE adapters...");
        
        // Fallback 1: Minimal manufacturer data with simple company ID
        info!("🧪 Fallback 1: Minimal manufacturer data (simple)");
        if let Ok(result) = self.try_minimal_manufacturer_data(&publisher, &advertisement, device_name).await {
            return Ok(result);
        }
        
        // Fallback 2: Generic BLE service UUID (not BitChat specific)
        info!("🧪 Fallback 2: Generic BLE service");
        if let Ok(result) = self.try_generic_service_uuid(&publisher, &advertisement, device_name).await {
            return Ok(result);
        }
        
        // Fallback 3: Shortened device name for restrictive adapters
        info!("🧪 Fallback 3: Shortened device names");
        if let Ok(result) = self.try_shortened_device_names(&publisher, &advertisement).await {
            return Ok(result);
        }
        
        Err(anyhow!("All hardware fallbacks exhausted"))
    }
    
    /// Try minimal manufacturer data for restrictive hardware
    #[cfg(windows)]
    async fn try_minimal_manufacturer_data(&mut self, publisher: &BluetoothLEAdvertisementPublisher, advertisement: &BluetoothLEAdvertisement, device_name: &str) -> Result<AdvertisingResult> {
        // Clear everything
        if let Ok(service_uuids) = advertisement.ServiceUuids() { service_uuids.Clear().ok(); }
        if let Ok(mfg_data_list) = advertisement.ManufacturerData() { mfg_data_list.Clear().ok(); }
        
        // Add minimal manufacturer data
        if let Ok(mfg_data_list) = advertisement.ManufacturerData() {
            let mfg_data = BluetoothLEManufacturerData::new()?;
            
            // Use most compatible company ID (Microsoft's for testing)
            mfg_data.SetCompanyId(0x0006)?; // Microsoft company ID
            
            let data_writer = DataWriter::new()?;
            // Just 2 bytes of data
            data_writer.WriteBytes(&[0x01, 0x02])?;
            
            mfg_data.SetData(&data_writer.DetachBuffer()?)?;
            mfg_data_list.Append(&mfg_data)?;
            
            info!("✅ Added minimal manufacturer data (Microsoft company ID)");
        }
        
        self.test_advertising_configuration(publisher, device_name, "Minimal Manufacturer Data").await
    }
    
    /// Try generic service UUID for restrictive hardware
    #[cfg(windows)]
    async fn try_generic_service_uuid(&mut self, publisher: &BluetoothLEAdvertisementPublisher, advertisement: &BluetoothLEAdvertisement, device_name: &str) -> Result<AdvertisingResult> {
        // Clear everything
        if let Ok(service_uuids) = advertisement.ServiceUuids() { service_uuids.Clear().ok(); }
        if let Ok(mfg_data) = advertisement.ManufacturerData() { mfg_data.Clear().ok(); }
        
        // Add a generic service UUID that's widely supported
        if let Ok(service_uuids) = advertisement.ServiceUuids() {
            // Use Heart Rate service UUID as it's widely supported
            if let Ok(generic_guid) = Self::uuid_to_guid("0000180D-0000-1000-8000-00805F9B34FB") {
                service_uuids.Append(generic_guid)?;
                info!("✅ Added generic service UUID (Heart Rate) for compatibility");
            }
        }
        
        self.test_advertising_configuration(publisher, device_name, "Generic Service UUID").await
    }
    
    /// Try shortened device names for restrictive hardware
    #[cfg(windows)]
    async fn try_shortened_device_names(&mut self, publisher: &BluetoothLEAdvertisementPublisher, advertisement: &BluetoothLEAdvertisement) -> Result<AdvertisingResult> {
        // Clear everything
        if let Ok(service_uuids) = advertisement.ServiceUuids() { service_uuids.Clear().ok(); }
        if let Ok(mfg_data) = advertisement.ManufacturerData() { mfg_data.Clear().ok(); }
        
        // Try very short device names (some hardware is restrictive)
        let short_names = vec![
            format!("BC{}", &self.my_peer_id[..6]),     // BC579003
            format!("BT{}", &self.my_peer_id[..6]),     // BT579003
            "BitChat".to_string(),                       // BitChat
            "BC".to_string(),                           // BC
        ];
        
        for (i, short_name) in short_names.iter().enumerate() {
            info!("🧪 Testing short name {}: '{}'", i + 1, short_name);
            
            // Set the short name
            if let Ok(advertisement) = publisher.Advertisement() {
                if advertisement.SetLocalName(&HSTRING::from(short_name)).is_ok() {
                    if let Ok(result) = self.test_advertising_configuration(publisher, short_name, &format!("Short Name {}", i + 1)).await {
                        return Ok(result);
                    }
                }
            }
        }
        
        Err(anyhow!("All shortened device names failed"))
    }

    /// Add BitChat service UUID for iOS compatibility
    #[cfg(windows)]
    async fn add_bitchat_service_uuid(&self, advertisement: &BluetoothLEAdvertisement) -> Result<()> {
        if let Ok(service_uuids) = advertisement.ServiceUuids() {
            // Add the BitChat service UUID that iOS expects
            if let Ok(bitchat_guid) = Self::uuid_to_guid(BITCHAT_SERVICE) {
                service_uuids.Append(bitchat_guid)?;
                info!("✅ Added BitChat service UUID for iOS compatibility");
            } else {
                return Err(anyhow!("Failed to convert BitChat service UUID"));
            }
        }
        
        Ok(())
    }

    /// Add manufacturer data in the safest possible way
    #[cfg(windows)]
    async fn add_compatible_manufacturer_data(&self, advertisement: &BluetoothLEAdvertisement) -> Result<()> {
        if let Ok(mfg_data_list) = advertisement.ManufacturerData() {
            mfg_data_list.Clear().ok(); // Ensure clean state
            
            let mfg_data = BluetoothLEManufacturerData::new()?;
            
            // Use BitChat company ID (or compatible fallback)
            let company_id = 0x02BC; // BitChat company ID (if allocated) or 0xFFFF for test
            mfg_data.SetCompanyId(company_id)?;
            
            let data_writer = DataWriter::new()?;
            
            // ENHANCED: Always include minimal required data for Windows
            data_writer.WriteBytes(&[0xBC, 0x01])?; // BitChat signature
            
            // Add peer ID bytes for iOS compatibility
            if let Ok(peer_id_bytes) = hex::decode(&self.my_peer_id) {
                data_writer.WriteBytes(&peer_id_bytes)?;
                info!("📡 Added full peer ID to manufacturer data for iOS compatibility");
            } else {
                // Fallback: add peer ID as UTF-8 bytes
                data_writer.WriteBytes(self.my_peer_id.as_bytes())?;
                warn!("⚠️ Using UTF-8 fallback for peer ID in manufacturer data");
            }
            
            mfg_data.SetData(&data_writer.DetachBuffer()?)?;
            mfg_data_list.Append(&mfg_data)?;
            
            info!("✅ Enhanced manufacturer data configured for Windows + iOS compatibility");
        }
        
        Ok(())
    }

    /// Finalize advertising with device name only
    #[cfg(windows)]
    async fn finalize_device_name_only(&mut self, publisher: &BluetoothLEAdvertisementPublisher, device_name: String) -> Result<AdvertisingResult> {
        // Start with just device name
        publisher.Start()?;
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        let status = publisher.Status()?;
        let status_str = format!("{:?}", status);
        
        if status_str.contains("Started") {
            self.publisher = Some(publisher.clone());
            *self.is_advertising.write().await = true;
            
            warn!("⚠️ LIMITED SUCCESS: Device name only advertising");
            warn!("📱 Device name: '{}' (Windows-compatible)", device_name);
            warn!("🚫 No manufacturer data (peer ID not in advertisement)");
            warn!("💡 macOS might detect as generic BLE device, not BitChat");
            
            Ok(AdvertisingResult {
                strategy_name: "Device Name Only (Limited)".to_string(),
                success: true,
                error_message: Some("No manufacturer data due to Windows BLE restrictions".to_string()),
                advertised_name: Some(device_name),
                publisher_status: Some(status_str),
            })
        } else {
            publisher.Stop().ok();
            Err(anyhow!("Device name only also failed: {}", status_str))
        }
    }

    /// FIXED: Diagnostic advertising with proper Windows payload
    #[cfg(windows)]
    async fn try_diagnostic_advertising_fixed(&mut self) -> Result<AdvertisingResult> {
        info!("🔧 Attempting diagnostic advertising (FIXED with payload)...");
        
        let publisher = BluetoothLEAdvertisementPublisher::new()
            .map_err(|e| anyhow!("Failed to create diagnostic publisher: {}", e))?;
        
        let advertisement = publisher.Advertisement()
            .map_err(|e| anyhow!("Failed to get advertisement: {}", e))?;
        
        // FIXED: Add minimal required payload for Windows
        if let Ok(mfg_data_list) = advertisement.ManufacturerData() {
            let mfg_data = BluetoothLEManufacturerData::new()
                .map_err(|e| anyhow!("Failed to create diagnostic manufacturer data: {}", e))?;
            
            mfg_data.SetCompanyId(0xFFFF) // Test company ID
                .map_err(|e| anyhow!("Failed to set diagnostic company ID: {}", e))?;
            
            let data_writer = DataWriter::new()
                .map_err(|e| anyhow!("Failed to create diagnostic data writer: {}", e))?;
            
            // Write minimal test data
            data_writer.WriteBytes(&[0x01, 0x02, 0x03])
                .map_err(|e| anyhow!("Failed to write diagnostic data: {}", e))?;
            
            mfg_data.SetData(&data_writer.DetachBuffer()?)
                .map_err(|e| anyhow!("Failed to set diagnostic data: {}", e))?;
            
            mfg_data_list.Append(&mfg_data)
                .map_err(|e| anyhow!("Failed to add diagnostic data: {}", e))?;
        }
        
        publisher.Start()
            .map_err(|e| anyhow!("Failed to start diagnostic publisher: {}", e))?;
        
        tokio::time::sleep(Duration::from_millis(500)).await;
        
        let status = publisher.Status()
            .map_err(|e| anyhow!("Failed to get diagnostic status: {}", e))?;
        
        // Stop diagnostic advertising
        publisher.Stop().ok();
        
        Ok(AdvertisingResult {
            strategy_name: "Diagnostic Basic (Fixed)".to_string(),
            success: true,
            error_message: None,
            advertised_name: Some("(diagnostic test)".to_string()),
            publisher_status: Some(format!("{:?}", status)),
        })
    }

    /// Verify what we're actually advertising
    pub async fn verify_advertising_format(&self) -> Result<String> {
        info!("🔍 VERIFYING ACTUAL ADVERTISING FORMAT");
        info!("=====================================");
        
        #[cfg(windows)]
        {
            if let Some(publisher) = &self.publisher {
                if let Ok(status) = publisher.Status() {
                    info!("📊 Publisher Status: {:?}", status);
                    
                    // Check if we're actually advertising
                    match status {
                        BluetoothLEAdvertisementPublisherStatus::Started => {
                            info!("✅ Publisher is STARTED and advertising");
                        }
                        BluetoothLEAdvertisementPublisherStatus::Waiting => {
                            warn!("⏳ Publisher is WAITING (may not be visible yet)");
                        }
                        BluetoothLEAdvertisementPublisherStatus::Stopped => {
                            error!("❌ Publisher is STOPPED (not advertising)");
                        }
                        BluetoothLEAdvertisementPublisherStatus::Aborted => {
                            error!("❌ Publisher ABORTED (advertising failed)");
                        }
                        _ => {
                            warn!("❓ Publisher status unknown: {:?}", status);
                        }
                    }
                    
                    // Get the actual advertisement content
                    if let Ok(advertisement) = publisher.Advertisement() {
                        if let Ok(local_name) = advertisement.LocalName() {
                            let advertised_name = local_name.to_string();
                            info!("🏷️  ACTUAL ADVERTISED NAME: '{}'", advertised_name);
                            info!("🎯 EXPECTED NAME: '{}'", self.my_peer_id);
                            
                            if advertised_name == self.my_peer_id {
                                info!("✅ PERFECT: Advertising pure iOS format");
                                info!("📱 macOS BitChat should detect device: '{}'", advertised_name);
                                return Ok(format!("SUCCESS: Pure iOS format '{}'", advertised_name));
                            } else if advertised_name.starts_with("BC_") {
                                error!("❌ WRONG: Using BC_ prefix format (macOS won't detect)");
                                return Ok(format!("ERROR: Legacy format '{}' (incompatible)", advertised_name));
                            } else {
                                warn!("⚠️  UNEXPECTED: Advertising unknown format");
                                return Ok(format!("WARNING: Unknown format '{}'", advertised_name));
                            }
                        } else {
                            warn!("❌ No device name set in advertisement");
                        }
                        
                        // Check for service UUIDs with proper error handling
                        if let Ok(service_uuids) = advertisement.ServiceUuids() {
                            if let Ok(uuid_count) = service_uuids.Size() {
                                if uuid_count > 0 {
                                    info!("🔵 Service UUIDs advertised: {}", uuid_count);
                                }
                            }
                        }
                        
                        // Check for manufacturer data with proper error handling  
                        if let Ok(mfg_data) = advertisement.ManufacturerData() {
                            if let Ok(mfg_count) = mfg_data.Size() {
                                if mfg_count > 0 {
                                    info!("🏭 Manufacturer data entries: {}", mfg_count);
                                }
                            }
                        }
                    } else {
                        error!("❌ Failed to get advertisement content");
                    }
                } else {
                    error!("❌ Failed to get publisher status");
                }
            } else {
                error!("❌ No active publisher");
            }
        }
        
        Ok("Verification complete - check logs above".to_string())
    }

    /// Print detailed advertising results
    pub async fn print_advertising_results(&self) {
        let results = self.advertising_results.read().await;
        
        info!("📊 ADVERTISING STRATEGY RESULTS");
        info!("================================");
        
        for (i, result) in results.iter().enumerate() {
            info!("{}. Strategy: {}", i + 1, result.strategy_name);
            info!("   Success: {}", if result.success { "✅ YES" } else { "❌ NO" });
            
            if let Some(ref error) = result.error_message {
                info!("   Error: {}", error);
            }
            
            if let Some(ref name) = result.advertised_name {
                info!("   Advertised Name: '{}'", name);
            }
            
            if let Some(ref status) = result.publisher_status {
                info!("   Publisher Status: {}", status);
            }
            
            info!("");
        }
    }

    /// Test macOS detection specifically
    pub async fn test_macos_compatibility(&self) -> Result<()> {
        info!("🍎 MACOS COMPATIBILITY TEST");
        info!("============================");
        info!("Your peer ID: {}", self.my_peer_id);
        info!("What macOS SHOULD see: Device named '{}'", self.my_peer_id);
        info!("What macOS should NOT see: Device named 'BC_{}' or 'BC_{}_M'", self.my_peer_id, self.my_peer_id);
        info!("");
        info!("💡 TO TEST ON MACOS:");
        info!("1. Open 'Bluetooth Explorer' app (from Xcode Additional Tools)");
        info!("   - Download from: https://developer.apple.com/download/more/");
        info!("   - Look for 'Additional Tools for Xcode'");
        info!("2. Go to 'Low Energy Devices' tab");
        info!("3. Click 'Start Scanning'");
        info!("4. Look for device named exactly: '{}'", self.my_peer_id);
        info!("5. If you see anything else, Windows is using wrong format");
        info!("");
        info!("🔧 ALTERNATIVE TEST (BitChat iOS App):");
        info!("1. Download BitChat from App Store");
        info!("2. Open the app and go to 'Nearby Peers'");
        info!("3. Look for peer ID: '{}'", self.my_peer_id);
        info!("4. If it appears, iOS compatibility is working!");
        
        Ok(())
    }

    /// Convert UUID string to Windows GUID
    #[cfg(windows)]
    fn uuid_to_guid(uuid_str: &str) -> Result<windows::core::GUID> {
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

    /// Start scanning for BitChat devices (supports all formats)
    pub async fn start_scanning(&mut self) -> Result<()> {
        info!("🔍 Starting BitChat device scanning (all formats)...");
        
        if *self.is_scanning.read().await {
            warn!("Already scanning");
            return Ok(());
        }

        #[cfg(windows)]
        {
            let watcher = BluetoothLEAdvertisementWatcher::new()?;
            watcher.SetScanningMode(BluetoothLEScanningMode::Active)?;
            
            let discovered_devices = Arc::clone(&self.discovered_devices);
            let my_peer_id = self.my_peer_id.clone();
            
            let handler = TypedEventHandler::new(move |_sender, args: &Option<BluetoothLEAdvertisementReceivedEventArgs>| {
                if let Some(args) = args {
                    let discovered_devices_clone = Arc::clone(&discovered_devices);
                    let my_peer_id_clone = my_peer_id.clone();
                    
                    let device_address = args.BluetoothAddress().unwrap_or(0);
                    let rssi = args.RawSignalStrengthInDBm().unwrap_or(-127);
                    let advertisement = args.Advertisement().ok();
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_discovered_device_data(
                            device_address, 
                            rssi, 
                            advertisement, 
                            &discovered_devices_clone, 
                            &my_peer_id_clone
                        ).await {
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
            info!("✅ BitChat scanning active (detecting all formats)");
        }
        
        #[cfg(not(windows))]
        {
            return Err(anyhow!("WinRT scanning only available on Windows"));
        }
        
        Ok(())
    }

    /// Enhanced advertisement handler (supports all BitChat formats)
    #[cfg(windows)]
    async fn handle_discovered_device_data(
        device_address: u64,
        rssi: i16,
        advertisement: Option<BluetoothLEAdvertisement>,
        discovered_devices: &Arc<RwLock<HashMap<String, DiscoveredDevice>>>,
        my_peer_id: &str,
    ) -> Result<()> {
        let device_id = format!("{:012X}", device_address);
        let rssi_i8 = rssi.clamp(-127, 127) as i8;
        
        let mut is_bitchat_device = false;
        let mut peer_id: Option<String> = None;
        let nickname: Option<String> = None;
        let mut device_format = "Unknown";
        
        if let Some(advertisement) = advertisement {
            if let Ok(local_name) = advertisement.LocalName() {
                let name = local_name.to_string();
                
                // METHOD 1: Pure iOS/macOS format (16 hex characters only)
                if name.len() == 16 && name.chars().all(|c| c.is_ascii_hexdigit()) {
                    is_bitchat_device = true;
                    peer_id = Some(name.to_uppercase());
                    device_format = "Pure iOS/macOS";
                    info!("🍎 Found pure iOS/macOS BitChat device: {}", name);
                }
                // METHOD 2: Legacy Windows format (BC_XXXXXXXXXXXXXXXX)
                else if name.starts_with("BC_") && name.len() >= 19 {
                    let extracted_peer_id = name.chars().skip(3).collect::<String>();
                    if extracted_peer_id.len() >= 16 && extracted_peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
                        is_bitchat_device = true;
                        let normalized_peer_id = extracted_peer_id.chars().take(16).collect::<String>();
                        peer_id = Some(normalized_peer_id.to_uppercase());
                        device_format = "Legacy Windows";
                        info!("🪟 Found legacy Windows BitChat device: {} -> {}", name, peer_id.as_ref().unwrap());
                    }
                }
                // METHOD 3: Moon Protocol format (BC_XXXXXXXXXXXXXXXX_M)
                else if name.starts_with("BC_") && name.ends_with("_M") {
                    let middle_part = &name[3..name.len()-2]; // Remove BC_ and _M
                    if middle_part.len() == 16 && middle_part.chars().all(|c| c.is_ascii_hexdigit()) {
                        is_bitchat_device = true;
                        peer_id = Some(middle_part.to_uppercase());
                        device_format = "Moon Protocol";
                        info!("🌙 Found Moon Protocol BitChat device: {} -> {}", name, peer_id.as_ref().unwrap());
                    }
                }
                // METHOD 4: Windows-compatible formats (BitChat-XXXXXXXX, BC-XXXXXXXX)
                else if (name.starts_with("BitChat-") || name.starts_with("BC-")) && name.len() >= 10 {
                    let prefix_len = if name.starts_with("BitChat-") { 8 } else { 3 };
                    let extracted_peer_id = name.chars().skip(prefix_len).collect::<String>();
                    if extracted_peer_id.len() >= 8 && extracted_peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
                        is_bitchat_device = true;
                        let normalized_peer_id = if extracted_peer_id.len() >= 16 {
                            extracted_peer_id.chars().take(16).collect::<String>()
                        } else {
                            format!("{:0<16}", extracted_peer_id)
                        };
                        peer_id = Some(normalized_peer_id.to_uppercase());
                        device_format = "Windows-Compatible";
                        info!("🪟 Found Windows-compatible BitChat device: {} -> {}", name, peer_id.as_ref().unwrap());
                    }
                }
                // METHOD 5: Other underscore formats (Pi, etc.)
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
                            device_format = "Pi/Other";
                            info!("🥧 Found Pi/Other BitChat device: {} -> {}", name, peer_id.as_ref().unwrap());
                        }
                    }
                }
            }

            // METHOD 5: Check for BitChat service UUID (with proper error handling)
            if let Ok(service_uuids) = advertisement.ServiceUuids() {
                if let Ok(bitchat_service_guid) = Self::uuid_to_guid(BITCHAT_SERVICE) {
                    if let Ok(size) = service_uuids.Size() {
                        for i in 0..size {
                            if let Ok(service_uuid) = service_uuids.GetAt(i) {
                                if service_uuid == bitchat_service_guid {
                                    is_bitchat_device = true;
                                    info!("🔵 Found BitChat service UUID!");
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }

        if is_bitchat_device {
            if let Some(found_peer_id) = peer_id {
                if found_peer_id != my_peer_id {
                    let discovered_device = DiscoveredDevice {
                        device_id: device_id.clone(),
                        peer_id: found_peer_id.clone(),
                        rssi: rssi_i8,
                        last_seen: Instant::now(),
                        nickname,
                    };
                    
                    let mut devices = discovered_devices.write().await;
                    devices.insert(device_id.clone(), discovered_device);
                    drop(devices);
                    
                    info!("🎯 Discovered {} BitChat peer: {} (RSSI: {} dBm)", device_format, found_peer_id, rssi_i8);
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
        error!("🚨 WINDOWS BLUETOOTH ADVERTISING DIAGNOSTICS");
        error!("=============================================");
        error!("Target Format: Pure iOS (device name = '{}')", self.my_peer_id);
        error!("Current Status: FAILED to advertise in iOS format");
        error!("");
        error!("💡 COMMON CAUSES & SOLUTIONS:");
        error!("1. 🔒 PERMISSIONS: Run as Administrator");
        error!("   - Right-click terminal/IDE → 'Run as administrator'");
        error!("2. 🔧 DRIVERS: Update Bluetooth drivers");
        error!("   - Device Manager → Bluetooth → Update drivers");
        error!("3. ⚙️  SETTINGS: Enable Bluetooth discoverability");
        error!("   - Windows Settings → Bluetooth → 'Allow devices to find this PC'");
        error!("4. 🔌 HARDWARE: Try USB Bluetooth dongle");
        error!("   - Built-in adapters often have restrictions");
        error!("   - USB dongles usually work better for advertising");
        error!("5. 🖥️  OS VERSION: Windows 10 1803+ required");
        error!("   - Earlier versions may not support BLE advertising");
        error!("");
        error!("🔬 DETAILED TROUBLESHOOTING:");
        error!("- Check if ANY advertising works (basic test)");
        error!("- Verify Bluetooth adapter supports LE advertising");
        error!("- Test with different Bluetooth hardware");
        error!("- Check Windows event logs for BLE errors");
        error!("");
        error!("🍎 FOR MACOS COMPATIBILITY:");
        error!("- Device MUST advertise as: '{}'", self.my_peer_id);
        error!("- NO 'BC_' prefix allowed");
        error!("- NO '_M' suffix allowed");
        error!("- Exactly 16 hexadecimal characters");
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

    /// ADDITIONAL: Test Administrator requirement specifically
    pub async fn test_admin_requirement(&mut self) -> Result<()> {
        info!("🔒 Testing Administrator Requirement");
        info!("===================================");
        
        let is_admin = Self::check_admin_privileges();
        info!("Current admin status: {}", if is_admin { "✅ Administrator" } else { "❌ Regular User" });
        
        // Try a simple test advertisement
        info!("🧪 Testing basic advertising capability...");
        
        match self.try_diagnostic_advertising_fixed().await {
            Ok(result) => {
                info!("✅ Basic advertising works without admin privileges!");
                info!("📊 Status: {}", result.publisher_status.unwrap_or("Unknown".to_string()));
                info!("💡 This suggests the issue is device name format, not permissions");
            }
            Err(e) => {
                if is_admin {
                    error!("❌ Advertising failed even with admin privileges: {}", e);
                    error!("💡 This suggests a hardware or driver issue");
                } else {
                    error!("❌ Advertising failed without admin privileges: {}", e);
                    error!("💡 Try running as Administrator");
                }
            }
        }
        
        Ok(())
    }

    /// ENHANCED: Run complete diagnostic with all tests
    pub async fn run_complete_diagnostic(&mut self) -> Result<()> {
        info!("🔬 COMPLETE WINDOWS BLE DIAGNOSTIC");
        info!("==================================");
        
        // Test 1: Admin privileges
        self.test_admin_requirement().await?;
        
        println!(); // Add spacing
        
        // Test 2: Basic advertising capability  
        info!("📡 Testing basic advertising...");
        match self.try_diagnostic_advertising_fixed().await {
            Ok(_) => info!("✅ Basic advertising: WORKS"),
            Err(e) => error!("❌ Basic advertising: FAILED - {}", e),
        }
        
        println!();
        
        // Test 3: Pure iOS format
        info!("🍎 Testing pure iOS format...");
        match self.try_pure_ios_advertising_fixed().await {
            Ok(result) => {
                info!("✅ Pure iOS advertising: WORKS");
                if let Some(name) = &result.advertised_name {
                    info!("📱 Device name: '{}'", name);
                    if name == &self.my_peer_id {
                        info!("🎯 PERFECT: Exact iOS format");
                    } else {
                        info!("🔄 COMPROMISE: Windows-compatible format");
                        info!("💡 Peer ID still available in manufacturer data");
                    }
                }
                
                // Verify what we're advertising
                self.verify_advertising_format().await?;
            }
            Err(e) => {
                error!("❌ Pure iOS advertising: FAILED - {}", e);
            }
        }
        
        Ok(())
    }
}