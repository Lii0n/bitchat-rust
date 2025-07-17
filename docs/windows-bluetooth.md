# Windows Bluetooth Implementation

## Architecture Overview

BitChat-Rust uses native Windows WinRT APIs for optimal Bluetooth LE performance:

```text
???????????????????????????????????????????????????????????????
?                BitChat Core Protocol                        ?
???????????????????????????????????????????????????????????????
?            Cross-Platform Bluetooth Manager                 ?
???????????????????????????????????????????????????????????????
?   Windows       ?              Other Platforms              ?
?   WinRT APIs    ?              btleplug                     ?
?                 ?              (BlueZ/CoreBluetooth)        ?
???????????????????????????????????????????????????????????????


// Windows: Must handle connection arbitration
impl CompatibilityManager {
    fn should_initiate_connection(&self, peer_id: &str) -> bool {
        // Deterministic connection logic prevents conflicts
        self.my_peer_id < peer_id  
    }
}

fn parse_windows_advertisement(args: &BluetoothLEAdvertisementReceivedEventArgs) 
    -> Option<PeerInfo> {
    // Method 1: Check service UUIDs
    if let Ok(service_uuids) = args.Advertisement()?.ServiceUuids() {
        for uuid in service_uuids {
            if uuid_matches_bitchat(uuid) {
                return extract_peer_info(args);
            }
        }
    }
    
    // Method 2: Parse device name (BC_<peer_id>)
    if let Ok(name) = args.Advertisement()?.LocalName() {
        if name.starts_with("BC_") && name.len() == 19 {
            return Some(PeerInfo::from_name(&name));
        }
    }
    
    // Method 3: Check manufacturer data
    if let Ok(mfg_data) = args.Advertisement()?.ManufacturerData() {
        return parse_bitchat_manufacturer_data(mfg_data);
    }
    
    None
}


impl WindowsBluetoothManager {
    async fn handle_discovered_device(&mut self, peer_id: String) -> Result<()> {
        // Skip our own advertisements
        if peer_id == self.my_peer_id {
            return Ok(());
        }
        
        // Use deterministic connection logic
        if self.compatibility.should_initiate_connection(&peer_id) {
            self.attempt_connection(peer_id).await?;
        } else {
            // Wait for peer to connect to us
            self.await_incoming_connection(peer_id).await?;
        }
        
        Ok(())
    }
}

### Priority 2B: Platform Abstraction Documentation
**Location**: `crates/core/src/bluetooth/mod.rs` (Rustdoc)
**Time**: 2-3 hours

Document how the cross-platform abstraction works:

```rust
//! # Cross-Platform Bluetooth LE Support
//! 
//! This module provides a unified interface for Bluetooth LE operations across
//! different platforms, with platform-specific optimizations.
//! 
//! ## Platform Support
//! 
//! | Platform | Backend | Status | Notes |
//! |----------|---------|--------|-------|
//! | Windows  | WinRT   | ? Full | Native Windows 10+ APIs |
//! | Linux    | BlueZ   | ? Full | Via btleplug |
//! | macOS    | CoreBT  | ? Full | Via btleplug |
//! | Android  | Planned | ?? Future | Java bindings |
//! 
//! ## Usage
//! 
//! The platform differences are abstracted away:
//! 
//! ```rust
//! use bitchat_core::bluetooth::BluetoothManager;
//! 
//! // Works the same on all platforms
//! let manager = BluetoothManager::new().await?;
//! manager.start_scanning().await?;
//! manager.start_advertising().await?;
//! ```
//! 
//! ## Platform-Specific Notes
//! 
//! ### Windows
//! - Requires Windows 10+ with Bluetooth LE support
//! - Uses WinRT APIs for optimal performance
//! - Includes special iOS/Android compatibility handling
//! 
//! ### Linux  
//! - Requires BlueZ 5.40+
//! - May need additional permissions for BLE access
//! - Uses btleplug for cross-platform compatibility