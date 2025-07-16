// crates/cli/src/bin/test_windows_ble.rs
use bitchat_core::bluetooth::{BluetoothConfig, windows::WindowsBluetoothAdapter};
use anyhow::Result;
use tracing_subscriber;

#[tokio::main] 
async fn main() -> Result<()> {
    // Enable debug logging to see all devices
    std::env::set_var("RUST_LOG", "debug,bitchat_core::bluetooth::windows=info");
    tracing_subscriber::fmt::init();
    
    // Use the same peer ID as your CLI
    let config = BluetoothConfig::with_device_name("AEA220194CD1D5A9".to_string());
    let mut adapter = WindowsBluetoothAdapter::new(config).await?;
    
    println!("?? BitChat macOS Detection Test");
    println!("==============================");
    println!("?? My Peer ID: AEA220194CD1D5A9");
    println!("?? Looking for macOS BitChat devices...");
    println!("?? Target Service UUID: F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C");
    println!("?? Expected device name format: BC_<16_hex_chars>");
    println!("");
    
    // Check if Bluetooth is available first
    if !adapter.is_available().await {
        println!("? Bluetooth not available on this system");
        return Ok(());
    }
    
    println!("? Bluetooth is available");
    
    // Start scanning for macOS devices
    println!("?? Starting enhanced BLE scanning...");
    adapter.start_scanning().await?;
    println!("? Scanning started - make sure your macOS BitChat is running!");
    println!("");
    
    println!("?? Debug Info:");
    println!("{}", adapter.get_platform_debug_info().await);
    println!("");
    
    println!("?? Scanning for 60 seconds...");
    println!("   ?? Make sure macOS BitChat is:");
    println!("   - Running and visible");
    println!("   - Not backgrounded (iOS/macOS may limit BLE when backgrounded)");
    println!("   - In Bluetooth range (< 10 meters)");
    println!("");
    
    // Scan for 60 seconds with detailed reporting
    for i in 1..=12 {
        tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
        
        let discovered = adapter.get_discovered_devices().await;
        println!("? Scan {} ({}s): {} BitChat devices found", i, i * 5, discovered.len());
        
        if !discovered.is_empty() {
            println!("?? BITCHAT DEVICES FOUND:");
            for (device_id, device) in discovered {
                println!("  ?? Device: {}", device_id);
                println!("     Peer ID: {}", device.peer_id.as_deref().unwrap_or("unknown"));
                println!("     RSSI: {} dBm", device.rssi);
                println!("     Last seen: {}s ago", device.last_seen.elapsed().as_secs());
                println!("     Platform: macOS (detected)");
                println!("");
            }
        } else if i % 2 == 0 {
            println!("   ?? Still scanning... (no BitChat devices found yet)");
        }
        
        // Show progress indicator
        match i % 4 {
            1 => print!("?? Scanning"),
            2 => print!("?? Scanning."),
            3 => print!("?? Scanning.."),
            0 => print!("?? Scanning..."),
            _ => {}
        }
        if i % 4 != 0 {
            println!("");
        }
    }
    
    adapter.stop_scanning().await?;
    
    let final_discovered = adapter.get_discovered_devices().await;
    println!("\n?? Final Results:");
    println!("==================");
    
    if final_discovered.is_empty() {
        println!("? No BitChat devices found");
        println!("");
        println!("?? Troubleshooting:");
        println!("   - Is macOS BitChat actually running?");
        println!("   - Is Bluetooth enabled on both devices?");
        println!("   - Are devices within 10 meters?");
        println!("   - Try restarting Bluetooth on macOS");
        println!("   - Check macOS Privacy settings for Bluetooth");
    } else {
        println!("? Found {} BitChat device(s)!", final_discovered.len());
        for (device_id, device) in final_discovered {
            println!("  ?? macOS Device: {}", device.peer_id.as_deref().unwrap_or("unknown"));
            println!("     Signal: {} dBm", device.rssi);
        }
        println!("");
        println!("?? SUCCESS! Windows can detect macOS BitChat devices!");
    }
    
    println!("?? Test completed!");
    Ok(())
}