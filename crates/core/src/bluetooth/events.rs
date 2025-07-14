//! Bluetooth event handling and configuration

use serde::{Serialize, Deserialize};
use std::collections::HashMap;

/// Bluetooth events that can occur during operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BluetoothEvent {
    DeviceDiscovered {
        device_id: String,
        device_name: Option<String>,
        rssi: i8,
    },
    DeviceConnected {
        device_id: String,
        peer_id: String,
    },
    DeviceDisconnected {
        device_id: String,
        peer_id: String,
    },
    MessageReceived {
        from_peer: String,
        data: Vec<u8>,
    },
    MessageSent {
        to_peer: Option<String>, // None for broadcast
        data: Vec<u8>,
    },
    ScanStarted,
    ScanStopped,
    AdvertisingStarted,
    AdvertisingStopped,
    Error {
        message: String,
    },
}

/// Configuration for Bluetooth operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BluetoothConfig {
    pub device_name: String,
    pub scan_duration_ms: u64,
    pub advertise_duration_ms: u64,
    pub max_connections: usize,
    pub verbose_logging: bool,
    pub connection_timeout_ms: u64,
}

impl Default for BluetoothConfig {
    fn default() -> Self {
        Self {
            device_name: "BitChat-Device".to_string(),
            scan_duration_ms: 5000,
            advertise_duration_ms: 10000,
            max_connections: 10,
            verbose_logging: false,
            connection_timeout_ms: 30000,
        }
    }
}

impl BluetoothConfig {
    /// Create a new config with a specific device name
    pub fn with_device_name(mut self, name: String) -> Self {
        self.device_name = name;
        self
    }

    /// Enable verbose logging
    pub fn with_verbose_logging(mut self) -> Self {
        self.verbose_logging = true;
        self
    }

    /// Set maximum connections
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set scan duration
    pub fn with_scan_duration(mut self, duration_ms: u64) -> Self {
        self.scan_duration_ms = duration_ms;
        self
    }
}

/// Information about a connected peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedPeer {
    pub device_id: String,
    pub peer_id: String,
    pub nickname: Option<String>,
    pub rssi: i8,
    pub connected_at: u64, // Timestamp
    pub last_seen: u64,
    pub message_count: u32,
}

impl ConnectedPeer {
    pub fn new(device_id: String, peer_id: String, rssi: i8) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            device_id,
            peer_id,
            nickname: None,
            rssi,
            connected_at: now,
            last_seen: now,
            message_count: 0,
        }
    }

    pub fn update_activity(&mut self, rssi: Option<i8>) {
        self.last_seen = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if let Some(new_rssi) = rssi {
            self.rssi = new_rssi;
        }
        
        self.message_count = self.message_count.saturating_add(1);
    }
}

/// Delegate trait for handling Bluetooth events
pub trait BluetoothConnectionDelegate: Send + Sync {
    fn on_device_discovered(&self, device_id: &str, device_name: Option<&str>, rssi: i8);
    fn on_device_connected(&self, device_id: &str, peer_id: &str);
    fn on_device_disconnected(&self, device_id: &str, peer_id: &str);
    fn on_message_received(&self, from_peer: &str, data: &[u8]);
    fn on_error(&self, message: &str);
}

/// Simple event handler that can be used for testing or basic operations
#[derive(Debug, Default)]
pub struct BasicBluetoothDelegate {
    pub events: std::sync::Mutex<Vec<BluetoothEvent>>,
}

impl BasicBluetoothDelegate {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_events(&self) -> Vec<BluetoothEvent> {
        self.events.lock().unwrap().clone()
    }

    pub fn clear_events(&self) {
        self.events.lock().unwrap().clear();
    }
}

impl BluetoothConnectionDelegate for BasicBluetoothDelegate {
    fn on_device_discovered(&self, device_id: &str, device_name: Option<&str>, rssi: i8) {
        let event = BluetoothEvent::DeviceDiscovered {
            device_id: device_id.to_string(),
            device_name: device_name.map(|s| s.to_string()),
            rssi,
        };
        self.events.lock().unwrap().push(event);
    }

    fn on_device_connected(&self, device_id: &str, peer_id: &str) {
        let event = BluetoothEvent::DeviceConnected {
            device_id: device_id.to_string(),
            peer_id: peer_id.to_string(),
        };
        self.events.lock().unwrap().push(event);
    }

    fn on_device_disconnected(&self, device_id: &str, peer_id: &str) {
        let event = BluetoothEvent::DeviceDisconnected {
            device_id: device_id.to_string(),
            peer_id: peer_id.to_string(),
        };
        self.events.lock().unwrap().push(event);
    }

    fn on_message_received(&self, from_peer: &str, data: &[u8]) {
        let event = BluetoothEvent::MessageReceived {
            from_peer: from_peer.to_string(),
            data: data.to_vec(),
        };
        self.events.lock().unwrap().push(event);
    }

    fn on_error(&self, message: &str) {
        let event = BluetoothEvent::Error {
            message: message.to_string(),
        };
        self.events.lock().unwrap().push(event);
    }
}