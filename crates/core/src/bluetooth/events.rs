//! Bluetooth event types and delegate traits

use btleplug::platform::Peripheral;
use btleplug::api::Characteristic;
use std::time::Instant;

/// Events emitted by the BluetoothConnectionManager
#[derive(Debug, Clone)]
pub enum BluetoothEvent {
    /// A new peer was discovered
    PeerDiscovered { 
        peer_id: String, 
        name: Option<String>, 
        rssi: i16 
    },
    /// A peer connected successfully
    PeerConnected { 
        peer_id: String 
    },
    /// A peer disconnected
    PeerDisconnected { 
        peer_id: String 
    },
    /// Message received from a peer
    MessageReceived { 
        peer_id: String, 
        data: Vec<u8> 
    },
    /// Error occurred with a peer
    PeerError { 
        peer_id: String, 
        error: String 
    },
    /// Scanning state changed
    ScanningStateChanged { 
        scanning: bool 
    },
    /// Advertising state changed  
    AdvertisingStateChanged { 
        advertising: bool 
    },
}

/// Delegate trait for handling Bluetooth events
pub trait BluetoothConnectionDelegate: Send + Sync {
    /// Called when a Bluetooth event occurs
    fn on_bluetooth_event(&self, event: BluetoothEvent);
}

/// Information about a connected peer
#[derive(Debug, Clone)]
pub struct ConnectedPeer {
    /// Unique identifier for this peer
    pub id: String,
    /// The underlying Bluetooth peripheral
    pub peripheral: Peripheral,
    /// Human-readable name (if available)
    pub name: Option<String>,
    /// Signal strength in dBm
    pub rssi: i16,
    /// When this peer was first connected
    pub connected_at: Instant,
    /// Last time we received data from this peer
    pub last_seen: Instant,
    /// The characteristic used for sending messages
    pub message_characteristic: Option<Characteristic>,
}

impl ConnectedPeer {
    /// Check if this peer is considered stale (hasn't been seen recently)
    pub fn is_stale(&self, timeout_secs: u64) -> bool {
        self.last_seen.elapsed().as_secs() > timeout_secs
    }

    /// Get a short display ID for this peer (first 8 characters)
    pub fn short_id(&self) -> &str {
        if self.id.len() >= 8 {
            &self.id[..8]
        } else {
            &self.id
        }
    }

    /// Get display name or fallback to short ID
    pub fn display_name(&self) -> &str {
        self.name.as_deref().unwrap_or_else(|| self.short_id())
    }
}

/// Configuration for the Bluetooth manager
#[derive(Debug, Clone)]
pub struct BluetoothConfig {
    /// How often to scan for devices (milliseconds)
    pub scan_interval_ms: u64,
    /// Maximum number of concurrent connections
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout_secs: u64,
    /// Peer cleanup timeout in seconds
    pub peer_cleanup_timeout_secs: u64,
    /// Whether to automatically retry failed connections
    pub auto_retry: bool,
    /// Device name for identification
    pub device_name: String,
    /// Enable verbose logging
    pub verbose_logging: bool,
}

impl Default for BluetoothConfig {
    fn default() -> Self {
        Self {
            scan_interval_ms: 5000,
            max_connections: 8,
            connection_timeout_secs: 30,
            peer_cleanup_timeout_secs: 60,
            auto_retry: true,
            device_name: "BitChat".to_string(),
            verbose_logging: false,
        }
    }
}

impl BluetoothConfig {
    /// Create a new config with custom device name
    pub fn with_device_name(mut self, name: impl Into<String>) -> Self {
        self.device_name = name.into();
        self
    }

    /// Enable verbose logging
    pub fn with_verbose_logging(mut self) -> Self {
        self.verbose_logging = true;
        self
    }

    /// Set maximum number of connections
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set scan interval
    pub fn with_scan_interval_ms(mut self, interval_ms: u64) -> Self {
        self.scan_interval_ms = interval_ms;
        self
    }

    /// Set connection timeout
    pub fn with_connection_timeout(mut self, timeout_secs: u64) -> Self {
        self.connection_timeout_secs = timeout_secs;
        self
    }
}