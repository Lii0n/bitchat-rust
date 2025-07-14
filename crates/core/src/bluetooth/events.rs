//! Bluetooth events and configuration

use std::time::Instant;
use serde::{Deserialize, Serialize};

/// Bluetooth event types
#[derive(Debug, Clone)]
pub enum BluetoothEvent {
    /// A new peer has connected
    PeerConnected { peer_id: String },
    
    /// A peer has disconnected
    PeerDisconnected { peer_id: String },
    
    /// A message was received from a peer
    MessageReceived { 
        peer_id: String, 
        data: Vec<u8> 
    },
    
    /// Bluetooth adapter state changed
    AdapterStateChanged { powered_on: bool },
    
    /// Scanning state changed
    ScanningStateChanged { scanning: bool },
    
    /// Advertising state changed
    AdvertisingStateChanged { advertising: bool },
}

/// Bluetooth configuration
#[derive(Debug, Clone)]
pub struct BluetoothConfig {
    /// Our peer ID (8 hex characters for iOS/Android compatibility)
    pub peer_id: String,
    
    /// Maximum number of simultaneous connections
    pub max_connections: usize,
    
    /// Scan timeout in seconds
    pub scan_timeout: u64,
    
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    
    /// Enable automatic reconnection
    pub auto_reconnect: bool,
}

impl Default for BluetoothConfig {
    fn default() -> Self {
        Self {
            peer_id: String::new(), // Will be generated
            max_connections: 8,
            scan_timeout: 30,
            connection_timeout: 10,
            auto_reconnect: true,
        }
    }
}

/// Information about a connected peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectedPeer {
    /// Peer ID
    pub peer_id: String,
    
    /// Device ID (platform-specific identifier)
    pub device_id: String,
    
    /// When the connection was established
    pub connected_at: Instant,
    
    /// Last time we heard from this peer
    pub last_seen: Instant,
}

impl ConnectedPeer {
    /// Get a short version of the peer ID for display
    pub fn short_id(&self) -> String {
        if self.peer_id.len() >= 8 {
            self.peer_id[..8].to_string()
        } else {
            self.peer_id.clone()
        }
    }
    
    /// Get connection duration
    pub fn connection_duration(&self) -> std::time::Duration {
        self.connected_at.elapsed()
    }
    
    /// Get time since last activity
    pub fn time_since_last_seen(&self) -> std::time::Duration {
        self.last_seen.elapsed()
    }
}