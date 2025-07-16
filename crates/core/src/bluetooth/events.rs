// ==============================================================================
// crates/core/src/bluetooth/events.rs
// ==============================================================================

//! Bluetooth events for BitChat mesh networking

use serde::{Deserialize, Serialize};

/// Events emitted by the Bluetooth manager  
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BluetoothEvent {
    /// Bluetooth adapter state changed
    AdapterStateChanged {
        powered_on: bool,
        scanning: bool,
        advertising: bool,
    },
    
    /// Device discovered during scan
    DeviceDiscovered {
        device_id: String,
        device_name: Option<String>,
        rssi: i8,
    },
    
    /// Peer connected successfully
    PeerConnected {
        peer_id: String,
    },
    
    /// Peer disconnected
    PeerDisconnected {
        peer_id: String,
    },
    
    /// Connection attempt failed
    ConnectionFailed {
        peer_id: String,
        error: String,
    },
    
    /// Packet received from peer
    PacketReceived {
        peer_id: String,
        packet_size: usize,
        message_type: String,
    },
    
    /// Packet send failed
    PacketSendFailed {
        peer_id: String,
        error: String,
    },
    
    /// RSSI updated for peer
    RssiUpdated {
        peer_id: String,
        rssi: i16,
    },
    
    /// Service/characteristic discovered
    ServiceDiscovered {
        peer_id: String,
        service_ready: bool,
    },
    
    /// Key exchange completed with peer
    KeyExchangeCompleted {
        peer_id: String,
        success: bool,
    },
    
    /// Announcement received from peer
    AnnouncementReceived {
        peer_id: String,
        nickname: String,
    },
    
    /// Error occurred in Bluetooth subsystem
    Error {
        error: String,
        context: Option<String>,
    },
}

impl BluetoothEvent {
    /// Get the peer ID associated with this event, if any
    pub fn peer_id(&self) -> Option<&str> {
        match self {
            BluetoothEvent::PeerConnected { peer_id } => Some(peer_id),
            BluetoothEvent::PeerDisconnected { peer_id } => Some(peer_id),
            BluetoothEvent::ConnectionFailed { peer_id, .. } => Some(peer_id),
            BluetoothEvent::PacketReceived { peer_id, .. } => Some(peer_id),
            BluetoothEvent::PacketSendFailed { peer_id, .. } => Some(peer_id),
            BluetoothEvent::RssiUpdated { peer_id, .. } => Some(peer_id),
            BluetoothEvent::ServiceDiscovered { peer_id, .. } => Some(peer_id),
            BluetoothEvent::KeyExchangeCompleted { peer_id, .. } => Some(peer_id),
            BluetoothEvent::AnnouncementReceived { peer_id, .. } => Some(peer_id),
            _ => None,
        }
    }
    
    /// Check if this is an error event
    pub fn is_error(&self) -> bool {
        matches!(self, BluetoothEvent::Error { .. } | BluetoothEvent::ConnectionFailed { .. } | BluetoothEvent::PacketSendFailed { .. })
    }
    
    /// Check if this is a connection-related event
    pub fn is_connection_event(&self) -> bool {
        matches!(
            self,
            BluetoothEvent::PeerConnected { .. } | 
            BluetoothEvent::PeerDisconnected { .. } | 
            BluetoothEvent::ConnectionFailed { .. }
        )
    }
    
    /// Get a human-readable description of the event
    pub fn description(&self) -> String {
        match self {
            BluetoothEvent::AdapterStateChanged { powered_on, scanning, advertising } => {
                format!("Adapter state: powered={}, scanning={}, advertising={}", powered_on, scanning, advertising)
            }
            BluetoothEvent::DeviceDiscovered { device_name, rssi, .. } => {
                format!("Discovered device: {} (RSSI: {} dBm)", 
                       device_name.as_deref().unwrap_or("unknown"), rssi)
            }
            BluetoothEvent::PeerConnected { peer_id } => {
                format!("Connected to peer: {}", peer_id)
            }
            BluetoothEvent::PeerDisconnected { peer_id } => {
                format!("Disconnected from peer: {}", peer_id)
            }
            BluetoothEvent::ConnectionFailed { peer_id, error } => {
                format!("Connection failed to {}: {}", peer_id, error)
            }
            BluetoothEvent::PacketReceived { peer_id, message_type, packet_size } => {
                format!("Received {} ({} bytes) from {}", message_type, packet_size, peer_id)
            }
            BluetoothEvent::PacketSendFailed { peer_id, error } => {
                format!("Send failed to {}: {}", peer_id, error)
            }
            BluetoothEvent::RssiUpdated { peer_id, rssi } => {
                format!("RSSI updated for {}: {} dBm", peer_id, rssi)
            }
            BluetoothEvent::ServiceDiscovered { peer_id, service_ready } => {
                format!("Service discovered for {}: ready={}", peer_id, service_ready)
            }
            BluetoothEvent::KeyExchangeCompleted { peer_id, success } => {
                format!("Key exchange with {}: {}", peer_id, if *success { "success" } else { "failed" })
            }
            BluetoothEvent::AnnouncementReceived { peer_id, nickname } => {
                format!("Announcement from {}: {}", peer_id, nickname)
            }
            BluetoothEvent::Error { error, context } => {
                match context {
                    Some(ctx) => format!("Error in {}: {}", ctx, error),
                    None => format!("Error: {}", error),
                }
            }
        }
    }
}

/// Event listener trait for Bluetooth events
pub trait BluetoothEventListener: Send + Sync {
    /// Handle a Bluetooth event
    fn handle_event(&self, event: BluetoothEvent);
}

/// Simple event handler that logs events
pub struct LoggingEventListener;

impl BluetoothEventListener for LoggingEventListener {
    fn handle_event(&self, event: BluetoothEvent) {
        use tracing::{info, error};
        
        match &event {
            BluetoothEvent::Error { .. } | BluetoothEvent::ConnectionFailed { .. } | BluetoothEvent::PacketSendFailed { .. } => {
                error!("Bluetooth event: {}", event.description());
            }
            BluetoothEvent::PeerConnected { .. } | BluetoothEvent::PeerDisconnected { .. } => {
                info!("Bluetooth event: {}", event.description());
            }
            _ => {
                info!("Bluetooth event: {}", event.description());
            }
        }
    }
}