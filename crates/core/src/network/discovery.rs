// ==============================================================================
// crates/core/src/network/discovery.rs - Network Discovery Types and Traits
// ==============================================================================

//! Core network discovery traits and types for BitChat network fallback

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Instant;
use async_trait::async_trait;

/// Network-based peer discovery methods
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DiscoveryMethod {
    /// Nostr relay network (NIP-17 private messaging)
    Nostr { relay_url: String },
    /// UDP broadcast on local network
    UdpBroadcast { port: u16 },
    /// TCP direct connection
    TcpDirect { host: String, port: u16 },
    /// mDNS/Bonjour service discovery
    Mdns { service_type: String },
    /// File system based discovery (for testing)
    FileSystem { path: String },
}

impl std::fmt::Display for DiscoveryMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiscoveryMethod::Nostr { relay_url } => write!(f, "Nostr({})", relay_url),
            DiscoveryMethod::UdpBroadcast { port } => write!(f, "UDP({})", port),
            DiscoveryMethod::TcpDirect { host, port } => write!(f, "TCP({}:{})", host, port),
            DiscoveryMethod::Mdns { service_type } => write!(f, "mDNS({})", service_type),
            DiscoveryMethod::FileSystem { path } => write!(f, "FS({})", path),
        }
    }
}

/// Network peer information
#[derive(Debug, Clone)]
pub struct NetworkPeer {
    /// BitChat peer ID (16 hex chars for iOS compatibility)
    pub peer_id: String,
    /// Network endpoint for connection
    pub endpoint: String,
    /// Discovery method that found this peer
    pub discovery_method: DiscoveryMethod,
    /// When this peer was last seen
    pub last_seen: Instant,
    /// Peer metadata (device info, capabilities, etc.)
    pub metadata: HashMap<String, String>,
    /// Whether this peer supports encrypted messaging
    pub supports_encryption: bool,
    /// Protocol version this peer supports
    pub protocol_version: String,
}

impl NetworkPeer {
    /// Create new network peer
    pub fn new(peer_id: String, endpoint: String, discovery_method: DiscoveryMethod) -> Self {
        let mut metadata = HashMap::new();
        metadata.insert("discovered_at".to_string(), chrono::Utc::now().to_rfc3339());
        
        Self {
            peer_id,
            endpoint,
            discovery_method,
            last_seen: Instant::now(),
            metadata,
            supports_encryption: true, // Default to encrypted for BitChat
            protocol_version: "1.1".to_string(), // Moon Protocol v1.1
        }
    }
    
    /// Check if peer is iOS BitChat compatible
    pub fn is_ios_compatible(&self) -> bool {
        // iOS BitChat peer IDs are exactly 16 hex chars
        self.peer_id.len() == 16 && 
        self.peer_id.chars().all(|c| c.is_ascii_hexdigit()) &&
        self.supports_encryption
    }
    
    /// Update last seen timestamp
    pub fn update_last_seen(&mut self) {
        self.last_seen = Instant::now();
        self.metadata.insert("last_updated".to_string(), chrono::Utc::now().to_rfc3339());
    }
    
    /// Get peer age in seconds
    pub fn age_seconds(&self) -> u64 {
        self.last_seen.elapsed().as_secs()
    }
    
    /// Check if peer is stale (not seen for more than threshold)
    pub fn is_stale(&self, threshold_seconds: u64) -> bool {
        self.age_seconds() > threshold_seconds
    }
}

/// Network discovery trait for different discovery methods
#[async_trait]
pub trait NetworkDiscovery: Send + Sync {
    /// Start network discovery
    async fn start(&mut self) -> Result<()>;
    
    /// Stop network discovery
    async fn stop(&mut self) -> Result<()>;
    
    /// Get discovered peers
    async fn get_peers(&self) -> Vec<NetworkPeer>;
    
    /// Send discovery announcement
    async fn announce_presence(&self, peer_id: &str, metadata: &HashMap<String, String>) -> Result<()>;
    
    /// Check if discovery is active
    async fn is_active(&self) -> bool;
    
    /// Get discovery method name
    fn method_name(&self) -> String;
    
    /// Get discovery method type
    fn method_type(&self) -> DiscoveryMethod;
}

/// BitChat network peer announcement message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerAnnouncement {
    /// BitChat peer ID (16 hex chars for iOS compatibility)
    pub peer_id: String,
    /// Device name/nickname
    pub device_name: String,
    /// Protocol version
    pub protocol_version: String,
    /// Supported features
    pub features: Vec<String>,
    /// Endpoint for connection
    pub endpoint: String,
    /// Timestamp of announcement
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Digital signature for authenticity (optional)
    pub signature: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl PeerAnnouncement {
    /// Create new peer announcement
    pub fn new(peer_id: String, device_name: String, endpoint: String) -> Self {
        let features = vec![
            "noise_protocol".to_string(),
            "mesh_routing".to_string(),
            "fragmentation".to_string(),
        ];
        
        let mut metadata = HashMap::new();
        metadata.insert("platform".to_string(), std::env::consts::OS.to_string());
        metadata.insert("client".to_string(), "bitchat-rust".to_string());
        
        Self {
            peer_id,
            device_name,
            protocol_version: "1.1".to_string(),
            features,
            endpoint,
            timestamp: chrono::Utc::now(),
            signature: None,
            metadata,
        }
    }
    
    /// Validate announcement format for iOS compatibility
    pub fn validate_ios_compatibility(&self) -> Result<()> {
        // Check peer ID format
        if self.peer_id.len() != 16 {
            return Err(anyhow::anyhow!("Peer ID must be exactly 16 chars for iOS compatibility"));
        }
        
        if !self.peer_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(anyhow::anyhow!("Peer ID must be hexadecimal for iOS compatibility"));
        }
        
        // Check protocol version
        if !self.features.contains(&"noise_protocol".to_string()) {
            return Err(anyhow::anyhow!("Noise protocol required for iOS compatibility"));
        }
        
        Ok(())
    }
    
    /// Serialize to JSON for network transmission
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(Into::into)
    }
    
    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(Into::into)
    }
    
    /// Check if announcement is recent (not stale)
    pub fn is_recent(&self, max_age_minutes: i64) -> bool {
        let now = chrono::Utc::now();
        let age = now.signed_duration_since(self.timestamp);
        age.num_minutes() < max_age_minutes
    }
}

/// Network discovery configuration
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// How often to announce our presence (seconds)
    pub announce_interval_seconds: u64,
    /// How long to keep discovered peers before considering them stale
    pub peer_timeout_seconds: u64,
    /// Maximum age for accepting peer announcements
    pub max_announcement_age_minutes: i64,
    /// Whether to enable encryption for network discovery
    pub enable_encryption: bool,
    /// Custom metadata to include in announcements
    pub metadata: HashMap<String, String>,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        let mut metadata = HashMap::new();
        metadata.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
        metadata.insert("platform".to_string(), std::env::consts::OS.to_string());
        
        Self {
            announce_interval_seconds: 30,      // Announce every 30 seconds
            peer_timeout_seconds: 300,          // 5 minutes peer timeout
            max_announcement_age_minutes: 10,   // Accept announcements up to 10 minutes old
            enable_encryption: true,            // Always enable encryption for BitChat
            metadata,
        }
    }
}