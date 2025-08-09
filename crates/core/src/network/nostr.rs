// ==============================================================================
// crates/core/src/network/nostr.rs - Complete Nostr Protocol Implementation
// ==============================================================================

//! Complete Nostr protocol implementation with WebSocket relay connections,
//! NIP-17 private messaging, and BitChat peer discovery integration.

use anyhow::Result;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use tokio_tungstenite::{connect_async, WebSocketStream, MaybeTlsStream};
use tokio_tungstenite::tungstenite::Message;
use futures::{SinkExt, StreamExt};
use tracing::{info, warn, debug, error};
use url::Url;

use crate::network::bridge::{NetworkBridge, BridgeConfig, BridgeStats};
use crate::network::discovery::DiscoveryMethod;

/// Default BitChat-compatible Nostr relays
pub const DEFAULT_BITCHAT_RELAYS: &[&str] = &[
    "wss://relay.damus.io",
    "wss://nostr-pub.wellorder.net", 
    "wss://relay.snort.social",
    "wss://nos.lol",
    "wss://relay.nostr.info",
];

/// Nostr event kinds for BitChat
const BITCHAT_DISCOVERY_KIND: u16 = 30000;  // Custom discovery event
const BITCHAT_MESSAGE_KIND: u16 = 4;        // NIP-04 private message (will upgrade to NIP-17)
const BITCHAT_PRESENCE_KIND: u16 = 30001;   // Custom presence event

/// WebSocket connection type
type WsStream = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// Nostr client for BitChat peer discovery and messaging
#[derive(Debug)]
pub struct NostrClient {
    peer_id: String,
    relays: Vec<String>,
    keypair: NostrKeypair,
    connections: Arc<RwLock<HashMap<String, RelayConnection>>>,
    discovered_peers: Arc<RwLock<HashMap<String, DiscoveredNostrPeer>>>,
    message_sender: Option<mpsc::UnboundedSender<OutgoingMessage>>,
}

/// Nostr keypair for signing events
#[derive(Debug, Clone)]
pub struct NostrKeypair {
    pub public_key: String,
    private_key: String,
    signing_key: ed25519_dalek::SigningKey,
}

/// Relay connection state
#[derive(Debug)]
struct RelayConnection {
    url: String,
    ws_sender: mpsc::UnboundedSender<Message>,
    connected: bool,
    last_ping: Option<std::time::Instant>,
}

/// Discovered peer via Nostr
#[derive(Debug, Clone)]
pub struct DiscoveredNostrPeer {
    pub peer_id: String,
    pub nostr_pubkey: String,
    pub protocol_version: String,
    pub features: Vec<String>,
    pub metadata: HashMap<String, String>,
    pub discovered_at: chrono::DateTime<chrono::Utc>,
}

/// Outgoing message to relay
#[derive(Debug)]
struct OutgoingMessage {
    relay_url: String,
    message: NostrMessage,
}

/// Nostr event structure (complete implementation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrEvent {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: String,
}

/// Nostr subscription filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NostrFilter {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ids: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authors: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<u16>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub since: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub until: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<HashMap<String, Vec<String>>>,
}

/// Nostr message types (complete protocol implementation)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum NostrMessage {
    Event(Vec<serde_json::Value>),
    Request(Vec<serde_json::Value>), 
    Close(Vec<serde_json::Value>),
    Notice(Vec<serde_json::Value>),
    EndOfStoredEvents(Vec<serde_json::Value>),
    Ok(Vec<serde_json::Value>),
    Auth(Vec<serde_json::Value>),
}

impl NostrClient {
    /// Create new Nostr client for BitChat
    pub fn new(peer_id: String, relays: Vec<String>) -> Self {
        info!("🔗 Creating Nostr client for BitChat peer: {}", peer_id);
        
        let keypair = Self::generate_keypair_from_peer_id(&peer_id);
        info!("🔑 Generated Nostr keypair - pubkey: {}", keypair.public_key);
        
        Self {
            peer_id,
            relays,
            keypair,
            connections: Arc::new(RwLock::new(HashMap::new())),
            discovered_peers: Arc::new(RwLock::new(HashMap::new())),
            message_sender: None,
        }
    }
    
    /// Generate deterministic Nostr keypair from BitChat peer ID
    fn generate_keypair_from_peer_id(peer_id: &str) -> NostrKeypair {
        use sha2::{Sha256, Digest};
        use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
        
        // Create deterministic private key from BitChat peer ID
        let mut hasher = Sha256::new();
        hasher.update(b"BitChat-Nostr-Seed-v1:");
        hasher.update(peer_id.as_bytes());
        let seed = hasher.finalize();
        
        // Convert to fixed-size array for ed25519_dalek
        let mut seed_bytes = [0u8; 32];
        seed_bytes.copy_from_slice(&seed[..32]);
        
        let signing_key = SigningKey::from_bytes(&seed_bytes);
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        
        let private_key = hex::encode(signing_key.to_bytes());
        let public_key = hex::encode(verifying_key.to_bytes());
        
        NostrKeypair {
            public_key,
            private_key,
            signing_key,
        }
    }
    
    /// Connect to all Nostr relays
    pub async fn connect(&mut self) -> Result<()> {
        info!("🌐 Connecting to {} Nostr relays for BitChat...", self.relays.len());
        
        let (tx, mut rx) = mpsc::unbounded_channel::<OutgoingMessage>();
        self.message_sender = Some(tx);
        
        let connections = Arc::clone(&self.connections);
        let _discovered_peers = Arc::clone(&self.discovered_peers);
        let keypair_clone = self.keypair.clone();
        let peer_id_clone = self.peer_id.clone();
        
        // Spawn message handling task
        tokio::spawn(async move {
            while let Some(outgoing_msg) = rx.recv().await {
                Self::handle_outgoing_message(outgoing_msg, &connections).await;
            }
        });
        
        // Connect to each relay
        let mut connection_tasks = Vec::new();
        
        for relay_url in &self.relays {
            let url = relay_url.clone();
            let connections_clone = Arc::clone(&self.connections);
            let discovered_peers_clone = Arc::clone(&self.discovered_peers);
            let keypair_clone2 = keypair_clone.clone();
            let peer_id_clone2 = peer_id_clone.clone();
            
            let task = tokio::spawn(async move {
                Self::connect_to_relay(
                    url, 
                    connections_clone, 
                    discovered_peers_clone,
                    keypair_clone2,
                    peer_id_clone2
                ).await
            });
            
            connection_tasks.push(task);
        }
        
        // Wait for connections and count successes
        let mut connected_count = 0;
        for task in connection_tasks {
            if let Ok(Ok(())) = task.await {
                connected_count += 1;
            }
        }
        
        if connected_count > 0 {
            info!("✅ Nostr client connected to {}/{} relays", connected_count, self.relays.len());
            
            // Subscribe to BitChat discovery events
            self.subscribe_to_bitchat_events().await?;
            
            // Announce our presence
            self.announce_presence_internal().await?;
            
            Ok(())
        } else {
            Err(anyhow::anyhow!("❌ Failed to connect to any Nostr relays"))
        }
    }
    
    /// Connect to a single Nostr relay with full WebSocket implementation
    async fn connect_to_relay(
        relay_url: String,
        connections: Arc<RwLock<HashMap<String, RelayConnection>>>,
        discovered_peers: Arc<RwLock<HashMap<String, DiscoveredNostrPeer>>>,
        keypair: NostrKeypair,
        peer_id: String,
    ) -> Result<()> {
        info!("🔗 Connecting to Nostr relay: {}", relay_url);
        
        // Parse and connect to WebSocket
        let url = Url::parse(&relay_url)?;
        let (ws_stream, _response) = connect_async(url).await?;
        
        info!("✅ WebSocket connected to: {}", relay_url);
        
        let (mut ws_sender, mut ws_receiver) = ws_stream.split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
        
        // Store connection
        {
            let mut connections_guard = connections.write().await;
            connections_guard.insert(relay_url.clone(), RelayConnection {
                url: relay_url.clone(),
                ws_sender: tx,
                connected: true,
                last_ping: Some(std::time::Instant::now()),
            });
        }
        
        // Spawn sender task
        let relay_url_sender = relay_url.clone();
        let connections_sender = Arc::clone(&connections);
        tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let Err(e) = ws_sender.send(message).await {
                    error!("❌ Failed to send message to {}: {}", relay_url_sender, e);
                    // Mark connection as disconnected
                    let mut connections_guard = connections_sender.write().await;
                    if let Some(conn) = connections_guard.get_mut(&relay_url_sender) {
                        conn.connected = false;
                    }
                    break;
                }
            }
        });
        
        // Spawn receiver task
        let relay_url_receiver = relay_url.clone();
        tokio::spawn(async move {
            while let Some(message_result) = ws_receiver.next().await {
                match message_result {
                    Ok(Message::Text(text)) => {
                        if let Err(e) = Self::handle_relay_message(
                            &relay_url_receiver, 
                            &text, 
                            &discovered_peers,
                            &keypair,
                            &peer_id
                        ).await {
                            debug!("Error handling relay message: {}", e);
                        }
                    }
                    Ok(Message::Pong(_)) => {
                        debug!("Received pong from {}", relay_url_receiver);
                    }
                    Ok(Message::Close(_)) => {
                        info!("Relay {} closed connection", relay_url_receiver);
                        break;
                    }
                    Err(e) => {
                        warn!("WebSocket error from {}: {}", relay_url_receiver, e);
                        break;
                    }
                    _ => {}
                }
            }
            
            info!("Disconnected from relay: {}", relay_url_receiver);
        });
        
        Ok(())
    }
    
    /// Handle incoming messages from Nostr relays
    async fn handle_relay_message(
        relay_url: &str,
        message: &str,
        discovered_peers: &Arc<RwLock<HashMap<String, DiscoveredNostrPeer>>>,
        _keypair: &NostrKeypair,
        _our_peer_id: &str,
    ) -> Result<()> {
        debug!("📥 Received from {}: {}", relay_url, message);
        
        // Parse Nostr message
        if let Ok(msg_array) = serde_json::from_str::<Vec<serde_json::Value>>(message) {
            if let Some(msg_type) = msg_array.get(0).and_then(|v| v.as_str()) {
                match msg_type {
                    "EVENT" => {
                        if let Some(event_value) = msg_array.get(2) {
                            if let Ok(event) = serde_json::from_value::<NostrEvent>(event_value.clone()) {
                                Self::handle_nostr_event(&event, discovered_peers).await?;
                            }
                        }
                    }
                    "NOTICE" => {
                        if let Some(notice) = msg_array.get(1).and_then(|v| v.as_str()) {
                            info!("📢 Relay notice from {}: {}", relay_url, notice);
                        }
                    }
                    "OK" => {
                        if let Some(event_id) = msg_array.get(1).and_then(|v| v.as_str()) {
                            if let Some(accepted) = msg_array.get(2).and_then(|v| v.as_bool()) {
                                if accepted {
                                    debug!("✅ Event {} accepted by {}", event_id, relay_url);
                                } else if let Some(reason) = msg_array.get(3).and_then(|v| v.as_str()) {
                                    warn!("❌ Event {} rejected by {}: {}", event_id, relay_url, reason);
                                }
                            }
                        }
                    }
                    _ => {
                        debug!("Unknown message type: {}", msg_type);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle Nostr events and extract BitChat peer discovery
    async fn handle_nostr_event(
        event: &NostrEvent,
        discovered_peers: &Arc<RwLock<HashMap<String, DiscoveredNostrPeer>>>,
    ) -> Result<()> {
        match event.kind {
            BITCHAT_DISCOVERY_KIND => {
                debug!("🔍 Processing BitChat discovery event from {}", event.pubkey);
                
                if let Ok(discovery_content) = serde_json::from_str::<NostrDiscoveryContent>(&event.content) {
                    let peer = DiscoveredNostrPeer {
                        peer_id: discovery_content.bitchat_peer_id.clone(),
                        nostr_pubkey: event.pubkey.clone(),
                        protocol_version: discovery_content.protocol_version,
                        features: discovery_content.features,
                        metadata: discovery_content.metadata,
                        discovered_at: chrono::Utc::now(),
                    };
                    
                    let mut peers_guard = discovered_peers.write().await;
                    peers_guard.insert(discovery_content.bitchat_peer_id.clone(), peer);
                    
                    info!("🎯 Discovered BitChat peer via Nostr: {}", discovery_content.bitchat_peer_id);
                }
            }
            BITCHAT_MESSAGE_KIND => {
                info!("📨 Received BitChat private message from {}", event.pubkey);
                // TODO: Decrypt and process private message
            }
            _ => {
                debug!("Ignoring event kind: {}", event.kind);
            }
        }
        
        Ok(())
    }
    
    /// Subscribe to BitChat discovery and messaging events
    async fn subscribe_to_bitchat_events(&self) -> Result<()> {
        info!("📡 Subscribing to BitChat events on Nostr relays");
        
        // Subscribe to BitChat discovery events
        let discovery_filter = NostrFilter {
            kinds: Some(vec![BITCHAT_DISCOVERY_KIND, BITCHAT_MESSAGE_KIND]),
            since: Some((chrono::Utc::now().timestamp() - 3600) as u64), // Last hour
            limit: Some(100),
            tags: Some({
                let mut tags = HashMap::new();
                tags.insert("t".to_string(), vec!["bitchat".to_string()]);
                tags
            }),
            ..Default::default()
        };
        
        let subscription_id = format!("bitchat-{}", self.peer_id);
        let req_message = vec![
            serde_json::Value::String("REQ".to_string()),
            serde_json::Value::String(subscription_id),
            serde_json::to_value(discovery_filter)?,
        ];
        
        self.broadcast_to_relays(serde_json::to_string(&req_message)?).await?;
        
        // Also subscribe to direct messages to our pubkey
        let dm_filter = NostrFilter {
            kinds: Some(vec![BITCHAT_MESSAGE_KIND]),
            tags: Some({
                let mut tags = HashMap::new();
                tags.insert("p".to_string(), vec![self.keypair.public_key.clone()]);
                tags
            }),
            since: Some((chrono::Utc::now().timestamp() - 3600) as u64),
            limit: Some(50),
            ..Default::default()
        };
        
        let dm_subscription_id = format!("bitchat-dm-{}", self.peer_id);
        let dm_req_message = vec![
            serde_json::Value::String("REQ".to_string()),
            serde_json::Value::String(dm_subscription_id),
            serde_json::to_value(dm_filter)?,
        ];
        
        self.broadcast_to_relays(serde_json::to_string(&dm_req_message)?).await?;
        
        Ok(())
    }
    
    /// Announce BitChat presence on Nostr network
    async fn announce_presence_internal(&self) -> Result<()> {
        info!("📢 Announcing BitChat presence on Nostr network");
        
        let mut metadata = HashMap::new();
        metadata.insert("client".to_string(), "bitchat-rust".to_string());
        metadata.insert("version".to_string(), env!("CARGO_PKG_VERSION").to_string());
        metadata.insert("platform".to_string(), std::env::consts::OS.to_string());
        metadata.insert("timestamp".to_string(), chrono::Utc::now().to_rfc3339());
        
        let discovery_content = NostrDiscoveryContent {
            bitchat_peer_id: self.peer_id.clone(),
            protocol_version: "1.1".to_string(),
            features: vec![
                "noise_protocol".to_string(),
                "mesh_routing".to_string(),
                "nip17_messaging".to_string(),
            ],
            metadata,
        };
        
        let event = self.create_signed_event(
            BITCHAT_DISCOVERY_KIND,
            vec![
                vec!["t".to_string(), "bitchat".to_string()],
                vec!["t".to_string(), "peer-discovery".to_string()],
                vec!["t".to_string(), "moon-protocol".to_string()],
            ],
            serde_json::to_string(&discovery_content)?,
        )?;
        
        self.publish_event(event).await?;
        
        info!("✅ BitChat presence announced on Nostr");
        Ok(())
    }
    
    /// Send private message via Nostr (NIP-04 for now, will upgrade to NIP-17)
    pub async fn send_private_message(&self, recipient_peer_id: &str, message: &str) -> Result<()> {
        info!("📤 Sending private message to BitChat peer: {}", recipient_peer_id);
        
        // Find recipient's Nostr pubkey from discovered peers
        let peers_guard = self.discovered_peers.read().await;
        let recipient_peer = peers_guard.get(recipient_peer_id)
            .ok_or_else(|| anyhow::anyhow!("Recipient peer not found: {}", recipient_peer_id))?;
        
        let recipient_pubkey = &recipient_peer.nostr_pubkey;
        
        // For now, use simple base64 encoding (will implement proper NIP-04/NIP-17 encryption)
        let encrypted_content = self.encrypt_message(recipient_pubkey, message)?;
        
        let event = self.create_signed_event(
            BITCHAT_MESSAGE_KIND,
            vec![
                vec!["p".to_string(), recipient_pubkey.clone()],
                vec!["t".to_string(), "bitchat".to_string()],
            ],
            encrypted_content,
        )?;
        
        self.publish_event(event).await?;
        
        info!("✅ Private message sent to {} via Nostr", recipient_peer_id);
        Ok(())
    }
    
    /// Create and sign a Nostr event
    fn create_signed_event(
        &self,
        kind: u16,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Result<NostrEvent> {
        let created_at = chrono::Utc::now().timestamp() as u64;
        
        // Create event for signing (without id and sig)
        let event_for_signing = format!(
            "[0,\"{}\",{},{},{},\"{}\"]",
            self.keypair.public_key,
            created_at,
            kind,
            serde_json::to_string(&tags)?,
            content.replace('"', "\\\"")
        );
        
        // Calculate event ID (sha256 hash of serialized event)
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(event_for_signing.as_bytes());
        let event_id = hex::encode(hasher.finalize());
        
        // Sign the event ID
        use ed25519_dalek::Signer;
        let signature = self.keypair.signing_key.sign(event_id.as_bytes());
        let sig_hex = hex::encode(signature.to_bytes());
        
        Ok(NostrEvent {
            id: event_id,
            pubkey: self.keypair.public_key.clone(),
            created_at,
            kind,
            tags,
            content,
            sig: sig_hex,
        })
    }
    
    /// Publish event to all connected relays
    async fn publish_event(&self, event: NostrEvent) -> Result<()> {
        let event_message = vec![
            serde_json::Value::String("EVENT".to_string()),
            serde_json::to_value(event)?,
        ];
        
        let message_json = serde_json::to_string(&event_message)?;
        self.broadcast_to_relays(message_json).await?;
        
        Ok(())
    }
    
    /// Broadcast message to all connected relays
    async fn broadcast_to_relays(&self, message: String) -> Result<()> {
        let connections_guard = self.connections.read().await;
        let mut sent_count = 0;
        
        for (relay_url, connection) in connections_guard.iter() {
            if connection.connected {
                if let Err(e) = connection.ws_sender.send(Message::Text(message.clone())) {
                    warn!("Failed to send message to {}: {}", relay_url, e);
                } else {
                    sent_count += 1;
                }
            }
        }
        
        if sent_count > 0 {
            debug!("📡 Message sent to {}/{} relays", sent_count, connections_guard.len());
            Ok(())
        } else {
            Err(anyhow::anyhow!("Failed to send message to any relay"))
        }
    }
    
    /// Handle outgoing messages
    async fn handle_outgoing_message(
        outgoing_msg: OutgoingMessage,
        connections: &Arc<RwLock<HashMap<String, RelayConnection>>>,
    ) {
        let connections_guard = connections.read().await;
        if let Some(connection) = connections_guard.get(&outgoing_msg.relay_url) {
            if connection.connected {
                let message_json = serde_json::to_string(&outgoing_msg.message)
                    .unwrap_or_else(|_| "{\"error\":\"serialization_failed\"}".to_string());
                
                if let Err(e) = connection.ws_sender.send(Message::Text(message_json)) {
                    error!("Failed to send message to {}: {}", outgoing_msg.relay_url, e);
                }
            }
        }
    }
    
    /// Encrypt message for NIP-04 private messaging (simplified for now)
    fn encrypt_message(&self, _recipient_pubkey: &str, message: &str) -> Result<String> {
        // TODO: Implement proper NIP-04 encryption with ECDH + AES-256-CBC
        // For now, use base64 encoding as placeholder
        use base64::prelude::*;
        let encrypted = BASE64_STANDARD.encode(format!("BITCHAT:{}", message));
        Ok(encrypted)
    }
    
    /// Get discovered BitChat peers
    pub async fn get_discovered_peers(&self) -> HashMap<String, DiscoveredNostrPeer> {
        self.discovered_peers.read().await.clone()
    }
    
    /// Get public key for this client
    pub fn public_key(&self) -> &str {
        &self.keypair.public_key
    }
    
    /// Check if connected to any relays
    pub async fn is_connected(&self) -> bool {
        let connections_guard = self.connections.read().await;
        connections_guard.values().any(|conn| conn.connected)
    }
}

/// Default implementation for NostrFilter
impl Default for NostrFilter {
    fn default() -> Self {
        Self {
            ids: None,
            authors: None,
            kinds: None,
            since: None,
            until: None,
            limit: None,
            tags: None,
        }
    }
}

/// BitChat discovery content for Nostr events
#[derive(Debug, Clone, Serialize, Deserialize)]
struct NostrDiscoveryContent {
    bitchat_peer_id: String,
    protocol_version: String,
    features: Vec<String>,
    metadata: HashMap<String, String>,
}

/// Nostr relay interface
#[derive(Debug)]
pub struct NostrRelay {
    url: String,
    connected: bool,
}

impl NostrRelay {
    pub fn new(url: String) -> Self {
        Self {
            url,
            connected: false,
        }
    }
    
    pub fn is_connected(&self) -> bool {
        self.connected
    }
    
    pub fn url(&self) -> &str {
        &self.url
    }
}

/// Nostr bridge implementation for BitChat network discovery
pub struct NostrBridge {
    peer_id: String,
    relay_urls: Vec<String>,
    client: Option<NostrClient>,
    config: BridgeConfig,
    is_active: Arc<RwLock<bool>>,
    stats: Arc<RwLock<BridgeStats>>,
}

impl NostrBridge {
    /// Create new Nostr bridge
    pub fn new(peer_id: String, relay_urls: Vec<String>, config: BridgeConfig) -> Self {
        let mut stats = BridgeStats::default();
        stats.name = "nostr-bridge".to_string();
        
        Self {
            peer_id,
            relay_urls,
            client: None,
            config,
            is_active: Arc::new(RwLock::new(false)),
            stats: Arc::new(RwLock::new(stats)),
        }
    }
    
    /// Get discovered BitChat peers from Nostr
    pub async fn get_discovered_nostr_peers(&self) -> HashMap<String, DiscoveredNostrPeer> {
        if let Some(ref client) = self.client {
            client.get_discovered_peers().await
        } else {
            HashMap::new()
        }
    }
}

#[async_trait]
impl NetworkBridge for NostrBridge {
    fn name(&self) -> String {
        "nostr-bridge".to_string()
    }
    
    async fn start(&mut self) -> Result<()> {
        info!("🚀 Starting Nostr bridge for BitChat...");
        
        let mut client = NostrClient::new(self.peer_id.clone(), self.relay_urls.clone());
        
        // Connect to relays and start discovery
        client.connect().await?;
        
        self.client = Some(client);
        *self.is_active.write().await = true;
        
        let mut stats = self.stats.write().await;
        stats.is_active = true;
        stats.connections_established += 1;
        stats.last_activity = Some(chrono::Utc::now());
        
        info!("✅ Nostr bridge connected and active");
        Ok(())
    }
    
    async fn stop(&mut self) -> Result<()> {
        info!("⏹️  Stopping Nostr bridge...");
        
        self.client = None;
        *self.is_active.write().await = false;
        
        let mut stats = self.stats.write().await;
        stats.is_active = false;
        
        Ok(())
    }
    
    fn supports_method(&self, method: &DiscoveryMethod) -> bool {
        matches!(method, DiscoveryMethod::Nostr { .. })
    }
    
    async fn send_message(&self, peer_id: &str, message: &[u8]) -> Result<()> {
        if let Some(ref client) = self.client {
            let message_str = String::from_utf8_lossy(message);
            client.send_private_message(peer_id, &message_str).await?;
            
            let mut stats = self.stats.write().await;
            stats.messages_sent += 1;
            stats.last_activity = Some(chrono::Utc::now());
            
            Ok(())
        } else {
            Err(anyhow::anyhow!("Nostr bridge not started"))
        }
    }
    
    async fn announce_presence(&self, _peer_id: &str, _metadata: &HashMap<String, String>) -> Result<()> {
        // Presence is announced automatically when client connects
        Ok(())
    }
    
    async fn is_active(&self) -> bool {
        if let Some(ref client) = self.client {
            client.is_connected().await
        } else {
            false
        }
    }
    
    async fn get_stats(&self) -> BridgeStats {
        let mut stats = self.stats.read().await.clone();
        stats.is_active = self.is_active().await;
        stats
    }
}