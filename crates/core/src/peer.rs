use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub id: Uuid,
    pub name: String,
    pub address: String,
    pub public_key: Option<Vec<u8>>,
    pub last_seen: DateTime<Utc>,
    pub connected: bool,
    pub channels: Vec<String>,
}

pub struct PeerManager {
    peers: HashMap<Uuid, Peer>,
}

impl PeerManager {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
        }
    }

    pub fn add_peer(&mut self, peer: Peer) {
        self.peers.insert(peer.id, peer);
    }

    pub fn get_peer(&self, id: &Uuid) -> Option<&Peer> {
        self.peers.get(id)
    }

    pub fn get_peers(&self) -> Vec<&Peer> {
        self.peers.values().collect()
    }

    pub fn update_peer_status(&mut self, id: &Uuid, connected: bool) {
        if let Some(peer) = self.peers.get_mut(id) {
            peer.connected = connected;
            peer.last_seen = Utc::now();
        }
    }

    pub fn get_connected_peers(&self) -> Vec<&Peer> {
        self.peers.values().filter(|p| p.connected).collect()
    }
}
