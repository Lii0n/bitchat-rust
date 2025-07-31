//! Packet router for BitChat mesh networking
//!
//! This module implements the packet routing logic for the BitChat mesh network,
//! handling message forwarding, TTL management, deduplication, and route discovery.

use super::binary::{BitchatPacket, MessageType, peer_utils};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

// ============================================================================
// ROUTING CONSTANTS
// ============================================================================

/// Maximum TTL for packets (from binary.rs)
const MAX_TTL: u8 = 7;
/// Route timeout - remove routes not used in this time
const ROUTE_TIMEOUT: Duration = Duration::from_secs(300); // 5 minutes
/// Maximum routing table size to prevent memory exhaustion
const MAX_ROUTING_TABLE_SIZE: usize = 1000;
/// Message deduplication cache size
const MAX_SEEN_MESSAGES: usize = 5000;
/// Cleanup interval for old routes and messages
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60); // 1 minute

// ============================================================================
// ROUTING STRUCTURES
// ============================================================================

/// Route entry in the routing table
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Next hop peer ID to reach the destination
    pub next_hop: [u8; 8],
    /// Number of hops to destination (metric)
    pub hop_count: u8,
    /// When this route was last updated
    pub last_updated: Instant,
    /// Reliability score (0-100) based on successful forwards
    pub reliability: u8,
}

/// Routing decision result
#[derive(Debug, Clone)]
pub enum RoutingDecision {
    /// Forward packet to these connected peers
    Forward(Vec<[u8; 8]>),
    /// Deliver locally (we are the destination)
    Deliver,
    /// Drop packet (TTL expired, duplicate, etc.)
    Drop(DropReason),
}

/// Reason for dropping a packet
#[derive(Debug, Clone)]
pub enum DropReason {
    /// TTL expired (reached 0)
    TtlExpired,
    /// Already seen this message (duplicate)
    Duplicate,
    /// No route to destination
    NoRoute,
    /// Packet validation failed
    InvalidPacket,
    /// Loop detected
    Loop,
}

/// Routing statistics
#[derive(Debug, Default)]
pub struct RoutingStats {
    pub packets_forwarded: u64,
    pub packets_delivered: u64,
    pub packets_dropped: u64,
    pub routes_discovered: u64,
    pub duplicate_packets: u64,
    pub active_routes: usize,
    pub connected_peers: usize,
}

// ============================================================================
// PACKET ROUTER IMPLEMENTATION
// ============================================================================

/// Packet router for mesh networking with intelligent forwarding
pub struct PacketRouter {
    /// Our peer ID
    my_peer_id: [u8; 8],
    /// Routing table: destination -> route info
    routing_table: HashMap<[u8; 8], RouteEntry>,
    /// Connected peers we can forward to
    connected_peers: HashSet<[u8; 8]>,
    /// Recently seen message IDs for deduplication
    seen_messages: HashSet<u32>,
    /// Routing statistics
    stats: RoutingStats,
    /// Last cleanup time
    last_cleanup: Instant,
}

impl PacketRouter {
    /// Create new packet router
    pub fn new(my_peer_id: [u8; 8]) -> Self {
        info!("🌐 Initializing packet router for peer {}", 
              peer_utils::peer_id_to_string(&my_peer_id));
        
        Self {
            my_peer_id,
            routing_table: HashMap::new(),
            connected_peers: HashSet::new(),
            seen_messages: HashSet::new(),
            stats: RoutingStats::default(),
            last_cleanup: Instant::now(),
        }
    }
    
    /// Get our peer ID
    pub fn my_peer_id(&self) -> [u8; 8] {
        self.my_peer_id
    }
    
    // ========================================================================
    // PEER MANAGEMENT
    // ========================================================================
    
    /// Add a connected peer
    pub fn add_connected_peer(&mut self, peer_id: [u8; 8]) {
        if self.connected_peers.insert(peer_id) {
            info!("🔗 Connected peer added: {}", peer_utils::peer_id_to_string(&peer_id));
            
            // Add direct route to this peer
            self.add_route(peer_id, peer_id, 1, 100);
            self.stats.connected_peers = self.connected_peers.len();
        }
    }
    
    /// Remove a connected peer
    pub fn remove_connected_peer(&mut self, peer_id: [u8; 8]) {
        if self.connected_peers.remove(&peer_id) {
            info!("🔗 Connected peer removed: {}", peer_utils::peer_id_to_string(&peer_id));
            
            // Remove direct route
            self.routing_table.remove(&peer_id);
            
            // Remove routes that use this peer as next hop
            self.routing_table.retain(|_, route| route.next_hop != peer_id);
            
            self.stats.connected_peers = self.connected_peers.len();
            self.stats.active_routes = self.routing_table.len();
        }
    }
    
    /// Get list of connected peers
    pub fn get_connected_peers(&self) -> Vec<[u8; 8]> {
        self.connected_peers.iter().copied().collect()
    }
    
    // ========================================================================
    // ROUTE MANAGEMENT
    // ========================================================================
    
    /// Add or update a route
    pub fn add_route(&mut self, dest: [u8; 8], next_hop: [u8; 8], hop_count: u8, reliability: u8) {
        // Don't add routes to ourselves
        if dest == self.my_peer_id {
            return;
        }
        
        // Check if we should update the route
        let should_update = match self.routing_table.get(&dest) {
            Some(existing) => {
                // Update if: better hop count, or same hop count but better reliability
                hop_count < existing.hop_count || 
                (hop_count == existing.hop_count && reliability > existing.reliability)
            }
            None => true, // New route
        };
        
        if should_update {
            let route = RouteEntry {
                next_hop,
                hop_count,
                last_updated: Instant::now(),
                reliability,
            };
            
            let is_new = self.routing_table.insert(dest, route).is_none();
            if is_new {
                self.stats.routes_discovered += 1;
                debug!("🗺️ New route: {} -> {} (via {}, {} hops)", 
                       peer_utils::peer_id_to_string(&self.my_peer_id),
                       peer_utils::peer_id_to_string(&dest),
                       peer_utils::peer_id_to_string(&next_hop),
                       hop_count);
            } else {
                debug!("🗺️ Updated route: {} -> {} (via {}, {} hops)",
                       peer_utils::peer_id_to_string(&self.my_peer_id),
                       peer_utils::peer_id_to_string(&dest),
                       peer_utils::peer_id_to_string(&next_hop),
                       hop_count);
            }
            
            self.stats.active_routes = self.routing_table.len();
        }
    }
    
    /// Get next hop for destination
    pub fn get_next_hop(&self, dest: &[u8; 8]) -> Option<[u8; 8]> {
        self.routing_table.get(dest).map(|route| route.next_hop)
    }
    
    /// Get route information
    pub fn get_route(&self, dest: &[u8; 8]) -> Option<&RouteEntry> {
        self.routing_table.get(dest)
    }
    
    // ========================================================================
    // PACKET ROUTING LOGIC
    // ========================================================================
    
    /// Route a packet through the mesh network
    pub fn route_packet(&mut self, packet: &BitchatPacket) -> RoutingDecision {
        // Periodic cleanup
        self.maybe_cleanup();
        
        // Basic packet validation
        if let Err(e) = packet.validate() {
            warn!("📦 Invalid packet: {}", e);
            self.stats.packets_dropped += 1;
            return RoutingDecision::Drop(DropReason::InvalidPacket);
        }
        
        // Check TTL (packets with TTL 0 should be dropped)
        if packet.ttl == 0 {
            debug!("📦 Dropping packet with TTL 0 from {}", 
                   peer_utils::peer_id_to_string(&packet.sender_id));
            self.stats.packets_dropped += 1;
            return RoutingDecision::Drop(DropReason::TtlExpired);
        }
        
        // Deduplication check
        if self.is_duplicate(packet) {
            debug!("📦 Dropping duplicate packet {} from {}", 
                   packet.message_id, 
                   peer_utils::peer_id_to_string(&packet.sender_id));
            self.stats.packets_dropped += 1;
            self.stats.duplicate_packets += 1;
            return RoutingDecision::Drop(DropReason::Duplicate);
        }
        
        // Mark as seen
        self.mark_as_seen(packet.message_id);
        
        // Update routing information from packet
        self.update_routes_from_packet(packet);
        
        // Determine routing decision
        match packet.recipient_id {
            Some(recipient) => self.route_private_packet(packet, recipient),
            None => self.route_broadcast_packet(packet),
        }
    }
    
    /// Route a private (directed) packet
    fn route_private_packet(&mut self, packet: &BitchatPacket, recipient: [u8; 8]) -> RoutingDecision {
        // Check if we are the recipient
        if recipient == self.my_peer_id {
            debug!("📦 Delivering private packet from {} to us", 
                   peer_utils::peer_id_to_string(&packet.sender_id));
            self.stats.packets_delivered += 1;
            return RoutingDecision::Deliver;
        }
        
        // Find route to recipient
        if let Some(route) = self.routing_table.get(&recipient) {
            // Check for loop (don't send back to sender)
            if route.next_hop == packet.sender_id {
                debug!("📦 Loop detected, dropping packet to {}", 
                       peer_utils::peer_id_to_string(&recipient));
                self.stats.packets_dropped += 1;
                return RoutingDecision::Drop(DropReason::Loop);
            }
            
            // Forward to next hop
            debug!("📦 Forwarding private packet to {} via {}", 
                   peer_utils::peer_id_to_string(&recipient),
                   peer_utils::peer_id_to_string(&route.next_hop));
            self.stats.packets_forwarded += 1;
            RoutingDecision::Forward(vec![route.next_hop])
        } else {
            debug!("📦 No route to {}, dropping packet", 
                   peer_utils::peer_id_to_string(&recipient));
            self.stats.packets_dropped += 1;
            RoutingDecision::Drop(DropReason::NoRoute)
        }
    }
    
    /// Route a broadcast packet
    fn route_broadcast_packet(&mut self, packet: &BitchatPacket) -> RoutingDecision {
        // Always deliver broadcast packets locally
        self.stats.packets_delivered += 1;
        
        // Determine which peers to forward to
        let forward_peers = self.select_broadcast_peers(packet);
        
        if forward_peers.is_empty() {
            debug!("📦 No peers to forward broadcast to");
            RoutingDecision::Deliver
        } else {
            debug!("📦 Forwarding broadcast to {} peers", forward_peers.len());
            self.stats.packets_forwarded += 1;
            RoutingDecision::Forward(forward_peers)
        }
    }
    
    /// Select peers to forward broadcast packet to
    fn select_broadcast_peers(&self, packet: &BitchatPacket) -> Vec<[u8; 8]> {
        self.connected_peers
            .iter()
            .filter(|&&peer_id| {
                // Don't send back to sender
                peer_id != packet.sender_id
            })
            .copied()
            .collect()
    }
    
    // ========================================================================
    // ROUTE DISCOVERY AND MAINTENANCE
    // ========================================================================
    
    /// Update routing table based on packet information
    fn update_routes_from_packet(&mut self, packet: &BitchatPacket) {
        let sender_id = packet.sender_id;
        
        // Don't add routes to ourselves
        if sender_id == self.my_peer_id {
            return;
        }
        
        // Calculate hop count (MAX_TTL - current_ttl + 1)
        let hop_count = MAX_TTL - packet.ttl + 1;
        
        // Find which connected peer this packet came through
        // In a real implementation, this would be provided by the transport layer
        // For now, we assume it came directly from the sender if they're connected
        if self.connected_peers.contains(&sender_id) {
            // Direct connection
            self.add_route(sender_id, sender_id, 1, 100);
        } else {
            // Try to find the best next hop among connected peers
            if let Some(&best_peer) = self.connected_peers.iter().next() {
                self.add_route(sender_id, best_peer, hop_count, 80);
            }
        }
    }
    
    // ========================================================================
    // DEDUPLICATION
    // ========================================================================
    
    /// Check if packet is a duplicate
    fn is_duplicate(&self, packet: &BitchatPacket) -> bool {
        self.seen_messages.contains(&packet.message_id)
    }
    
    /// Mark message as seen
    fn mark_as_seen(&mut self, message_id: u32) {
        self.seen_messages.insert(message_id);
        
        // Prevent unbounded growth
        if self.seen_messages.len() > MAX_SEEN_MESSAGES {
            // Clear half the cache (simple approach)
            let to_remove: Vec<_> = self.seen_messages.iter().take(MAX_SEEN_MESSAGES / 2).copied().collect();
            for msg_id in to_remove {
                self.seen_messages.remove(&msg_id);
            }
            debug!("🧹 Cleaned seen messages cache");
        }
    }
    
    // ========================================================================
    // MAINTENANCE AND CLEANUP
    // ========================================================================
    
    /// Maybe perform cleanup if enough time has passed
    fn maybe_cleanup(&mut self) {
        if self.last_cleanup.elapsed() >= CLEANUP_INTERVAL {
            self.cleanup();
            self.last_cleanup = Instant::now();
        }
    }
    
    /// Clean up expired routes and old messages
    pub fn cleanup(&mut self) {
        let before_routes = self.routing_table.len();
        let now = Instant::now();
        
        // Remove expired routes
        self.routing_table.retain(|dest, route| {
            let keep = now.duration_since(route.last_updated) < ROUTE_TIMEOUT;
            if !keep {
                debug!("🧹 Removing expired route to {}", 
                       peer_utils::peer_id_to_string(dest));
            }
            keep
        });
        
        // Limit routing table size
        if self.routing_table.len() > MAX_ROUTING_TABLE_SIZE {
            // Remove oldest routes
            let mut routes: Vec<_> = self.routing_table.iter().collect();
            routes.sort_by_key(|(_, route)| route.last_updated);
            
            let to_remove = routes.len() - MAX_ROUTING_TABLE_SIZE;
            let keys_to_remove: Vec<[u8; 8]> = routes.iter()
                .take(to_remove)
                .map(|(&dest, _)| dest)
                .collect();
            
            for dest in keys_to_remove {
                self.routing_table.remove(&dest);
            }
            debug!("🧹 Removed {} old routes to limit table size", to_remove);
        }
        
        let cleaned_routes = before_routes - self.routing_table.len();
        if cleaned_routes > 0 {
            info!("🧹 Cleaned {} expired routes", cleaned_routes);
        }
        
        self.stats.active_routes = self.routing_table.len();
    }
    
    // ========================================================================
    // STATISTICS AND MONITORING
    // ========================================================================
    
    /// Get routing statistics
    pub fn get_stats(&self) -> &RoutingStats {
        &self.stats
    }
    
    /// Get routing table size
    pub fn routing_table_size(&self) -> usize {
        self.routing_table.len()
    }
    
    /// Get all known destinations
    pub fn get_known_destinations(&self) -> Vec<[u8; 8]> {
        self.routing_table.keys().copied().collect()
    }
    
    /// Check if we have a route to destination
    pub fn has_route_to(&self, dest: &[u8; 8]) -> bool {
        self.routing_table.contains_key(dest)
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Create a copy of packet with decremented TTL
pub fn decrement_packet_ttl(packet: &BitchatPacket) -> Option<BitchatPacket> {
    if packet.ttl > 0 {
        let mut forwarded_packet = packet.clone();
        forwarded_packet.ttl -= 1;
        Some(forwarded_packet)
    } else {
        None
    }
}

/// Check if packet should be forwarded based on type
pub fn should_forward_packet(packet: &BitchatPacket) -> bool {
    match packet.message_type {
        MessageType::Announce => true,      // Always forward announcements
        MessageType::Message => true,       // Forward messages
        MessageType::KeyExchange => false,  // Key exchanges are direct only
        MessageType::Leave => true,         // Forward leave announcements
        MessageType::ChannelAnnounce => true, // Forward channel announcements
        MessageType::ChannelJoin => true,   // Forward channel joins
        MessageType::ChannelLeave => true,  // Forward channel leaves
        MessageType::DeliveryAck => false, // Acks are direct only
        MessageType::ReadReceipt => false, // Receipts are direct only
        _ => false, // Conservative approach for unknown types
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_packet(sender: [u8; 8], recipient: Option<[u8; 8]>) -> BitchatPacket {
        match recipient {
            Some(recv) => BitchatPacket::new_private(
                MessageType::Message,
                sender,
                recv,
                b"test message".to_vec(),
            ),
            None => BitchatPacket::new_broadcast(
                MessageType::Message,
                sender,
                b"test broadcast".to_vec(),
            ),
        }
    }

    #[test]
    fn test_router_creation() {
        let my_peer_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let router = PacketRouter::new(my_peer_id);
        
        assert_eq!(router.my_peer_id(), my_peer_id);
        assert_eq!(router.routing_table_size(), 0);
        assert_eq!(router.get_connected_peers().len(), 0);
    }

    #[test]
    fn test_peer_management() {
        let my_peer_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let peer_a = [1, 1, 1, 1, 1, 1, 1, 1];
        let peer_b = [2, 2, 2, 2, 2, 2, 2, 2];
        let mut router = PacketRouter::new(my_peer_id);
        
        // Add peers
        router.add_connected_peer(peer_a);
        router.add_connected_peer(peer_b);
        
        assert_eq!(router.get_connected_peers().len(), 2);
        assert!(router.has_route_to(&peer_a));
        assert!(router.has_route_to(&peer_b));
        
        // Remove peer
        router.remove_connected_peer(peer_a);
        assert_eq!(router.get_connected_peers().len(), 1);
        assert!(!router.has_route_to(&peer_a));
        assert!(router.has_route_to(&peer_b));
    }

    #[test]
    fn test_packet_routing_direct_delivery() {
        let my_peer_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let sender = [9, 9, 9, 9, 9, 9, 9, 9];
        let mut router = PacketRouter::new(my_peer_id);
        
        // Create packet addressed to us
        let packet = create_test_packet(sender, Some(my_peer_id));
        
        match router.route_packet(&packet) {
            RoutingDecision::Deliver => {
                // Correct - packet should be delivered to us
            }
            _ => panic!("Expected Deliver decision"),
        }
    }

    #[test]
    fn test_deduplication() {
        let my_peer_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let sender = [9, 9, 9, 9, 9, 9, 9, 9];
        let peer_a = [2, 2, 2, 2, 2, 2, 2, 2];
        let mut router = PacketRouter::new(my_peer_id);
        
        // Add a connected peer so broadcast gets forwarded
        router.add_connected_peer(peer_a);
        
        let packet = create_test_packet(sender, None);
        
        // First time should be processed (forwarded since we have connected peers)
        match router.route_packet(&packet) {
            RoutingDecision::Forward(_) => {},
            _ => panic!("Expected Forward decision"),
        }
        
        // Second time should be dropped as duplicate
        match router.route_packet(&packet) {
            RoutingDecision::Drop(DropReason::Duplicate) => {
                // Correct - duplicate should be dropped
            }
            _ => panic!("Expected Drop(Duplicate) decision"),
        }
    }

    #[test]
    fn test_ttl_expiration() {
        let my_peer_id = [1, 2, 3, 4, 5, 6, 7, 8];
        let sender = [9, 9, 9, 9, 9, 9, 9, 9];
        let mut router = PacketRouter::new(my_peer_id);
        
        let mut packet = create_test_packet(sender, None);
        packet.ttl = 0; // Expired TTL
        
        match router.route_packet(&packet) {
            RoutingDecision::Drop(DropReason::TtlExpired) => {
                // Correct - TTL expired
            }
            _ => panic!("Expected Drop(TtlExpired) decision"),
        }
    }
}