//! BitChat protocol constants
//!
//! This module contains constants used throughout the BitChat protocol,
//! including Bluetooth service UUIDs and other configuration values.

use uuid::Uuid;

/// BitChat service UUID for Bluetooth LE advertisement and discovery
/// This UUID is used to identify BitChat devices on the mesh network
pub const BITCHAT_SERVICE_UUID: Uuid = Uuid::from_u128(0x12340000_1234_1234_1234_123456789abc);

/// BitChat characteristic UUID for message exchange
/// This characteristic is used for sending and receiving messages
pub const BITCHAT_MESSAGE_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0x12340001_1234_1234_1234_123456789abc);

/// BitChat characteristic UUID for peer announcements
/// This characteristic is used for peer discovery and announcement
pub const BITCHAT_ANNOUNCE_CHARACTERISTIC_UUID: Uuid = Uuid::from_u128(0x12340002_1234_1234_1234_123456789abc);

/// Maximum message size (MTU - headers)
pub const MAX_MESSAGE_SIZE: usize = 500;

/// Maximum TTL for message routing
pub const MAX_TTL: u8 = 7;

/// Connection timeout in seconds
pub const CONNECTION_TIMEOUT_SECS: u64 = 30;

/// Maximum number of simultaneous connections
pub const MAX_CONNECTIONS: usize = 10;

/// RSSI threshold for connection quality
pub const MIN_RSSI_THRESHOLD: i8 = -85;

/// Scan interval in milliseconds
pub const DEFAULT_SCAN_INTERVAL_MS: u64 = 3000;

/// Advertise interval in milliseconds
pub const DEFAULT_ADVERTISE_INTERVAL_MS: u64 = 1000;