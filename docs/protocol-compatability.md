# BitChat Protocol Compatibility

## Overview
BitChat-Rust implements the complete BitChat binary protocol as specified in the [BitChat whitepaper](WHITEPAPER.md). This document details our compatibility with iOS/Android implementations and outlines the internal Rust modules powering the desktop client.

---

## Protocol Implementation Status

### Packet Structure ✅
- [x] Binary packet format (version + type + ttl + timestamp + flags + payload_len + message_id)
- [x] 8-byte sender/recipient IDs  
- [x] Optional fragmentation headers
- [x] Ed25519 signature support

### Message Types
- [x] ANNOUNCE (0x01) - Peer announcement with public key
- [x] KEY_EXCHANGE (0x02) - X25519 key exchange
- [x] LEAVE (0x03) - Graceful disconnect
- [x] MESSAGE (0x04) - Chat messages
- [x] FRAGMENT_* (0x05-0x07) - Message fragmentation
- [x] CHANNEL_* (0x08-0x09) - Channel management

### Cross-Platform Testing Results
| Feature           | iOS Compatibility | Android Compatibility | Notes                          |
|------------------|-------------------|------------------------|--------------------------------|
| Peer Discovery    | ✅ Tested         | ✅ Tested              | Uses BC_<peer_id> naming       |
| Message Exchange  | ✅ Tested         | ✅ Tested              | X25519 + AES-256-GCM           |
| Channel Joining   | ✅ Tested         | ✅ Tested              | Argon2id password derivation   |
| Mesh Routing      | ✅ Tested         | ✅ Tested              | TTL-based forwarding           |

---

## BitChat-Rust Implementation Breakdown

### mod.rs - Protocol Aggregator
- Root module that re-exports `binary`, `windows`, `constants`, and `compatibility`.
- Provides public API for upper layers.
- Ensures consistency across implementations.

### binary.rs - Core Packet Encoding & Decoding
- Handles encoding/decoding of headers, payloads, and signatures.
- Aligns with mobile protocol formats.
- Supports fragmentation and reassembly.

### constants.rs - Protocol Constants & Message Types
- Shared values for message types, TTL, signature sizes, etc.
- Synced with mobile platforms.

### compatibility.rs - Peer ID & Device Name Utilities
- Generates 8-char hex peer IDs.
- Formats BLE name as BC_<PEERID> for cross-platform compatibility.

Example:
let peer_id = generate_compatible_peer_id();     // "3F6A92C4"
let device_name = create_device_name(&peer_id);  // "BC_3F6A92C4"

### windows.rs - Windows BLE Integration (Desktop)
- Bluetooth LE advertiser/scanner for Windows.
- Makes Rust peers visible to mobile clients.
- Sends and receives GATT packets.

### test_windows_ble.rs - BLE Interop Integration Tests
- Validates protocol behaviors through BLE.
- Tests ANNOUNCE, MESSAGE, FRAGMENT, CHANNEL logic.

---

## Status Summary

| Rust Module              | Role                            | iOS Compatible | Android Compatible | Notes                             |
|--------------------------|----------------------------------|----------------|--------------------|-----------------------------------|
| binary.rs                | Packet serialization             | ✅             | ✅                 | Fully symmetric                   |
| constants.rs             | Shared protocol values           | ✅             | ✅                 | Mirrors mobile definitions        |
| compatibility.rs         | Peer ID & BLE name formatting    | ✅             | ✅                 | Required for discovery            |
| windows.rs               | BLE layer (Windows)              | ✅             | ✅                 | Appears as BC_* device            |
| test_windows_ble.rs      | Cross-platform BLE interop tests | ✅             | ✅                 | Confirms real-world compatibility |

---

## Peer ID Compatibility

Example:
fn generate_compatible_peer_id() -> String {
    format!("{:08X}", rand::random::<u32>())
}

fn create_device_name(peer_id: &str) -> String {
    format!("BC_{}", peer_id.to_uppercase())
}

---

## Why This Matters

- ✅ Establishes credibility with iOS/Android BitChat community
- ✅ Ensures all peers speak the same protocol
- ✅ Enables seamless roaming between mobile and desktop clients
