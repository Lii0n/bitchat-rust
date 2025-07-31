# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

BitChat-Rust is a Rust implementation of the BitChat Moon Protocol (v1.1) - a secure, decentralized peer-to-peer messaging system that operates over Bluetooth LE mesh networks. The project enables encrypted communication without requiring internet infrastructure or centralized servers.

## Build Commands

### Primary Build Commands
```bash
# Build all components
cargo build --release --all-features

# Build specific components
cargo build -p bitchat-cli --features bluetooth    # CLI only
cargo build -p bitchat-desktop --features bluetooth # GUI only
cargo build -p bitchat-core --features bluetooth   # Core library only

# Development build (faster compilation)
cargo build --workspace
```

### Run Commands
```bash
# Run CLI client
cargo run --bin bitchat-cli --features bluetooth -- --nickname "YourName"

# Run desktop GUI
cargo run --bin bitchat-desktop --features bluetooth

# Run with diagnostics (Windows only)
cargo run --bin bitchat-cli --features bluetooth -- diagnostic
```

### Test Commands
```bash
# Run all tests
cargo test --all-features

# Run tests for specific crate
cargo test -p bitchat-core --features bluetooth

# Run with Bluetooth features (integration tests)
cargo test --features bluetooth test_noise_handshake
cargo test --features bluetooth test_cross_platform
```

### Development Commands
```bash
# Check code without building
cargo check --workspace

# Format code
cargo fmt --all

# Run clippy lints
cargo clippy --all-features

# Fix lint suggestions
cargo fix --lib -p bitchat-core
```

## Architecture Overview

### Workspace Structure
The project uses a Cargo workspace with three main crates:

- **`crates/core/`** - Core BitChat library implementing the Moon Protocol
- **`crates/cli/`** - Command-line interface application  
- **`crates/desktop/`** - Desktop GUI application using egui

### Core Architecture Components

#### Protocol Stack
- **Application Layer**: CLI and Desktop GUI interfaces
- **Moon Protocol v1.1**: Noise Protocol Framework implementation
- **Transport Layer**: Bluetooth LE GATT + Advertisement
- **Physical Layer**: Bluetooth Low Energy radio

#### Key Modules in `bitchat-core`

**Bluetooth Module** (`src/bluetooth/`):
- `manager.rs` - BluetoothManager for device discovery and connections
- `windows.rs` - Windows-specific WinRT Bluetooth implementation
- `events.rs` - Event system for Bluetooth state changes
- `compatibility.rs` - Cross-platform compatibility layer

**Protocol Module** (`src/protocol/`) - COMPLETE IMPLEMENTATION:
- `binary.rs` - Binary packet serialization/deserialization with fragmentation
- `router.rs` - **Complete mesh routing** with TTL, deduplication, and intelligent forwarding
- `constants.rs` - Protocol constants and message types

**Encryption Module** (`src/encryption/`) - UNIFIED ARCHITECTURE:
- `unified.rs` - **UnifiedEncryptionManager** coordinating all encryption strategies
- `noise.rs` - Noise Protocol Framework (XX pattern) for iOS compatibility
- `channels.rs` - Channel encryption with Argon2id password derivation
- `legacy.rs` - X25519 + ChaCha20-Poly1305 for backward compatibility
- Strategy-based routing with automatic protocol detection

**Messaging Module** (`src/messaging/`):
- `channel.rs` - **Consolidated ChannelManager** (unified from 3 duplicates)
- Message routing and delivery
- Store-and-forward for offline peers
- Channel-based communication with password protection

### Protocol Implementation

#### Noise Protocol (Moon v1.1)
The project implements the Noise XX pattern for mutual authentication:
- **Handshake**: 3-message XX pattern with identity hiding
- **Transport**: ChaCha20-Poly1305 with replay protection
- **Key Agreement**: X25519 (Curve25519)
- **Hash Function**: BLAKE2s

#### Bluetooth LE Mesh
- **Advertisement Format**: "BC_<PEER_ID>_M" (M = Moon protocol)
- **Service UUID**: Custom BitChat service identifier
- **GATT Characteristics**: TX/RX for bidirectional communication
- **Connection Management**: Dual role (server + client)

## Development Workflow

### Setting Up Development
1. Ensure Rust 1.70+ is installed
2. Enable Bluetooth LE adapter (4.0+ required)
3. On Windows: Run as Administrator for Bluetooth advertising
4. Use `cargo check --workspace` to verify setup

### Testing Cross-Platform Compatibility
The project is designed to interoperate with iOS and Android BitChat clients:
- Use the diagnostic command to test advertising format
- Verify device discovery between platforms
- Test Noise handshake establishment
- Confirm message encryption/decryption

### Key Implementation Notes

#### Unified Architecture (MAJOR CONSOLIDATION COMPLETED)
- **UnifiedEncryptionManager** in `crates/core/src/encryption/unified.rs`
- **Single API** for all encryption: `encryption.encrypt_message(context, data)`
- **Strategy-based routing**: 
  - `EncryptionStrategy::Noise` for iOS-compatible peer-to-peer
  - `EncryptionStrategy::Channel` for Argon2id password-based groups
  - `EncryptionStrategy::Legacy` for X25519 backward compatibility
- **Consolidated ChannelManager** - unified 3 duplicate implementations into 1
- **BitchatCore integration** - uses unified `EncryptionManager` type alias

#### Feature Flags
- `bluetooth` - Enables Bluetooth LE functionality (required for networking)
- Windows-specific code uses `#[cfg(windows)]` conditional compilation
- Non-Windows platforms use btleplug for cross-platform Bluetooth

#### Error Handling
- Uses `anyhow` for error propagation in async contexts
- `thiserror` for custom error types in protocol implementation
- Bluetooth errors are wrapped and propagated through event system

#### Async Architecture
- Built on Tokio runtime for async operations
- Bluetooth operations are non-blocking with event callbacks
- Message processing uses async channels for coordination

### Security Considerations

#### Unified Encryption System (UPDATED ARCHITECTURE)
The codebase now uses a **UnifiedEncryptionManager** that coordinates three encryption strategies:

**1. Noise Protocol (Primary - iOS Compatible)**
- `Noise_XX_25519_ChaChaPoly_BLAKE2s` pattern
- 3-message handshake: → e, ← e,ee,s,es, → s,se
- ChaCha20-Poly1305 AEAD in transport mode
- Forward secrecy with ephemeral keys
- **This is the primary method for peer-to-peer encryption**

**2. Channel Encryption (Groups)**
- Argon2id password derivation
- ChaCha20-Poly1305 for group messages
- Per-channel key management

**3. Legacy Encryption (Backward Compatibility)**
- X25519 + ChaCha20-Poly1305
- Maintains compatibility with v1.0 clients

#### Cryptographic Components
- All crypto operations use vetted libraries (snow, ring, chacha20poly1305, argon2)
- Private keys are zeroized after use using `zeroize` crate
- Session keys have automatic rotation limits (10k messages or 1 hour)
- Forward secrecy protects past communications
- **Noise Protocol provides iOS BitChat compatibility**

#### Protocol Security
- Noise XX provides mutual authentication and identity hiding
- Message counters prevent replay attacks
- TTL limits prevent infinite message forwarding
- Rate limiting protects against DoS attacks
- Session cleanup prevents memory leaks

## Common Development Tasks

### Using the Unified Encryption System
```rust
// Get encryption manager from BitchatCore
let mut encryption = core.encryption;

// === PEER-TO-PEER ENCRYPTION (Noise Protocol) ===
// Automatic strategy detection based on protocol version
let context = EncryptionContext::for_peer("peer123".to_string(), ProtocolVersion::Moon);
let ciphertext = encryption.encrypt_message(&context, b"Hello!")?;

// iOS-compatible Noise handshake
let handshake_msg = encryption.start_noise_handshake("peer123")?;
let response = encryption.handle_noise_handshake("peer123", &incoming_msg)?;

// === CHANNEL ENCRYPTION (Password-based Groups) ===
encryption.join_channel("general", "password123")?;
let context = EncryptionContext::for_channel("general".to_string());
let ciphertext = encryption.encrypt_message(&context, b"Hello channel!")?;

// === QUICK CONVENIENCE METHODS ===
let ciphertext = encryption.quick_encrypt_for_peer("peer123", b"Hello!")?;
let ciphertext = encryption.quick_encrypt_for_channel("general", b"Hello!")?;

// === STRATEGY MANAGEMENT ===
encryption.set_peer_strategy("alice", EncryptionStrategy::Noise);
let strategy = encryption.get_peer_strategy("alice"); // Returns Noise by default

// === STATISTICS AND MONITORING ===
let stats = encryption.get_stats(); // UnifiedEncryptionStats
let active_peers = encryption.get_active_peers();
```

### Adding New Message Types
1. Define in `protocol/constants.rs`
2. Add serialization in `protocol/binary.rs`
3. Handle in `messaging/manager.rs`
4. Update protocol documentation

### Encryption Strategy Selection
The **UnifiedEncryptionManager** automatically chooses encryption strategies:
- **EncryptionStrategy::Noise**: Default for Moon Protocol v1.1 peers (iOS compatible)
  - Uses `Noise_XX_25519_ChaChaPoly_BLAKE2s` pattern
  - 3-message handshake with identity hiding
  - ChaCha20-Poly1305 in transport mode
- **EncryptionStrategy::Legacy**: For backward compatibility with v1.0 clients
  - X25519 key exchange + ChaCha20-Poly1305
  - Maintains session compatibility
- **EncryptionStrategy::Channel**: Always for password-protected group channels
  - Argon2id password derivation with 64MB memory, 10 iterations
  - ChaCha20-Poly1305 with random nonces
  
Strategy detection is automatic based on peer protocol version, or can be manually set with `set_peer_strategy()`.

### Bluetooth Platform Support
- Windows: Uses WinRT APIs directly
- Linux/macOS: Uses btleplug library
- Platform-specific code isolated in `bluetooth/` module
- Common interface through BluetoothManager

### Performance Optimization
- **Unified encryption architecture** reduces memory overhead and code complexity
- **Strategy-based routing** eliminates redundant encryption managers
- **Consolidated channel management** prevents duplicate data structures
- Message compression using LZ4 for large payloads
- Bluetooth scanning duty cycling for battery life
- Connection limits to prevent resource exhaustion
- Efficient binary protocol with minimal overhead
- Session cleanup prevents memory leaks in long-running applications

## Troubleshooting

### Common Build Issues
- **Missing features**: Add `--features bluetooth` to enable networking
- **Windows permissions**: Run as Administrator for Bluetooth advertising
- **Bluetooth adapter**: Ensure BLE 4.0+ adapter is present and enabled

### Runtime Issues
- **Connection failures**: Check Bluetooth adapter compatibility
- **Advertisement not visible**: Verify Windows discoverability settings
- **Handshake timeout**: Ensure both devices support Noise Protocol

### Testing with Mobile Clients
- **iOS BitChat**: Compatible with unified Noise Protocol implementation
  - Device name format: Pure 16-character hex (no BC_ prefix for iOS)
  - Service UUID: `F47B5E2D-4A9E-4C5A-9B3F-8E1D2C3A4B5C`
  - Noise Pattern: `Noise_XX_25519_ChaChaPoly_BLAKE2s`
- **Android BitChat**: Compatible with store-and-forward messaging
- **Cross-platform testing**: Use `/diagnostic` command in CLI for compatibility verification

### Mesh Network Packet Routing (COMPLETED ✅)
The **PacketRouter** provides complete mesh networking functionality:
```rust
// Create router for our peer
let mut router = PacketRouter::new(my_peer_id);

// Add connected peers
router.add_connected_peer(peer_a);
router.add_connected_peer(peer_b);

// Route incoming packets
match router.route_packet(&packet) {
    RoutingDecision::Deliver => {
        // Packet is for us - process locally
        handle_local_packet(&packet);
    }
    RoutingDecision::Forward(peers) => {
        // Forward to these peers
        for peer in peers {
            send_to_peer(peer, &packet);
        }
    }
    RoutingDecision::Drop(reason) => {
        // Drop packet (TTL expired, duplicate, loop, etc.)
        debug!("Dropped packet: {:?}", reason);
    }
}

// Get routing statistics
let stats = router.get_stats();
println!("Forwarded: {}, Delivered: {}, Dropped: {}", 
         stats.packets_forwarded, stats.packets_delivered, stats.packets_dropped);
```

**Routing Features:**
- **TTL-based forwarding** prevents infinite loops
- **Message deduplication** using message IDs
- **Route discovery** with reliability scoring
- **Loop detection** and prevention
- **Broadcast flooding** with sender exclusion
- **Statistics tracking** for monitoring
- **Automatic cleanup** of expired routes

### iOS Protocol Requirements (Moon v1.1)
The unified encryption system ensures full iOS compatibility:
```rust
// iOS-compatible device discovery
let ios_device_name = peer_id_to_hex_string(&peer_id); // Pure hex, no prefix

// iOS-compatible Noise handshake
let handshake = encryption.start_noise_handshake("ios_peer")?;
// Handles full XX pattern: → e, ← e,ee,s,es, → s,se

// iOS-compatible transport encryption
let ciphertext = encryption.quick_encrypt_for_peer("ios_peer", message)?;
```