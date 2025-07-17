# 🔐 BitChat-Rust

A Rust implementation of the BitChat protocol - enabling secure, decentralized peer-to-peer messaging over Bluetooth LE mesh networks. Compatible with existing BitChat iOS/Android clients while providing native performance and cross-platform support.

---

## 🚀 Features

### Core BitChat Protocol
- 🔒 **End-to-end encryption** using X25519 + AES-256-GCM for private messages
- 🏠 **Channel encryption** with Argon2id password derivation for group chats
- ✍️ **Digital signatures** using Ed25519 for message authenticity
- 📡 **Mesh networking** with TTL-based routing (max 7 hops)
- 📦 **Store-and-forward** message delivery for offline peers
- 🗜️ **LZ4 compression** for messages >100 bytes (30-70% bandwidth savings)

### Cross-Platform Support
- 🖥️ **Desktop GUI** built with `egui` and `eframe`
- 💻 **CLI interface** for headless or terminal-based operation
- 🪟 **Windows** native support via WinRT Bluetooth APIs
- 🐧 **Linux/macOS** support via `btleplug`
- 📱 **Protocol compatibility** with iOS/Android BitChat clients

### Performance & Privacy
- 🔋 **Battery optimization** with adaptive power modes
- 🌐 **Offline-first** operation with no internet dependencies
- 👻 **Ephemeral by default** - messages exist only in memory
- 🎭 **Cover traffic** and timing randomization for privacy
- 🔄 **Automatic fragmentation** for large messages over BLE

---

## 🧱 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                        │
├─────────────────┬─────────────────┬─────────────────────────┤
│   Desktop GUI   │   CLI Client    │   Channel Management    │
│     (egui)      │    (clap)       │     (#channels)         │
└─────────────────┴─────────────────┴─────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                     Core Library                            │
├─────────────────┬─────────────────┬─────────────────────────┤
│   Encryption    │   Bluetooth     │   Protocol Handler      │
│   (X25519/AES)  │   (BLE Mesh)    │   (Binary Protocol)     │
└─────────────────┴─────────────────┴─────────────────────────┘
┌─────────────────────────────────────────────────────────────┐
│                   Platform Layer                            │
├─────────────────┬─────────────────┬─────────────────────────┤
│   Windows       │   Linux/macOS   │   Protocol Constants    │
│   (WinRT)       │   (btleplug)    │   (BitChat Compatible)  │
└─────────────────┴─────────────────┴─────────────────────────┘
```

### Workspace Structure

```
bitchat-rust/
├── crates/
│   ├── core/              # Core BitChat protocol implementation
│   │   ├── bluetooth/     # Cross-platform Bluetooth LE support
│   │   ├── protocol/      # Binary protocol & message handling
│   │   ├── encryption/    # Cryptographic operations
│   │   └── peer/          # Peer discovery & management
│   ├── desktop/           # GUI application (egui)
│   └── cli/               # Command-line interface
├── docs/                  # Documentation & protocol specs
└── Cargo.toml            # Workspace manifest
```

---

## ⚡ Quick Start

### Prerequisites
- [Rust](https://www.rust-lang.org/tools/install) 1.70+ 
- Bluetooth LE capable device
- Platform-specific requirements:
  - **Windows**: Windows 10+ with WinRT support
  - **Linux**: BlueZ 5.40+ 
  - **macOS**: macOS 10.15+

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/bitchat-rust
cd bitchat-rust

# Build all components
cargo build --release

# Or install from crates.io (when published)
cargo install bitchat-rust
```

### Running BitChat

#### Desktop GUI
```bash
# Launch the desktop application
cargo run --bin bitchat-desktop --release

# Or from the desktop crate
cd crates/desktop
cargo run --release
```

#### CLI Interface
```bash
# Start CLI with default settings
cargo run --bin bitchat-cli --release

# Custom configuration
cargo run --bin bitchat-cli --release -- --nickname "YourName" --verbose

# Join a specific channel
cargo run --bin bitchat-cli --release -- --join "#general"
```

### First Connection

1. **Start the application** on your device
2. **Set your nickname** (or use the auto-generated one)
3. **Scan for peers** - you'll automatically discover nearby BitChat users
4. **Join channels** with `/j #channelname` or start chatting publicly
5. **Send private messages** with `/msg @username your message`

---

## 🔧 Configuration

### Basic Configuration

Create a config file at `~/.config/bitchat/config.toml`:

```toml
[device]
name = "MyDevice"           # Device identifier (8 hex chars)
nickname = "YourNickname"   # Display name

[bluetooth]
scan_duration = 5           # Seconds to scan for peers
advertising_interval = 2    # Seconds between advertisements
max_connections = 10        # Maximum simultaneous peer connections

[privacy]
cover_traffic = true        # Enable dummy traffic for privacy
timing_randomization = true # Randomize message send timing
ephemeral_messages = true   # Don't persist messages to disk

[performance]
auto_compress = true        # Enable LZ4 compression
fragment_threshold = 350    # Fragment messages larger than this
battery_optimization = true # Adjust behavior based on battery level
```

### Power Management

BitChat automatically adjusts behavior based on battery level:

- **Performance Mode** (>60% or charging): Full features, maximum connectivity
- **Balanced Mode** (30-60%): Standard operation with minor optimizations  
- **Power Saver** (<30%): Reduced scanning, fewer connections
- **Ultra Low Power** (<10%): Minimal operation for emergency use

---

## 🛡️ Security & Privacy

### Encryption Protocols

- **Private Messages**: X25519 key exchange → AES-256-GCM encryption
- **Channel Messages**: Argon2id password derivation → AES-256-GCM encryption  
- **Digital Signatures**: Ed25519 signatures for message authenticity
- **Forward Secrecy**: New key pairs generated each session

### Privacy Features

- **No Registration**: No accounts, emails, or phone numbers required
- **Ephemeral by Default**: Messages exist only in device memory
- **Cover Traffic**: Random dummy messages prevent traffic analysis
- **Timing Randomization**: Random delays prevent correlation attacks
- **Local-First**: Works completely offline, no servers involved

### Security Considerations

- Messages are **end-to-end encrypted** with modern cryptography
- Peer IDs are **ephemeral** and regenerated each session
- **No metadata collection** - we can't see who you talk to or when
- **Open source** - audit the code yourself
- **Decentralized** - no single point of failure or surveillance

---

## 🌐 Protocol Compatibility

BitChat-Rust implements the complete BitChat binary protocol and is **fully compatible** with:

- [BitChat iOS](https://github.com/permissionlesstech/bitchat) (Swift)
- BitChat Android (Kotlin)
- Other BitChat protocol implementations

### Protocol Features

| Feature | Status | Notes |
|---------|---------|-------|
| Basic messaging | ✅ | Full compatibility |
| Private messages | ✅ | X25519 + AES-256-GCM |
| Channel support | ✅ | Password-protected channels |
| Message fragmentation | ✅ | Large message support |
| Store-and-forward | ✅ | Offline message delivery |
| Digital signatures | ✅ | Ed25519 authentication |
| Compression | ✅ | LZ4 compression |
| Mesh routing | ✅ | TTL-based forwarding |
| Peer discovery | ✅ | BLE advertisement compatible |

### Cross-Platform Testing

Your BitChat-Rust client can:
- ✅ **Discover** iOS/Android BitChat users
- ✅ **Exchange messages** with other platforms  
- ✅ **Join channels** created on mobile devices
- ✅ **Relay messages** in mixed-platform mesh networks
- ✅ **Maintain compatibility** with protocol updates

---

## 🚀 Usage Examples

### CLI Examples

```bash
# Basic usage - start and auto-join discovery
bitchat-cli --nickname "Alice"

# Join specific channel with password
bitchat-cli --join "#secret" --password "mypassword"

# High verbosity for debugging
bitchat-cli --verbose --log-level debug

# Save logs to file  
bitchat-cli --log-file bitchat.log

# Custom device configuration
bitchat-cli --device-id "ABCD1234" --max-connections 5
```

### API Usage

```rust
use bitchat_core::{BitchatCore, Config, BluetoothConfig};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create configuration
    let mut config = Config::default();
    config.device_name = "MyDevice".to_string();
    config.nickname = "Alice".to_string();
    
    // Initialize BitChat core
    let core = BitchatCore::new(config).await?;
    
    // Start the mesh network
    core.start().await?;
    
    // Send a message
    core.send_message("#general", "Hello, mesh network!").await?;
    
    // Listen for incoming messages
    while let Some(message) = core.receive_message().await {
        println!("Received: {} from {}", message.content, message.sender);
    }
    
    Ok(())
}
```

---

## 🔨 Development

### Building from Source

```bash
# Debug build with all features
cargo build --all-features

# Release build optimized for size
cargo build --release --all-features

# Run tests
cargo test --all

# Check code formatting and lints
cargo fmt --check
cargo clippy -- -D warnings

# Generate documentation
cargo doc --open --all-features
```

### Platform-Specific Development

#### Windows Development
```bash
# Windows requires WinRT support
cargo build --features windows-native

# Test Bluetooth on Windows
cargo test --features windows-native bluetooth::windows::tests
```

#### Linux Development  
```bash
# Install BlueZ development headers
sudo apt-get install libbluetooth-dev

# Build with btleplug backend
cargo build --features linux-bluez
```

### Cross-Compilation

```bash
# Build for Windows from Linux
cargo build --target x86_64-pc-windows-gnu

# Build for ARM (Raspberry Pi)
cargo build --target armv7-unknown-linux-gnueabihf

# Build for macOS from Linux (requires osxcross)
cargo build --target x86_64-apple-darwin
```

---

## 📊 Performance

### Benchmarks

- **Message Encryption**: ~50μs per message (X25519 + AES-256-GCM)
- **Compression**: ~30-70% size reduction for text messages
- **BLE Throughput**: ~1-3 Mbps effective (depending on device)
- **Mesh Latency**: <100ms per hop in ideal conditions
- **Battery Usage**: 5-15% per hour depending on activity and power mode

### Memory Usage

- **Core Library**: ~5-10MB base memory usage
- **Desktop GUI**: +15-25MB for UI framework  
- **Message Cache**: ~1MB per 1000 messages stored
- **Bluetooth Stack**: ~2-5MB for platform BLE drivers

---

## 🤝 Contributing

We welcome contributions! BitChat-Rust is open source and community-driven.

### Ways to Contribute

- 🐛 **Report bugs** and suggest features via GitHub issues
- 📝 **Improve documentation** and add examples
- 🔧 **Submit pull requests** for bug fixes and features
- 🧪 **Test compatibility** with different devices and platforms
- 🌍 **Add platform support** for new operating systems

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/yourusername/bitchat-rust
cd bitchat-rust

# Install development dependencies
cargo install cargo-watch cargo-audit

# Run tests in watch mode during development
cargo watch -x test

# Check security advisories
cargo audit
```

### Code Standards

- Follow [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `cargo fmt` for consistent formatting
- Pass `cargo clippy` with no warnings
- Add tests for new functionality
- Document public APIs with examples


---

## 📄 License

BitChat-Rust is released into the **public domain** under [The Unlicense](https://unlicense.org/), just like the original BitChat project.

This means you can use, modify, and distribute this software for any purpose, commercial or non-commercial, without any restrictions or attribution requirements.

---

## 🙏 Acknowledgments

- **[PermissionlessTech](https://github.com/permissionlesstech)** for the original BitChat protocol and iOS implementation

---

## 🔗 Related Projects

- **[BitChat iOS/macOS](https://github.com/permissionlesstech/bitchat)** - Original Swift implementation

---

*Built for the decentralized web*