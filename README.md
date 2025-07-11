# 🔐 SecureMesh

A Rust-based secure peer-to-peer messaging platform supporting both desktop GUI and CLI interfaces. Built with modern cryptography, async networking, and a modular architecture.

---

## 🚀 Features

- 🔒 End-to-end encryption using `x25519-dalek`, `ed25519-dalek`, and `chacha20poly1305`
- 🖥️ GUI built with `egui` and `eframe`
- 💻 CLI interface for headless or terminal-based use
- 📦 Modular crate-based workspace (`core`, `desktop`, `cli`)
- 📡 Bluetooth Low Energy (BLE) peer discovery (via `btleplug`)
- 🧾 Message serialization with `serde`
- ⏱️ Time-stamped secure messaging with `chrono`
- 🔍 Structured logging using `tracing`

---

## 🧱 Workspace Structure

├── crates/
│ ├── core/ # Core logic: crypto, messaging, protocol
│ ├── desktop/ # GUI application using egui/eframe
│ └── cli/ # Command-line interface
├── Cargo.toml # Workspace-level manifest


---

## 🛠 Dependencies

Core technologies used:

- **Async Runtime**: `tokio`, `futures`
- **Cryptography**: `ring`, `chacha20poly1305`, `x25519-dalek`, `ed25519-dalek`
- **Serialization**: `serde`, `serde_json`
- **UI**: `eframe`, `egui`
- **Bluetooth (Windows)**: `btleplug`
- **CLI**: `clap`
- **Utilities**: `uuid`, `chrono`, `dirs`, `anyhow`, `thiserror`

---

## 🧪 Running the Project

### 🧵 Prerequisites
- [Rust](https://www.rust-lang.org/tools/install)
- Cargo Workspace support (built-in)

### 📟 CLI Mode
```bash
cd crates/cli
cargo run --release
