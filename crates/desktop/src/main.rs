use bitchat_core::{BitchatCore, Config, BitchatBluetoothDelegate, BinaryProtocol, MessageType};
use eframe::egui;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::sync::OnceLock;

#[cfg(feature = "bluetooth")]
use bitchat_core::bluetooth::windows::WindowsBluetoothAdapter;

// Safe global adapter reference using Arc<Mutex<Option<T>>>
#[cfg(feature = "bluetooth")]
static REAL_BLUETOOTH: OnceLock<Arc<Mutex<Option<WindowsBluetoothAdapter>>>> = OnceLock::new();

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enable logging
    tracing_subscriber::fmt::init();

    // Create default config
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("bitchat");

    // Generate deterministic device name like CLI
    let device_name = {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        std::env::var("COMPUTERNAME")
            .or_else(|_| std::env::var("HOSTNAME"))
            .unwrap_or_else(|_| "bitchat-desktop".to_string())
            .hash(&mut hasher);
        let hash = hasher.finish();
        
        let mut peer_bytes = [0u8; 8];
        peer_bytes.copy_from_slice(&hash.to_be_bytes());
        hex::encode(peer_bytes).to_uppercase()
    };

    let config = Config {
        device_name,
        data_dir,
        ..Default::default()
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([600.0, 500.0])
            .with_title("BitChat Desktop"),
        ..Default::default()
    };

    eframe::run_native(
        "BitChat Desktop",
        options,
        Box::new(|cc| {
            // Create the app with the config
            let rt = tokio::runtime::Runtime::new().unwrap();
            let core = rt.block_on(async { BitchatCore::new(config).await }).unwrap();
            
            Box::new(BitChatApp::new(cc, core, rt)) as Box<dyn eframe::App>
        }),
    )?;

    Ok(())
}

// Desktop delegate for handling Bluetooth events
struct DesktopDelegate {
    messages: Arc<Mutex<Vec<String>>>,
}

impl DesktopDelegate {
    fn new(messages: Arc<Mutex<Vec<String>>>) -> Self {
        Self { messages }
    }
}

impl BitchatBluetoothDelegate for DesktopDelegate {
    fn on_device_discovered(&self, device_id: &str, device_name: Option<&str>, rssi: i8) {
        let message = format!("📡 Discovered: {} ({:?}) RSSI: {}dBm", device_id, device_name, rssi);
        if let Ok(mut msgs) = self.messages.try_lock() {
            msgs.push(message);
        }
    }

    fn on_device_connected(&self, device_id: &str, peer_id: &str) {
        let message = format!("🔗 Connected: {} (peer: {})", device_id, peer_id);
        if let Ok(mut msgs) = self.messages.try_lock() {
            msgs.push(message);
        }
    }

    fn on_device_disconnected(&self, device_id: &str, peer_id: &str) {
        let message = format!("❌ Disconnected: {} (peer: {})", device_id, peer_id);
        if let Ok(mut msgs) = self.messages.try_lock() {
            msgs.push(message);
        }
    }

    fn on_message_received(&self, from_peer: &str, data: &[u8]) {
        if let Ok(packet) = BinaryProtocol::decode(data) {
            let message = match packet.message_type {
                MessageType::Message => {
                    if let Ok(content) = String::from_utf8(packet.payload.clone()) {
                        if content.starts_with('#') {
                            let parts: Vec<&str> = content.splitn(2, ' ').collect();
                            if parts.len() == 2 {
                                let channel = parts[0];
                                let msg = parts[1];
                                format!("📺 [{}] {}: {}", channel, from_peer, msg)
                            } else {
                                format!("💬 {}: {}", from_peer, content)
                            }
                        } else {
                            format!("💬 {}: {}", from_peer, content)
                        }
                    } else {
                        format!("📦 Binary message from {}", from_peer)
                    }
                }
                MessageType::Announce => {
                    if let Ok(nickname) = String::from_utf8(packet.payload) {
                        format!("👋 {} announced as: {}", from_peer, nickname)
                    } else {
                        format!("👋 {} announced", from_peer)
                    }
                }
                MessageType::ChannelJoin => {
                    if let Ok(channel) = String::from_utf8(packet.payload) {
                        format!("🚪 {} joined channel: {}", from_peer, channel)
                    } else {
                        format!("🚪 {} joined a channel", from_peer)
                    }
                }
                MessageType::ChannelLeave => {
                    if let Ok(channel) = String::from_utf8(packet.payload) {
                        format!("👋 {} left channel: {}", from_peer, channel)
                    } else {
                        format!("👋 {} left a channel", from_peer)
                    }
                }
                _ => format!("📦 Received {:?} from {}", packet.message_type, from_peer)
            };
            
            if let Ok(mut msgs) = self.messages.try_lock() {
                msgs.push(message);
            }
        }
    }

    fn on_error(&self, message: &str) {
        let error_msg = format!("❌ Bluetooth error: {}", message);
        if let Ok(mut msgs) = self.messages.try_lock() {
            msgs.push(error_msg);
        }
    }
}

struct BitChatApp {
    core: BitchatCore,
    runtime: tokio::runtime::Runtime,
    message_input: String,
    messages: Arc<Mutex<Vec<String>>>,
    current_tab: Tab,
    bluetooth_initialized: bool,
    discovered_devices: Vec<(String, String, i16, u64)>, // (device_id, peer_id, rssi, age_secs)
    channels: Vec<String>,
    status_text: String,
}

#[derive(PartialEq)]
enum Tab {
    Chat,
    Peers,
    Channels,
    Status,
}

impl BitChatApp {
    fn new(_cc: &eframe::CreationContext<'_>, core: BitchatCore, runtime: tokio::runtime::Runtime) -> Self {
        let messages = Arc::new(Mutex::new(Vec::new()));
        
        let mut app = Self {
            core,
            runtime,
            message_input: String::new(),
            messages: messages.clone(),
            current_tab: Tab::Chat,
            bluetooth_initialized: false,
            discovered_devices: Vec::new(),
            channels: Vec::new(),
            status_text: "Initializing...".to_string(),
        };
        
        // Initialize real Bluetooth adapter (same as CLI)
        app.initialize_real_bluetooth(messages);
        
        app
    }
    
    fn initialize_real_bluetooth(&mut self, messages: Arc<Mutex<Vec<String>>>) {
        #[cfg(feature = "bluetooth")]
        {
            let device_name = self.core.config.device_name.clone();
            let runtime = &self.runtime;
            
            // Add initialization message
            if let Ok(mut msgs) = messages.try_lock() {
                msgs.push("🔵 Starting REAL Bluetooth adapter...".to_string());
            }
            
            let result = runtime.block_on(async {
                let bluetooth_config = bitchat_core::bluetooth::BluetoothConfig::with_device_name(device_name);
                
                match WindowsBluetoothAdapter::new(bluetooth_config).await {
                    Ok(mut adapter) => {
                        if adapter.is_available().await {
                            match adapter.start_scanning().await {
                                Ok(_) => {
                                    // Store adapter globally
                                    let adapter_ref = REAL_BLUETOOTH.get_or_init(|| {
                                        Arc::new(Mutex::new(None))
                                    });
                                    *adapter_ref.lock().await = Some(adapter);
                                    Ok("✅ Real Bluetooth adapter started successfully".to_string())
                                }
                                Err(e) => Err(format!("❌ Failed to start scanning: {}", e))
                            }
                        } else {
                            Err("❌ Bluetooth not available".to_string())
                        }
                    }
                    Err(e) => Err(format!("❌ Failed to create adapter: {}", e))
                }
            });
            
            match result {
                Ok(success_msg) => {
                    self.bluetooth_initialized = true;
                    self.status_text = success_msg.clone();
                    if let Ok(mut msgs) = messages.try_lock() {
                        msgs.push(success_msg);
                    }
                }
                Err(error_msg) => {
                    self.status_text = error_msg.clone();
                    if let Ok(mut msgs) = messages.try_lock() {
                        msgs.push(error_msg);
                        msgs.push("💡 Falling back to core Bluetooth manager".to_string());
                    }
                    
                    // Fallback to core manager
                    let delegate = Arc::new(DesktopDelegate::new(messages.clone()));
                    let core_ref = &self.core;
                    if let Err(e) = runtime.block_on(async {
                        core_ref.start_bluetooth_with_delegate(delegate).await
                    }) {
                        if let Ok(mut msgs) = messages.try_lock() {
                            msgs.push(format!("❌ Core Bluetooth also failed: {}", e));
                        }
                    }
                }
            }
        }
        
        #[cfg(not(feature = "bluetooth"))]
        {
            self.status_text = "⚠️ Bluetooth feature not enabled".to_string();
            if let Ok(mut msgs) = messages.try_lock() {
                msgs.push("⚠️ Bluetooth feature not enabled".to_string());
            }
        }
    }
    
    fn update_discovered_devices(&mut self) {
        #[cfg(feature = "bluetooth")]
        {
            if let Some(adapter_ref) = REAL_BLUETOOTH.get() {
                let discovered = self.runtime.block_on(async {
                    if let Some(ref adapter) = *adapter_ref.lock().await {
                        adapter.get_discovered_devices().await
                    } else {
                        std::collections::HashMap::new()
                    }
                });
                
                self.discovered_devices = discovered
                    .into_iter()
                    .map(|(device_id, device)| {
                        let peer_id = device.peer_id.unwrap_or_else(|| "unknown".to_string());
                        let rssi = device.rssi;
                        let age_secs = device.last_seen.elapsed().as_secs();
                        (device_id, peer_id, rssi, age_secs)
                    })
                    .collect();
            }
        }
        
        // Also update channels
        if let Ok(channels) = self.runtime.block_on(async {
            self.core.list_channels().await
        }) {
            self.channels = channels;
        }
    }
    
    fn send_message(&mut self, message: &str) {
        let core_ref = &self.core;
        let result = self.runtime.block_on(async {
            core_ref.send_channel_message("#general", message).await
        });
        
        match result {
            Ok(_) => {
                if let Ok(mut msgs) = self.messages.try_lock() {
                    msgs.push(format!("You: {}", message));
                }
            }
            Err(e) => {
                if let Ok(mut msgs) = self.messages.try_lock() {
                    msgs.push(format!("❌ Failed to send: {}", e));
                }
            }
        }
    }
}

impl eframe::App for BitChatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Update discovered devices periodically
        self.update_discovered_devices();
        
        // Top panel with tabs
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.current_tab, Tab::Chat, "💬 Chat");
                ui.selectable_value(&mut self.current_tab, Tab::Peers, "👥 Peers");
                ui.selectable_value(&mut self.current_tab, Tab::Channels, "📺 Channels");
                ui.selectable_value(&mut self.current_tab, Tab::Status, "🔧 Status");
                
                ui.separator();
                
                // Show device info in header
                ui.label(format!("Device: {}", self.core.config.device_name));
                ui.separator();
                ui.monospace(format!("ID: {}", hex::encode(self.core.get_peer_id())));
            });
        });
        
        // Main content area
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_tab {
                Tab::Chat => self.show_chat_tab(ui),
                Tab::Peers => self.show_peers_tab(ui),
                Tab::Channels => self.show_channels_tab(ui),
                Tab::Status => self.show_status_tab(ui),
            }
        });
        
        // Request repaint for real-time updates
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }
}

impl BitChatApp {
    fn show_chat_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("💬 Chat");
        
        // Messages area
        egui::ScrollArea::vertical()
            .max_height(300.0)
            .auto_shrink([false; 2])
            .stick_to_bottom(true)
            .show(ui, |ui| {
                if let Ok(messages) = self.messages.try_lock() {
                    for message in messages.iter() {
                        ui.label(message);
                    }
                    if messages.is_empty() {
                        ui.label("No messages yet. Start chatting!");
                    }
                }
            });
        
        ui.separator();
        
        // Message input
        ui.horizontal(|ui| {
            ui.label("Message:");
            let response = ui.text_edit_singleline(&mut self.message_input);
            
            if response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                if !self.message_input.trim().is_empty() {
                    let message = self.message_input.trim().to_string();
                    self.send_message(&message);
                    self.message_input.clear();
                }
                response.request_focus();
            }
            
            if ui.button("Send").clicked() && !self.message_input.trim().is_empty() {
                let message = self.message_input.trim().to_string();
                self.send_message(&message);
                self.message_input.clear();
            }
        });
    }
    
    fn show_peers_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("👥 Discovered Peers");
        
        #[cfg(feature = "bluetooth")]
        if self.bluetooth_initialized {
            ui.label("🔥 Using REAL Bluetooth Adapter (same as CLI/test)");
        } else {
            ui.label("🔧 Using Core Bluetooth Manager (fallback)");
        }
        
        ui.separator();
        
        if self.discovered_devices.is_empty() {
            ui.label("📭 No BitChat devices discovered yet");
            ui.label("💡 Make sure other BitChat devices are nearby and running");
        } else {
            ui.label(format!("🎉 Found {} BitChat device(s):", self.discovered_devices.len()));
            
            egui::ScrollArea::vertical().show(ui, |ui| {
                for (device_id, peer_id, rssi, age_secs) in &self.discovered_devices {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.label("📱");
                            ui.vertical(|ui| {
                                ui.strong(format!("Peer ID: {}", peer_id));
                                ui.label(format!("Device: {}", device_id));
                                ui.horizontal(|ui| {
                                    ui.label(format!("📶 {} dBm", rssi));
                                    ui.separator();
                                    ui.label(format!("⏰ {}s ago", age_secs));
                                });
                                ui.label("🍎 Platform: iOS/macOS (likely)");
                            });
                        });
                    });
                }
            });
        }
        
        ui.separator();
        
        // Connected peers from core
        let peers = self.core.list_peers();
        ui.label(format!("🔗 Connected Peers ({})", peers.len()));
        if peers.is_empty() {
            ui.label("No peers connected");
        } else {
            for peer in peers {
                ui.label(format!("• {}", peer));
            }
        }
    }
    
    fn show_channels_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("📺 Channels");
        
        if self.channels.is_empty() {
            ui.label("📭 No channels joined");
            ui.label("💡 Channels will appear when you receive messages from them");
        } else {
            ui.label(format!("📊 Known Channels ({})", self.channels.len()));
            
            for (i, channel) in self.channels.iter().enumerate() {
                ui.horizontal(|ui| {
                    ui.label(format!("{}.", i + 1));
                    ui.strong(channel);
                    if i == 0 {
                        ui.label("📍 (active)");
                    }
                });
            }
        }
        
        ui.separator();
        ui.label("💡 Channel joining happens automatically when receiving messages");
    }
    
    fn show_status_tab(&mut self, ui: &mut egui::Ui) {
        ui.heading("🔧 System Status");
        
        // Device info
        ui.group(|ui| {
            ui.label("🖥️ Device Information");
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("📱 Name:");
                ui.strong(&self.core.config.device_name);
            });
            ui.horizontal(|ui| {
                ui.label("🔑 Peer ID:");
                ui.monospace(hex::encode(self.core.get_peer_id()));
            });
            ui.horizontal(|ui| {
                ui.label("📁 Data Dir:");
                ui.label(self.core.config.data_dir.display().to_string());
            });
        });
        
        ui.separator();
        
        // Bluetooth status
        ui.group(|ui| {
            ui.label("🔵 Bluetooth Status");
            ui.separator();
            
            #[cfg(feature = "bluetooth")]
            {
                if let Some(adapter_ref) = REAL_BLUETOOTH.get() {
                    let (available, scanning, advertising) = self.runtime.block_on(async {
                        if let Some(ref adapter) = *adapter_ref.lock().await {
                            (
                                adapter.is_available().await,
                                adapter.is_scanning().await,
                                adapter.is_advertising().await,
                            )
                        } else {
                            (false, false, false)
                        }
                    });
                    
                    ui.horizontal(|ui| {
                        ui.label("Available:");
                        ui.label(if available { "✅ Yes" } else { "❌ No" });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Scanning:");
                        ui.label(if scanning { "✅ Active" } else { "❌ Inactive" });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Advertising:");
                        ui.label(if advertising { "✅ Active" } else { "❌ Inactive" });
                    });
                    ui.horizontal(|ui| {
                        ui.label("Implementation:");
                        ui.strong("REAL Windows Adapter");
                    });
                } else {
                    ui.label("⚠️ Real adapter not initialized");
                    ui.label("Using core Bluetooth manager (simulated)");
                }
            }
            
            #[cfg(not(feature = "bluetooth"))]
            {
                ui.label("❌ Bluetooth feature not enabled");
            }
        });
        
        ui.separator();
        
        // Discovery statistics
        ui.group(|ui| {
            ui.label("📊 Discovery Statistics");
            ui.separator();
            ui.horizontal(|ui| {
                ui.label("Discovered devices:");
                ui.strong(self.discovered_devices.len().to_string());
            });
            ui.horizontal(|ui| {
                ui.label("Known channels:");
                ui.strong(self.channels.len().to_string());
            });
            ui.horizontal(|ui| {
                ui.label("Connected peers:");
                ui.strong(self.core.list_peers().len().to_string());
            });
        });
        
        ui.separator();
        
        // Current status
        ui.group(|ui| {
            ui.label("📋 Current Status");
            ui.separator();
            ui.label(&self.status_text);
        });
    }
}