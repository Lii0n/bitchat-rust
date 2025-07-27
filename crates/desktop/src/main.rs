use eframe::egui;
use bitchat_core::{Config, BitchatCore};

fn main() -> Result<(), eframe::Error> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Create tokio runtime for async operations
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    
    // Create BitChat core with default config
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("bitchat");
    
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
        auto_accept_channels: false,
        max_peers: 8,
        scan_interval_ms: 1000,
    };
    
    let core = rt.block_on(async {
        BitchatCore::new(config).await.expect("Failed to create BitChat core")
    });
    
    // Set up eframe options
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_title("BitChat Desktop - Moon Protocol"),
        ..Default::default()
    };
    
    // Run the app
    eframe::run_native(
        "BitChat Desktop",
        options,
        Box::new(|cc| {
            // Wrap in Ok() since eframe now expects Result<Box<dyn App>, Error>
            Ok(Box::new(BitChatApp::new(cc, core, rt)) as Box<dyn eframe::App>)
        }),
    )
}

struct BitChatApp {
    _core: BitchatCore,      // Prefixed with _ to indicate intentionally unused for now
    _runtime: tokio::runtime::Runtime,  // Prefixed with _ to indicate intentionally unused for now
    message_input: String,
    messages: Vec<String>,
    current_tab: Tab,
    bluetooth_status: String,
    peer_count: usize,
    encryption_stats: Option<String>,
}

#[derive(PartialEq)]
enum Tab {
    Chat,
    Peers,
    Encryption,
    Settings,
}

impl BitChatApp {
    fn new(_cc: &eframe::CreationContext<'_>, core: BitchatCore, runtime: tokio::runtime::Runtime) -> Self {
        let mut app = Self {
            _core: core,
            _runtime: runtime,
            message_input: String::new(),
            messages: Vec::new(),
            current_tab: Tab::Chat,
            bluetooth_status: "Initializing...".to_string(),
            peer_count: 0,
            encryption_stats: None,
        };
        
        // Add welcome message
        app.messages.push("🌑 Welcome to BitChat Moon Protocol!".to_string());
        app.messages.push("✨ Features: Noise Protocol encryption, Bluetooth LE mesh".to_string());
        app.messages.push("📡 Scanning for nearby BitChat devices...".to_string());
        
        app
    }
    
    fn update_bluetooth_status(&mut self) {
        // Update status in a non-blocking way
        self.bluetooth_status = "Moon Protocol Active".to_string();
        self.peer_count = 0; // Placeholder - in real implementation, get from core
    }
    
    fn update_encryption_stats(&mut self) {
        // Placeholder for encryption statistics
        self.encryption_stats = Some(format!(
            "Protocol: Moon v1.1 (Noise XX)\nActive Sessions: 0\nMessages Encrypted: 0"
        ));
    }
}

impl eframe::App for BitChatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Update status periodically
        self.update_bluetooth_status();
        self.update_encryption_stats();
        
        // Top menu bar
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.current_tab, Tab::Chat, "💬 Chat");
                ui.selectable_value(&mut self.current_tab, Tab::Peers, "👥 Peers");
                ui.selectable_value(&mut self.current_tab, Tab::Encryption, "🔐 Encryption");
                ui.selectable_value(&mut self.current_tab, Tab::Settings, "⚙️ Settings");
                
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(format!("Peers: {}", self.peer_count));
                    ui.separator();
                    ui.label(&self.bluetooth_status);
                });
            });
        });
        
        // Main content area
        egui::CentralPanel::default().show(ctx, |ui| {
            match self.current_tab {
                Tab::Chat => self.show_chat_tab(ui),
                Tab::Peers => self.show_peers_tab(ui),
                Tab::Encryption => self.show_encryption_tab(ui),
                Tab::Settings => self.show_settings_tab(ui),
            }
        });
        
        // Request repaint for real-time updates
        ctx.request_repaint_after(std::time::Duration::from_millis(1000));
    }
}

impl BitChatApp {
    fn show_chat_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading("💬 BitChat Moon Protocol");
            
            ui.separator();
            
            // Message history
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .show(ui, |ui| {
                    for message in &self.messages {
                        ui.label(message);
                    }
                });
            
            ui.separator();
            
            // Message input
            ui.horizontal(|ui| {
                let response = ui.text_edit_singleline(&mut self.message_input);
                
                if ui.button("Send").clicked() || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                    if !self.message_input.trim().is_empty() {
                        let message = format!("You: {}", self.message_input.trim());
                        self.messages.push(message);
                        self.message_input.clear();
                        
                        // In a real implementation, send the message through core
                        // self.runtime.spawn(async { ... });
                    }
                }
            });
            
            if self.messages.is_empty() {
                ui.centered_and_justified(|ui| {
                    ui.label("No messages yet. Start a conversation!");
                });
            }
        });
    }
    
    fn show_peers_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading("👥 Discovered Peers");
            
            ui.separator();
            
            if self.peer_count == 0 {
                ui.centered_and_justified(|ui| {
                    ui.label("🔍 Scanning for nearby BitChat devices...\n\nMake sure Bluetooth is enabled and other\nBitChat clients are nearby.");
                });
            } else {
                // In real implementation, show actual peer list
                ui.label("Peer list would be displayed here");
            }
            
            ui.separator();
            
            ui.horizontal(|ui| {
                if ui.button("🔄 Refresh").clicked() {
                    // Trigger peer refresh
                    self.messages.push("🔄 Refreshing peer list...".to_string());
                }
                
                if ui.button("📡 Start Advertising").clicked() {
                    // Start advertising our presence
                    self.messages.push("📡 Started advertising as BitChat Moon device".to_string());
                }
            });
        });
    }
    
    fn show_encryption_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading("🔐 Encryption Status");
            
            ui.separator();
            
            // Protocol information
            ui.group(|ui| {
                ui.label("🌑 Moon Protocol v1.1");
                ui.label("🛡️ Noise XX Pattern");
                ui.label("🔑 ChaCha20-Poly1305 AEAD");
                ui.label("🔐 X25519 Key Agreement");
                ui.label("📝 BLAKE2s Hashing");
            });
            
            ui.separator();
            
            // Encryption statistics
            if let Some(ref stats) = self.encryption_stats {
                ui.label("📊 Statistics:");
                ui.monospace(stats);
            }
            
            ui.separator();
            
            // Security features
            ui.label("🛡️ Security Features:");
            ui.group(|ui| {
                ui.label("✅ Forward Secrecy");
                ui.label("✅ Identity Hiding");
                ui.label("✅ Mutual Authentication");
                ui.label("✅ Replay Protection");
                ui.label("✅ Session Renewal");
            });
        });
    }
    
    fn show_settings_tab(&mut self, ui: &mut egui::Ui) {
        ui.vertical(|ui| {
            ui.heading("⚙️ Settings");
            
            ui.separator();
            
            ui.group(|ui| {
                ui.label("Protocol Settings:");
                ui.label("• Protocol Version: Moon v1.1");
                ui.label("• Encryption: Noise Protocol");
                ui.label("• Bluetooth: LE 4.0+");
            });
            
            ui.separator();
            
            ui.group(|ui| {
                ui.label("Network Settings:");
                ui.label("• Max TTL: 7 hops");
                ui.label("• Session Timeout: 1 hour");
                ui.label("• Max Connections: 8");
            });
            
            ui.separator();
            
            if ui.button("🔄 Reset to Defaults").clicked() {
                self.messages.push("⚙️ Settings reset to defaults".to_string());
            }
            
            if ui.button("🧹 Clear Messages").clicked() {
                self.messages.clear();
                self.messages.push("🧹 Message history cleared".to_string());
            }
        });
    }
}