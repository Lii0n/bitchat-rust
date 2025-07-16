use bitchat_core::{BitchatCore, Config};
use eframe::egui;

fn main() -> anyhow::Result<()> {
    // Enable logging
    tracing_subscriber::fmt::init();

    // Create default config
    let data_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("bitchat");

    let config = Config {
        device_name: "BitChat Desktop".to_string(),
        data_dir,
        ..Default::default()
    };

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([400.0, 300.0]),
        ..Default::default()
    };

    eframe::run_native(
        "BitChat",
        options,
        Box::new(|cc| {
            // Create the app with the config
            let rt = tokio::runtime::Runtime::new().unwrap();
            let core = rt.block_on(async { BitchatCore::new(config).await }).unwrap();
            
            Box::new(BitChatApp::new(cc, core, rt))
        }),
    )?;

    Ok(())
}

struct BitChatApp {
    core: BitchatCore,
    runtime: tokio::runtime::Runtime,
    message_input: String,
    messages: Vec<String>,
}

impl BitChatApp {
    fn new(_cc: &eframe::CreationContext<'_>, core: BitchatCore, runtime: tokio::runtime::Runtime) -> Self {
        Self {
            core,
            runtime,
            message_input: String::new(),
            messages: Vec::new(),
        }
    }
}

impl eframe::App for BitChatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("BitChat Desktop");
            
            ui.separator();
            
            // Show device info
            ui.horizontal(|ui| {
                ui.label("Device:");
                ui.strong(&self.core.config.device_name);
            });
            
            ui.horizontal(|ui| {
                ui.label("Peer ID:");
                ui.monospace(hex::encode(self.core.get_peer_id()));
            });
            
            ui.separator();
            
            // Messages area
            ui.heading("Messages");
            egui::ScrollArea::vertical()
                .max_height(200.0)
                .show(ui, |ui| {
                    for message in &self.messages {
                        ui.label(message);
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
                        
                        // Send message asynchronously
                        let core_ref = &self.core;
                        self.runtime.block_on(async {
                            if let Err(e) = core_ref.send_channel_message("#general", &message).await {
                                eprintln!("Failed to send message: {}", e);
                            }
                        });
                        
                        self.messages.push(format!("You: {}", message));
                        self.message_input.clear();
                    }
                    response.request_focus();
                }
                
                if ui.button("Send").clicked() && !self.message_input.trim().is_empty() {
                    let message = self.message_input.trim().to_string();
                    
                    // Send message asynchronously
                    let core_ref = &self.core;
                    self.runtime.block_on(async {
                        if let Err(e) = core_ref.send_channel_message("#general", &message).await {
                            eprintln!("Failed to send message: {}", e);
                        }
                    });
                    
                    self.messages.push(format!("You: {}", message));
                    self.message_input.clear();
                }
            });
            
            ui.separator();
            
            // Peers section
            ui.heading("Connected Peers");
            let peers = self.core.list_peers();
            if peers.is_empty() {
                ui.label("No connected peers");
            } else {
                for peer in peers {
                    ui.label(format!("• {}", peer));
                }
            }
        });
    }
}