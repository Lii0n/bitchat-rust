use bitchat_core::{BitchatCore, Config};
use eframe::egui;
use std::path::PathBuf;

#[derive(Default)]
struct BitChatApp {
    message_input: String,
    messages: Vec<String>,
    connected_peers: Vec<String>,
    core: Option<BitchatCore>,
}

impl BitChatApp {
    fn new(_cc: &eframe::CreationContext<'_>) -> Self {
        Self::default()
    }
}

impl eframe::App for BitChatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔐 BitChat Desktop");
            
            ui.separator();
            
            // Connection status
            ui.horizontal(|ui| {
                ui.label("Status:");
                if self.core.is_some() {
                    ui.colored_label(egui::Color32::GREEN, "Connected");
                } else {
                    ui.colored_label(egui::Color32::RED, "Disconnected");
                }
            });
            
            ui.separator();
            
            // Peers list
            ui.heading("Connected Peers");
            egui::ScrollArea::vertical()
                .max_height(100.0)
                .show(ui, |ui| {
                    if self.connected_peers.is_empty() {
                        ui.label("No connected peers");
                    } else {
                        for peer in &self.connected_peers {
                            ui.label(format!("🔗 {}", peer));
                        }
                    }
                });
            
            ui.separator();
            
            // Messages area
            ui.heading("Messages");
            egui::ScrollArea::vertical()
                .max_height(300.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for message in &self.messages {
                        ui.label(message);
                    }
                });
            
            ui.separator();
            
            // Message input
            ui.horizontal(|ui| {
                let text_edit = egui::TextEdit::singleline(&mut self.message_input)
                    .hint_text("Type a message...")
                    .desired_width(ui.available_width() - 100.0);
                
                let response = ui.add(text_edit);
                
                let send_button = ui.button("Send");
                
                if (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) 
                    || send_button.clicked() {
                    if !self.message_input.trim().is_empty() {
                        let message = self.message_input.clone();
                        self.messages.push(format!("You: {}", message));
                        self.message_input.clear();
                        
                        // TODO: Send message through BitChat core
                    }
                }
            });
            
            ui.separator();
            
            // Control buttons
            ui.horizontal(|ui| {
                if ui.button("Start BitChat").clicked() {
                    // TODO: Initialize BitChat core
                    self.messages.push("BitChat starting...".to_string());
                }
                
                if ui.button("Stop BitChat").clicked() {
                    self.core = None;
                    self.messages.push("BitChat stopped".to_string());
                }
                
                if ui.button("Clear Messages").clicked() {
                    self.messages.clear();
                }
            });
        });
        
        // Request repaint for real-time updates
        ctx.request_repaint_after(std::time::Duration::from_millis(100));
    }
}

fn main() -> eframe::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_min_inner_size([400.0, 300.0]),
        ..Default::default()
    };
    
    eframe::run_native(
        "BitChat Desktop",
        options,
        Box::new(|cc| Box::new(BitChatApp::new(cc))),
    )
}