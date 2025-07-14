//! SecureMesh Desktop Application with iOS/Android Compatibility
//!
//! This is the desktop GUI application for SecureMesh, designed to be compatible
//! with existing iOS and Android implementations.

use anyhow::Result;
use eframe::egui;
use bitchat_core::SecureMeshCore;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, error};

/// Main application state
struct SecureMeshApp {
    core: Arc<SecureMeshCore>,
    
    // UI state
    input_text: String,
    chat_messages: Vec<ChatMessage>,
    current_channel: Option<String>,
    peer_list: Vec<String>,
    debug_info: String,
    show_debug: bool,
    
    // Connection status
    connected_peers: usize,
    my_peer_id: String,
}

#[derive(Clone)]
struct ChatMessage {
    sender: String,
    content: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    is_system: bool,
}

impl SecureMeshApp {
    async fn new() -> Result<Self> {
        info!("Initializing SecureMesh desktop application");
        
        let core = SecureMeshCore::new_with_compatibility().await?;
        let my_peer_id = core.get_peer_id().to_string();
        
        // Start core services
        core.start().await?;
        
        Ok(Self {
            core: Arc::new(core),
            input_text: String::new(),
            chat_messages: Vec::new(),
            current_channel: None,
            peer_list: Vec::new(),
            debug_info: String::new(),
            show_debug: false,
            connected_peers: 0,
            my_peer_id,
        })
    }
    
    fn add_system_message(&mut self, content: String) {
        self.chat_messages.push(ChatMessage {
            sender: "System".to_string(),
            content,
            timestamp: chrono::Utc::now(),
            is_system: true,
        });
    }
    
    fn add_chat_message(&mut self, sender: String, content: String) {
        self.chat_messages.push(ChatMessage {
            sender,
            content,
            timestamp: chrono::Utc::now(),
            is_system: false,
        });
    }
    
    async fn process_command(&mut self, input: &str) {
        if input.starts_with('/') {
            let parts: Vec<&str> = input.splitn(2, ' ').collect();
            let command = parts[0];
            let args = parts.get(1).unwrap_or(&"");
            
            match command {
                "/help" | "/h" => {
                    self.add_system_message(
                        "Available commands:\n\
                        /help, /h - Show this help\n\
                        /peers, /p - List connected peers\n\
                        /join, /j <channel> - Join a channel\n\
                        /leave <channel> - Leave a channel\n\
                        /channels - List joined channels\n\
                        /debug - Toggle debug information\n\
                        /clear - Clear chat messages\n\
                        Type any message (without /) to broadcast it.".to_string()
                    );
                }
                "/peers" | "/p" => {
                    let peers = self.core.get_connected_peers().await;
                    if peers.is_empty() {
                        self.add_system_message("No connected peers".to_string());
                    } else {
                        let peer_list = peers.join(", ");
                        self.add_system_message(format!("Connected peers: {}", peer_list));
                    }
                }
                "/join" | "/j" => {
                    if args.is_empty() {
                        self.add_system_message("Usage: /join <channel>".to_string());
                    } else {
                        match self.core.join_channel(args).await {
                            Ok(msg) => {
                                self.current_channel = Some(args.to_string());
                                self.add_system_message(msg);
                            }
                            Err(e) => self.add_system_message(format!("Failed to join channel: {}", e)),
                        }
                    }
                }
                "/leave" => {
                    if args.is_empty() {
                        self.add_system_message("Usage: /leave <channel>".to_string());
                    } else {
                        match self.core.leave_channel(args).await {
                            Ok(msg) => {
                                if self.current_channel.as_deref() == Some(args) {
                                    self.current_channel = None;
                                }
                                self.add_system_message(msg);
                            }
                            Err(e) => self.add_system_message(format!("Failed to leave channel: {}", e)),
                        }
                    }
                }
                "/channels" => {
                    match self.core.list_channels().await {
                        Ok(channels) => self.add_system_message(channels),
                        Err(e) => self.add_system_message(format!("Failed to list channels: {}", e)),
                    }
                }
                "/debug" => {
                    self.show_debug = !self.show_debug;
                    if self.show_debug {
                        self.debug_info = self.core.get_debug_info().await;
                    }
                    self.add_system_message(format!("Debug view: {}", if self.show_debug { "enabled" } else { "disabled" }));
                }
                "/clear" => {
                    self.chat_messages.clear();
                    self.add_system_message("Chat cleared".to_string());
                }
                _ => {
                    self.add_system_message(format!("Unknown command: {}", command));
                }
            }
        } else {
            // Regular message - broadcast to all peers
            match self.core.broadcast_message(input).await {
                Ok(_) => {
                    self.add_chat_message(self.my_peer_id.clone(), input.to_string());
                }
                Err(e) => {
                    self.add_system_message(format!("Failed to send message: {}", e));
                }
            }
        }
    }
    
    async fn update_status(&mut self) {
        // Update peer count and other status information
        self.connected_peers = self.core.get_connected_peers().await.len();
        
        if self.show_debug {
            self.debug_info = self.core.get_debug_info().await;
        }
    }
}

impl eframe::App for SecureMeshApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Update status in background
        let app_clone = self.core.clone();
        let ctx_clone = ctx.clone();
        tokio::spawn(async move {
            // This is a simplified status update - in a real app you'd want
            // to use proper async state management
            ctx_clone.request_repaint();
        });
        
        egui::CentralPanel::default().show(ctx, |ui| {
            // Title bar
            ui.horizontal(|ui| {
                ui.heading("🔐 SecureMesh");
                ui.separator();
                ui.label(format!("Peer ID: {}", &self.my_peer_id[..8]));
                ui.separator();
                ui.label(format!("Connected: {}", self.connected_peers));
                if let Some(ref channel) = self.current_channel {
                    ui.separator();
                    ui.label(format!("Channel: #{}", channel));
                }
            });
            
            ui.separator();
            
            // Main content area
            ui.horizontal(|ui| {
                // Chat area (left side)
                ui.vertical(|ui| {
                    ui.heading("Chat");
                    
                    // Messages area
                    egui::ScrollArea::vertical()
                        .auto_shrink([false; 2])
                        .max_height(400.0)
                        .show(ui, |ui| {
                            for message in &self.chat_messages {
                                ui.horizontal(|ui| {
                                    let time_str = message.timestamp.format("%H:%M:%S").to_string();
                                    
                                    if message.is_system {
                                        ui.colored_label(egui::Color32::YELLOW, format!("[{}] System:", time_str));
                                        ui.label(&message.content);
                                    } else {
                                        ui.colored_label(egui::Color32::CYAN, format!("[{}] {}:", time_str, &message.sender[..8]));
                                        ui.label(&message.content);
                                    }
                                });
                            }
                        });
                    
                    // Input area
                    ui.horizontal(|ui| {
                        let response = ui.text_edit_singleline(&mut self.input_text);
                        
                        if ui.button("Send").clicked() || (response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                            if !self.input_text.trim().is_empty() {
                                let input = self.input_text.clone();
                                self.input_text.clear();
                                
                                // Process command directly for now
                                // TODO: Implement proper async command processing
                                if input.starts_with('/') {
                                    self.add_system_message(format!("Command received: {}", input));
                                } else {
                                    self.add_chat_message(self.my_peer_id.clone(), input);
                                }
                            }
                        }
                    });
                });
                
                ui.separator();
                
                // Debug/status area (right side)
                if self.show_debug {
                    ui.vertical(|ui| {
                        ui.heading("Debug Information");
                        
                        egui::ScrollArea::vertical()
                            .auto_shrink([false; 2])
                            .max_width(300.0)
                            .show(ui, |ui| {
                                ui.monospace(&self.debug_info);
                            });
                        
                        if ui.button("Refresh Debug").clicked() {
                            let core_clone = self.core.clone();
                            tokio::spawn(async move {
                                // Update debug info
                            });
                        }
                    });
                }
            });
        });
        
        // Request repaint for real-time updates
        ctx.request_repaint_after(std::time::Duration::from_secs(1));
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    info!("Starting SecureMesh Desktop Application");
    
    // Create the application
    let app = SecureMeshApp::new().await?;
    
    // Configure eframe
    let options = eframe::NativeOptions {
        initial_window_size: Some(egui::vec2(800.0, 600.0)),
        ..Default::default()
    };
    
    // Run the application
    eframe::run_native(
        "SecureMesh",
        options,
        Box::new(|_cc| Box::new(app)),
    ).map_err(|e| anyhow::anyhow!("Failed to run eframe application: {}", e))?;
    
    Ok(())
}