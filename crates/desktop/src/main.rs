use anyhow::Result;
use eframe::egui;
use std::sync::Arc;
use bitchat_core::{init, Config, BitchatCore, BluetoothEvent};
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Create configuration
    let config = Config::default();
    
    // Initialize BitChat core
    let core = Arc::new(init(config).await?);
    
    // Start BitChat services
    if let Err(e) = core.start().await {
        eprintln!("⚠️  Could not start all services: {}", e);
    }

    // Get Bluetooth event receiver
    let event_receiver = core.take_bluetooth_events().await;

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([800.0, 600.0])
            .with_title("BitChat Desktop"),
        ..Default::default()
    };

    eframe::run_native(
        "BitChat Desktop",
        options,
        Box::new(move |_cc| {
            Box::new(BitChatApp::new(core, event_receiver))
        }),
    ).map_err(|e| anyhow::anyhow!("Failed to run app: {}", e))
}

struct BitChatApp {
    core: Arc<BitchatCore>,
    
    // UI State
    message_input: String,
    channel_input: String,
    current_channel: Option<String>,
    
    // Message History
    messages: Vec<ChatMessage>,
    
    // Connection State
    connected_peers: HashMap<String, PeerInfo>,
    scanning: bool,
    
    // Background Event Handling
    event_receiver: Option<tokio::sync::mpsc::UnboundedReceiver<BluetoothEvent>>,
    runtime: Arc<tokio::runtime::Runtime>,
    
    // UI State
    show_channels: bool,
    show_peers: bool,
}

#[derive(Debug, Clone)]
struct ChatMessage {
    content: String,
    timestamp: String,
    message_type: MessageType,
    channel: Option<String>,
}

#[derive(Debug, Clone)]
enum MessageType {
    Sent,
    Received,
    System,
    ChannelJoin,
    ChannelLeave,
}

#[derive(Debug, Clone)]
struct PeerInfo {
    id: String,
    name: Option<String>,
    rssi: i16,
    connected: bool,
}

impl BitChatApp {
    fn new(
        core: Arc<BitchatCore>, 
        event_receiver: Option<tokio::sync::mpsc::UnboundedReceiver<BluetoothEvent>>
    ) -> Self {
        let runtime = Arc::new(
            tokio::runtime::Runtime::new()
                .expect("Failed to create tokio runtime")
        );
        
        Self {
            core,
            message_input: String::new(),
            channel_input: String::new(),
            current_channel: None,
            messages: Vec::new(),
            connected_peers: HashMap::new(),
            scanning: false,
            event_receiver,
            runtime,
            show_channels: false,
            show_peers: true,
        }
    }
    
    fn add_message(&mut self, content: String, msg_type: MessageType, channel: Option<String>) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let timestamp_str = format!("{:02}:{:02}:{:02}", 
            (timestamp / 3600) % 24, 
            (timestamp / 60) % 60, 
            timestamp % 60
        );
        
        self.messages.push(ChatMessage {
            content,
            timestamp: timestamp_str,
            message_type: msg_type,
            channel,
        });
        
        // Keep only last 100 messages
        if self.messages.len() > 100 {
            self.messages.remove(0);
        }
    }
    
    fn send_message(&mut self) {
        if self.message_input.is_empty() {
            return;
        }
        
        let message = self.message_input.clone();
        self.message_input.clear();
        
        let core = self.core.clone();
        let current_channel = self.current_channel.clone();
        
        // Add to UI immediately
        if let Some(channel) = &current_channel {
            self.add_message(
                format!("[{}] You: {}", channel, message),
                MessageType::Sent,
                Some(channel.clone())
            );
        } else {
            self.add_message(
                format!("You: {}", message),
                MessageType::Sent,
                None
            );
        }
        
        // Send via BitChat core
        self.runtime.spawn(async move {
            let result = if let Some(channel) = current_channel {
                core.send_channel_message(&channel, &message).await
            } else {
                core.send_protocol_message(&message, None).await
            };
            
            if let Err(e) = result {
                eprintln!("Failed to send message: {}", e);
            }
        });
    }
    
    fn join_channel(&mut self) {
        if self.channel_input.is_empty() {
            return;
        }
        
        let channel = self.channel_input.clone();
        self.channel_input.clear();
        
        let core = self.core.clone();
        let mut app_channel = channel.clone();
        
        // Ensure channel starts with #
        if !app_channel.starts_with('#') {
            app_channel = format!("#{}", app_channel);
        }
        
        self.current_channel = Some(app_channel.clone());
        
        self.add_message(
            format!("Joining channel {}", app_channel),
            MessageType::System,
            Some(app_channel.clone())
        );
        
        self.runtime.spawn(async move {
            match core.join_channel(&channel).await {
                Ok(msg) => println!("✅ {}", msg),
                Err(e) => eprintln!("❌ Failed to join channel: {}", e),
            }
        });
    }
    
    fn leave_current_channel(&mut self) {
        if let Some(channel) = &self.current_channel {
            let channel = channel.clone();
            let core = self.core.clone();
            
            self.add_message(
                format!("Leaving channel {}", channel),
                MessageType::System,
                Some(channel.clone())
            );
            
            self.current_channel = None;
            
            self.runtime.spawn(async move {
                match core.leave_channel(&channel).await {
                    Ok(msg) => println!("✅ {}", msg),
                    Err(e) => eprintln!("❌ Failed to leave channel: {}", e),
                }
            });
        }
    }
    
    fn handle_bluetooth_events(&mut self) {
        if let Some(receiver) = &mut self.event_receiver {
            // Process up to 10 events per frame to avoid blocking UI
            let mut events_to_process = Vec::new();
            
            for _ in 0..10 {
                match receiver.try_recv() {
                    Ok(event) => events_to_process.push(event),
                    Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                    Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                        self.event_receiver = None;
                        break;
                    }
                }
            }
            
            // Process collected events
            for event in events_to_process {
                self.process_bluetooth_event(event);
            }
        }
    }
    
    fn process_bluetooth_event(&mut self, event: BluetoothEvent) {
        match event {
            BluetoothEvent::PeerDiscovered { peer_id, name, rssi } => {
                let short_id = if peer_id.len() >= 8 { &peer_id[..8] } else { &peer_id };
                
                self.connected_peers.insert(peer_id.clone(), PeerInfo {
                    id: peer_id.clone(),
                    name: name.clone(),
                    rssi,
                    connected: false,
                });
                
                self.add_message(
                    format!("🔍 Discovered peer: {} RSSI: {}dBm", 
                           name.as_deref().unwrap_or(short_id), rssi),
                    MessageType::System,
                    None
                );
            }
            BluetoothEvent::PeerConnected { peer_id } => {
                let short_id = if peer_id.len() >= 8 { &peer_id[..8] } else { &peer_id };
                
                if let Some(peer) = self.connected_peers.get_mut(&peer_id) {
                    peer.connected = true;
                }
                
                self.add_message(
                    format!("🤝 Connected to peer: {}", short_id),
                    MessageType::System,
                    None
                );
            }
            BluetoothEvent::PeerDisconnected { peer_id } => {
                let short_id = if peer_id.len() >= 8 { &peer_id[..8] } else { &peer_id };
                
                if let Some(peer) = self.connected_peers.get_mut(&peer_id) {
                    peer.connected = false;
                }
                
                self.add_message(
                    format!("❌ Disconnected from peer: {}", short_id),
                    MessageType::System,
                    None
                );
            }
            BluetoothEvent::MessageReceived { peer_id, data } => {
                let core = self.core.clone();
                let short_id = if peer_id.len() >= 8 { 
                    peer_id[..8].to_string() 
                } else { 
                    peer_id.clone() 
                };
                
                // Process the packet and try to decode it
                let data_clone = data.clone();
                let short_id_for_async = short_id.clone(); // Clone for async task
                
                self.runtime.spawn(async move {
                    if let Err(e) = core.process_packet(&data).await {
                        eprintln!("Failed to process packet from {}: {}", short_id_for_async, e);
                    }
                });
                
                // Try to decode and display the message immediately
                if let Ok(packet) = bitchat_core::protocol::BinaryProtocolManager::decode(&data_clone) {
                    if let Ok(content) = String::from_utf8(packet.payload.clone()) {
                        match packet.message_type {
                            bitchat_core::protocol::MessageType::Message => {
                                // Check if it's a channel message
                                if let Some((channel, message_content)) = content.split_once('|') {
                                    if channel.starts_with('#') {
                                        self.add_message(
                                            format!("[{}] {}: {}", channel, short_id, message_content),
                                            MessageType::Received,
                                            Some(channel.to_string())
                                        );
                                        return;
                                    }
                                }
                                // Regular message
                                self.add_message(
                                    format!("{}: {}", short_id, content),
                                    MessageType::Received,
                                    None
                                );
                            }
                            bitchat_core::protocol::MessageType::Announce => {
                                self.add_message(
                                    format!("📢 {} announced as '{}'", short_id, content),
                                    MessageType::System,
                                    None
                                );
                            }
                            bitchat_core::protocol::MessageType::ChannelJoin => {
                                self.add_message(
                                    format!("📢 {} joined channel: {}", short_id, content),
                                    MessageType::ChannelJoin,
                                    Some(content)
                                );
                            }
                            bitchat_core::protocol::MessageType::ChannelLeave => {
                                self.add_message(
                                    format!("📤 {} left channel: {}", short_id, content),
                                    MessageType::ChannelLeave,
                                    Some(content)
                                );
                            }
                            bitchat_core::protocol::MessageType::Leave => {
                                self.add_message(
                                    format!("👋 {} left the network", short_id),
                                    MessageType::System,
                                    None
                                );
                            }
                            _ => {
                                // Other message types
                                self.add_message(
                                    format!("📦 Received {:?} from {}", packet.message_type, short_id),
                                    MessageType::System,
                                    None
                                );
                            }
                        }
                    }
                }
            }
            BluetoothEvent::ScanningStateChanged { scanning } => {
                self.scanning = scanning;
                self.add_message(
                    if scanning {
                        "🔍 Started scanning for peers".to_string()
                    } else {
                        "⏹️ Stopped scanning".to_string()
                    },
                    MessageType::System,
                    None
                );
            }
            BluetoothEvent::AdvertisingStateChanged { advertising: _ } => {
                // Handle advertising state if needed
            }
            BluetoothEvent::PeerError { peer_id, error } => {
                let short_id = if peer_id.len() >= 8 { &peer_id[..8] } else { &peer_id };
                self.add_message(
                    format!("❌ Error with peer {}: {}", short_id, error),
                    MessageType::System,
                    None
                );
            }
        }
    }
}

impl eframe::App for BitChatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Handle background events
        self.handle_bluetooth_events();
        
        // Request repaint to keep processing events
        ctx.request_repaint();
        
        // Top panel with connection info
        egui::TopBottomPanel::top("top_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("BitChat Desktop");
                ui.separator();
                
                let peer_count = self.connected_peers.values().filter(|p| p.connected).count();
                let status_color = if peer_count > 0 {
                    egui::Color32::GREEN
                } else {
                    egui::Color32::RED
                };
                
                ui.colored_label(status_color, format!("👥 {} peers", peer_count));
                
                if self.scanning {
                    ui.colored_label(egui::Color32::BLUE, "🔍 Scanning");
                }
                
                if let Some(channel) = &self.current_channel {
                    ui.separator();
                    ui.colored_label(egui::Color32::YELLOW, format!("📢 {}", channel));
                }
            });
        });
        
        // Side panel for peers and channels
        egui::SidePanel::right("side_panel").default_width(200.0).show(ctx, |ui| {
            ui.vertical(|ui| {
                // Peers section
                ui.collapsing("Connected Peers", |ui| {
                    let connected_peers: Vec<_> = self.connected_peers.values()
                        .filter(|p| p.connected)
                        .collect();
                    
                    if connected_peers.is_empty() {
                        ui.label("No connected peers");
                    } else {
                        for peer in connected_peers {
                            let short_id = if peer.id.len() >= 8 { &peer.id[..8] } else { &peer.id };
                            let display_name = peer.name.as_deref().unwrap_or(short_id);
                            ui.label(format!("🔗 {} ({}dBm)", display_name, peer.rssi));
                        }
                    }
                });
                
                ui.separator();
                
                // Channel controls
                ui.heading("Channels");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.channel_input);
                    if ui.button("Join").clicked() && !self.channel_input.is_empty() {
                        self.join_channel();
                    }
                });
                
                if self.current_channel.is_some() {
                    if ui.button("Leave Channel").clicked() {
                        self.leave_current_channel();
                    }
                }
            });
        });
        
        // Bottom panel for message input
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            ui.horizontal(|ui| {
                let text_edit = ui.text_edit_singleline(&mut self.message_input);
                
                if ui.button("Send").clicked() || 
                   (text_edit.has_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))) {
                    self.send_message();
                }
                
                if ui.button("Clear").clicked() {
                    self.messages.clear();
                }
            });
        });
        
        // Central panel for messages
        egui::CentralPanel::default().show(ctx, |ui| {
            egui::ScrollArea::vertical()
                .auto_shrink([false; 2])
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    for message in &self.messages {
                        let color = match message.message_type {
                            MessageType::Sent => egui::Color32::LIGHT_BLUE,
                            MessageType::Received => egui::Color32::WHITE,
                            MessageType::System => egui::Color32::LIGHT_GRAY,
                            MessageType::ChannelJoin => egui::Color32::LIGHT_GREEN,
                            MessageType::ChannelLeave => egui::Color32::LIGHT_RED,
                        };
                        
                        ui.horizontal(|ui| {
                            ui.label(format!("[{}]", message.timestamp));
                            ui.colored_label(color, &message.content);
                        });
                    }
                });
        });
    }
}