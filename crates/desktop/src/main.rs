use anyhow::Result;
use eframe::egui;

fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([800.0, 600.0]),
        ..Default::default()
    };

    eframe::run_native(
        "BitChat Desktop",
        options,
        Box::new(|_cc| Box::new(BitChatApp::default())),
    ).map_err(|e| anyhow::anyhow!("Failed to run app: {}", e))
}

#[derive(Default)]
struct BitChatApp {
    message_input: String,
    messages: Vec<String>,
}

impl eframe::App for BitChatApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("BitChat Desktop");
            
            // Chat area
            egui::ScrollArea::vertical()
                .max_height(400.0)
                .show(ui, |ui| {
                    for message in &self.messages {
                        ui.label(message);
                    }
                });

            ui.separator();

            // Input area
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.message_input);
                if ui.button("Send").clicked() || ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                    if !self.message_input.is_empty() {
                        self.messages.push(format!("You: {}", self.message_input));
                        self.message_input.clear();
                    }
                }
            });

            if ui.button("Clear Messages").clicked() {
                self.messages.clear();
            }
        });
    }
}
