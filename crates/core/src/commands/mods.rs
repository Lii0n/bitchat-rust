//! Command processing module for SecureMesh

/// Process user commands
pub fn process_command(input: &str) -> Option<String> {
    if !input.starts_with('/') {
        return None;
    }
    
    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    let command = parts[0];
    
    match command {
        "/help" | "/h" => {
            Some("Available commands:\n\
                  /help, /h - Show this help\n\
                  /peers, /p - List connected peers\n\
                  /join, /j <channel> - Join a channel\n\
                  /leave <channel> - Leave a channel\n\
                  /channels - List joined channels\n\
                  /debug - Show debug information\n\
                  /clear - Clear chat messages".to_string())
        }
        _ => Some(format!("Unknown command: {}", command)),
    }
}