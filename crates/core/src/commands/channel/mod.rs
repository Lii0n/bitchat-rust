//! Channel management module for BitChat
//! 
//! This module provides channel functionality including joining, leaving,
//! and managing channel state and metadata.

pub mod channel;

// Re-export the main types for easy access
pub use channel::{ChannelManager, ChannelInfo};