/// This crate provides the network server for Lighthouse.
pub mod error;
mod message_handler;
mod messages;
mod service;

pub use libp2p::NetworkConfig;
pub use messages::NodeMessage;
pub use service::Service;
