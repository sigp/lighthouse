/// This crate provides the network server for Lighthouse.
pub mod error;
pub mod message_handler;
pub mod message_processor;
pub mod persisted_dht;
pub mod service;
pub mod sync;

pub use eth2_libp2p::NetworkConfig;
pub use message_processor::MessageProcessor;
pub use service::NetworkMessage;
pub use service::Service;
