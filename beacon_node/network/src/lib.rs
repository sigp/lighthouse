/// This crate provides the network server for Lighthouse.
pub mod error;
#[allow(clippy::unit_arg)]
pub mod message_handler;
pub mod service;
pub mod sync;

pub use eth2_libp2p::NetworkConfig;
pub use service::NetworkMessage;
pub use service::Service;
