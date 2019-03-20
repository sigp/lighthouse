/// This crate provides the network server for Lighthouse.
pub mod beacon_chain;
pub mod error;
mod message_handler;
mod service;
pub mod sync;

pub use eth2_libp2p::NetworkConfig;
pub use service::Service;
