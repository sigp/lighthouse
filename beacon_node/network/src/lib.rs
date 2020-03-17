/// This crate provides the network server for Lighthouse.
pub mod error;
pub mod service;

mod attestation_service;
mod persisted_dht;
mod router;
mod sync;

pub use eth2_libp2p::NetworkConfig;
pub use service::{NetworkMessage, NetworkService};
