#[macro_use]
extern crate lazy_static;

/// This crate provides the network server for Lighthouse.
pub mod error;
#[allow(clippy::mutable_key_type)] // PeerId in hashmaps are no longer permitted by clippy
pub mod service;

mod beacon_processor;
#[allow(clippy::mutable_key_type)] // PeerId in hashmaps are no longer permitted by clippy
mod metrics;
mod nat;
mod persisted_dht;
mod router;
mod status;
mod subnet_service;
#[allow(clippy::mutable_key_type)] // PeerId in hashmaps are no longer permitted by clippy
mod sync;

pub use eth2_libp2p::NetworkConfig;
pub use service::{NetworkMessage, NetworkService};
