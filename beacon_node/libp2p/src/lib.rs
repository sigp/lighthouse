/// This crate contains the main link for lighthouse to rust-libp2p. It therefore re-exports
/// all required libp2p functionality.
///
/// This crate builds and manages the libp2p services required by the beacon node.
pub mod behaviour;
pub mod error;
mod network_config;
mod rpc;
mod service;

pub use libp2p::{
    gossipsub::{GossipsubConfig, GossipsubConfigBuilder},
    PeerId,
};
pub use network_config::NetworkConfig;
pub use service::Libp2pEvent;
pub use service::Service;
pub use types::multiaddr;
pub use types::Multiaddr;
