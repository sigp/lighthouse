/// This crate contains the main link for lighthouse to rust-libp2p. It therefore re-exports
/// all required libp2p functionality.
///
/// This crate builds and manages the libp2p services required by the beacon node.
mod behaviour;
mod network_config;
mod service;

pub use libp2p::multiaddr;
pub use libp2p::Multiaddr;
pub use libp2p::{
    gossipsub::{GossipsubConfig, GossipsubConfigBuilder},
    PeerId,
};
pub use network_config::NetworkConfig;
pub use service::Service;
