/// This crate contains the main link for lighthouse to rust-libp2p. It therefore re-exports
/// all required libp2p functionality.
///
/// This crate builds and manages the libp2p services required by the beacon node.
pub mod behaviour;
mod config;
pub mod error;
pub mod rpc;
mod service;

pub use behaviour::PubsubMessage;
pub use config::Config as NetworkConfig;
pub use libp2p::{
    gossipsub::{GossipsubConfig, GossipsubConfigBuilder},
    PeerId,
};
pub use rpc::RPCEvent;
pub use service::Libp2pEvent;
pub use service::Service;
pub use types::multiaddr;
pub use types::Multiaddr;
