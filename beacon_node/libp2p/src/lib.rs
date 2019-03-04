/// This crate contains the main link for lighthouse to rust-libp2p. It therefore re-exports
/// all required libp2p functionality.
///
/// This crate builds and manages the libp2p services required by the beacon node.
extern crate libp2p;

mod libp2p_service;

pub use libp2p::{GossipsubConfig, PeerId};

pub use libp2p_service::LibP2PService;
