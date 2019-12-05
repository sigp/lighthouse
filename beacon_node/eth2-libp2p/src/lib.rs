/// This crate contains the main link for lighthouse to rust-libp2p. It therefore re-exports
/// all required libp2p functionality.
///
/// This crate builds and manages the libp2p services required by the beacon node.
#[macro_use]
extern crate lazy_static;

extern crate snap;

pub mod behaviour;
mod config;
mod discovery;
mod globals;
mod metrics;
mod pubsub;
pub mod rpc;
mod service;
pub mod types;

pub use crate::types::{error, topics, GossipTopic, SubnetId};
pub use config::Config as NetworkConfig;
pub use globals::NetworkGlobals;
pub use libp2p::enr::Enr;
pub use libp2p::gossipsub::{MessageId, Topic, TopicHash};
pub use libp2p::{multiaddr, Multiaddr};
pub use libp2p::{PeerId, Swarm};
pub use pubsub::PubsubMessage;
pub use rpc::RPCEvent;
pub use service::{Libp2pEvent, Service};
