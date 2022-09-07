/// This crate contains the main link for lighthouse to rust-libp2p. It therefore re-exports
/// all required libp2p functionality.
///
/// This crate builds and manages the libp2p services required by the beacon node.
#[macro_use]
extern crate lazy_static;

mod config;
pub mod service;

#[allow(clippy::mutable_key_type)] // PeerId in hashmaps are no longer permitted by clippy
pub mod discovery;
pub mod metrics;
pub mod peer_manager;
pub mod rpc;
pub mod types;

pub use config::gossip_max_size;

use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;

/// Wrapper over a libp2p `PeerId` which implements `Serialize` and `Deserialize`
#[derive(Clone, Debug)]
pub struct PeerIdSerialized(libp2p::PeerId);

impl From<PeerIdSerialized> for PeerId {
    fn from(peer_id: PeerIdSerialized) -> Self {
        peer_id.0
    }
}

impl FromStr for PeerIdSerialized {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(
            PeerId::from_str(s).map_err(|e| format!("Invalid peer id: {}", e))?,
        ))
    }
}

impl Serialize for PeerIdSerialized {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0.to_string())
    }
}

impl<'de> Deserialize<'de> for PeerIdSerialized {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        Ok(Self(PeerId::from_str(&s).map_err(|e| {
            de::Error::custom(format!("Failed to deserialise peer id: {:?}", e))
        })?))
    }
}

pub use crate::types::{
    error, Enr, EnrSyncCommitteeBitfield, GossipTopic, NetworkGlobals, PubsubMessage, Subnet,
    SubnetDiscovery,
};

pub use prometheus_client;

pub use config::Config as NetworkConfig;
pub use discovery::{CombinedKeyExt, EnrExt, Eth2Enr};
pub use discv5;
pub use libp2p;
pub use libp2p::bandwidth::BandwidthSinks;
pub use libp2p::gossipsub::{IdentTopic, MessageAcceptance, MessageId, Topic, TopicHash};
pub use libp2p::{core::ConnectedPoint, PeerId, Swarm};
pub use libp2p::{multiaddr, Multiaddr};
pub use metrics::scrape_discovery_metrics;
pub use peer_manager::{
    peerdb::client::Client,
    peerdb::score::{PeerAction, ReportSource},
    peerdb::PeerDB,
    ConnectionDirection, PeerConnectionStatus, PeerInfo, PeerManager, SyncInfo, SyncStatus,
};
// pub use service::{load_private_key, Context, Libp2pEvent, Service, NETWORK_KEY_FILENAME};
pub use service::api_types::{PeerRequestId, Request, Response};
pub use service::utils::*;
pub use service::{Gossipsub, NetworkEvent};
