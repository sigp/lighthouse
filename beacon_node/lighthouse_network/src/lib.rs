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
pub mod listen_addr;
pub mod metrics;
pub mod peer_manager;
pub mod rpc;
pub mod types;

pub use config::gossip_max_size;
use libp2p::swarm::DialError;
pub use listen_addr::*;

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

// A wrapper struct that prints a dial error nicely.
struct ClearDialError<'a>(&'a DialError);

impl<'a> std::fmt::Display for ClearDialError<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        match &self.0 {
            DialError::Transport(errors) => {
                for (_, transport_error) in errors {
                    match transport_error {
                        libp2p::TransportError::MultiaddrNotSupported(multiaddr_error) => {
                            write!(f, "Multiaddr not supported: {multiaddr_error}")?;
                        }
                        libp2p::TransportError::Other(io_error) => {
                            write!(f, "A transport level io error has occured: {io_error}")?;
                        }
                    }
                }
                Ok(())
            }
            DialError::Banned => write!(f, "The peer is currently banned"),
            DialError::ConnectionLimit(_) => write!(f, "The configured limit for simultaneous outgoing connections has been reached."),
            DialError::LocalPeerId =>  write!(f, "The peer being dialed is the local peer and thus the dial was aborted."),
            DialError::NoAddresses => write!(f, "NetworkBehaviour::addresses_of_peer returned no addresses for the peer to dial."),
            DialError::DialPeerConditionFalse(_) => write!(f, "The provided dial_opts::PeerCondition evaluated to false and thus the dial was aborted."),
            DialError::Aborted => write!(f, "Pending connection attempt has been aborted."),
            DialError::InvalidPeerId(_) => write!(f, "The provided peer identity is invalid."),
            DialError::WrongPeerId { .. } =>  write!(f, "The peer identity obtained on the connection did not match the one that was expected."),
            DialError::ConnectionIo(_) => write!(f, "An I/O error occurred on the connection."),
        }
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
