use super::peerdb::{Rep, DEFAULT_REPUTATION};
use crate::rpc::MetaData;
use std::time::Instant;
use types::{EthSpec, Slot, SubnetId};
use PeerConnectionStatus::*;

/// Information about a given connected peer.
#[derive(Debug)]
pub struct PeerInfo<T: EthSpec> {
    /// The connection status of the peer
    _status: PeerStatus,
    /// The peers reputation
    pub reputation: Rep,
    /// Client managing this peer
    _client: Client,
    /// Connection status of this peer
    pub connection_status: PeerConnectionStatus,
    /// The current syncing state of the peer. The state may be determined after it's initial
    /// connection.
    pub sync_status: PeerSyncStatus,
    /// The ENR subnet bitfield of the peer. This may be determined after it's initial
    /// connection.
    pub meta_data: Option<MetaData<T>>,
}

impl<TSpec: EthSpec> Default for PeerInfo<TSpec> {
    fn default() -> PeerInfo<TSpec> {
        PeerInfo {
            reputation: DEFAULT_REPUTATION,
            _status: Default::default(),
            _client: Client {
                _client_name: "Unknown".into(),
                _version: vec![0],
            },
            connection_status: Default::default(),
            sync_status: PeerSyncStatus::Unknown,
            meta_data: None,
        }
    }
}

impl<T: EthSpec> PeerInfo<T> {
    /// Returns if the peer is subscribed to a given `SubnetId`
    pub fn on_subnet(&self, subnet_id: SubnetId) -> bool {
        if let Some(meta_data) = &self.meta_data {
            return meta_data
                .attnets
                .get(*subnet_id as usize)
                .unwrap_or_else(|_| false);
        }
        false
    }
}

#[derive(Debug)]
pub enum PeerStatus {
    /// The peer is healthy
    Healthy,
    /// The peer is clogged. It has not been responding to requests on time
    Clogged,
}

impl Default for PeerStatus {
    fn default() -> Self {
        PeerStatus::Healthy
    }
}

/// Representation of the client managing a peer
#[derive(Debug)]
pub struct Client {
    /// The client's name (Ex: lighthouse, prism, nimbus, etc)
    _client_name: String,
    /// The client's version
    _version: Vec<u8>,
}

/// Connection Status of the peer
#[derive(Debug, Clone)]
pub enum PeerConnectionStatus {
    Connected {
        /// number of ingoing connections
        n_in: u8,
        /// number of outgoing connections
        n_out: u8,
    },
    Disconnected {
        /// last time the peer was connected or discovered
        since: Instant,
    },
    Banned {
        /// moment when the peer was banned
        since: Instant,
    },
    Unknown {
        /// time since we know of this peer
        since: Instant,
    },
}

#[derive(Debug, Clone, PartialEq)]
pub enum PeerSyncStatus {
    /// At the current state as our node or ahead of us.
    Synced {
        /// The last known head slot from the peer's handshake.
        status_head_slot: Slot,
    },
    /// Is behind our current head and not useful for block downloads.
    Behind {
        /// The last known head slot from the peer's handshake.
        status_head_slot: Slot,
    },
    /// Not currently known as a STATUS handshake has not occurred.
    Unknown,
}

impl Default for PeerConnectionStatus {
    fn default() -> Self {
        PeerConnectionStatus::Unknown {
            since: Instant::now(),
        }
    }
}

impl PeerConnectionStatus {
    /// Checks if the status is connected
    pub fn is_connected(&self) -> bool {
        match self {
            PeerConnectionStatus::Connected { .. } => true,
            _ => false,
        }
    }

    /// Checks if the status is banned
    pub fn is_banned(&self) -> bool {
        match self {
            PeerConnectionStatus::Banned { .. } => true,
            _ => false,
        }
    }

    /// Checks if the status is disconnected
    pub fn is_disconnected(&self) -> bool {
        match self {
            Disconnected { .. } => true,
            _ => false,
        }
    }

    /// Modifies the status to Connected and increases the number of ingoing
    /// connections by one
    pub fn connect_ingoing(&mut self) {
        match self {
            Connected { n_in, .. } => *n_in += 1,
            Disconnected { .. } | Banned { .. } | Unknown { .. } => {
                *self = Connected { n_in: 1, n_out: 0 }
            }
        }
    }

    /// Modifies the status to Connected and increases the number of outgoing
    /// connections by one
    pub fn connect_outgoing(&mut self) {
        match self {
            Connected { n_out, .. } => *n_out += 1,
            Disconnected { .. } | Banned { .. } | Unknown { .. } => {
                *self = Connected { n_in: 0, n_out: 1 }
            }
        }
    }

    /// Modifies the status to Disconnected and sets the last seen instant to now
    pub fn disconnect(&mut self) {
        *self = Disconnected {
            since: Instant::now(),
        };
    }

    /// Modifies the status to Banned
    pub fn ban(&mut self) {
        *self = Banned {
            since: Instant::now(),
        };
    }

    pub fn connections(&self) -> (u8, u8) {
        match self {
            Connected { n_in, n_out } => (*n_in, *n_out),
            _ => (0, 0),
        }
    }
}
