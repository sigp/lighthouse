use super::client::Client;
use super::score::Score;
use super::PeerSyncStatus;
use crate::rpc::MetaData;
use crate::Multiaddr;
use serde::{
    ser::{SerializeStruct, Serializer},
    Serialize,
};
use std::net::IpAddr;
use std::time::Instant;
use types::{EthSpec, SubnetId};
use PeerConnectionStatus::*;

/// Information about a given connected peer.
#[derive(Clone, Debug, Serialize)]
#[serde(bound = "T: EthSpec")]
pub struct PeerInfo<T: EthSpec> {
    /// The connection status of the peer
    _status: PeerStatus,
    /// The peers reputation
    pub score: Score,
    /// Client managing this peer
    pub client: Client,
    /// Connection status of this peer
    pub connection_status: PeerConnectionStatus,
    /// The known listening addresses of this peer.
    pub listening_addresses: Vec<Multiaddr>,
    /// The current syncing state of the peer. The state may be determined after it's initial
    /// connection.
    pub sync_status: PeerSyncStatus,
    /// The ENR subnet bitfield of the peer. This may be determined after it's initial
    /// connection.
    pub meta_data: Option<MetaData<T>>,
    /// The time we would like to retain this peer. After this time, the peer is no longer
    /// necessary.
    #[serde(skip)]
    pub min_ttl: Option<Instant>,
}

impl<TSpec: EthSpec> Default for PeerInfo<TSpec> {
    fn default() -> PeerInfo<TSpec> {
        PeerInfo {
            _status: Default::default(),
            score: Score::default(),
            client: Client::default(),
            connection_status: Default::default(),
            listening_addresses: vec![],
            sync_status: PeerSyncStatus::Unknown,
            meta_data: None,
            min_ttl: None,
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

    /// Reports if this peer has some future validator duty in which case it is valuable to keep it.
    pub fn has_future_duty(&self) -> bool {
        self.min_ttl.map_or(false, |i| i >= Instant::now())
    }
}

#[derive(Clone, Debug, Serialize)]
/// The current health status of the peer.
pub enum PeerStatus {
    /// The peer is healthy.
    Healthy,
    /// The peer is clogged. It has not been responding to requests on time.
    _Clogged,
}

impl Default for PeerStatus {
    fn default() -> Self {
        PeerStatus::Healthy
    }
}

/// Connection Status of the peer.
#[derive(Debug, Clone)]
pub enum PeerConnectionStatus {
    /// The peer is connected.
    Connected {
        /// number of ingoing connections.
        n_in: u8,
        /// number of outgoing connections.
        n_out: u8,
    },
    /// The peer has disconnected.
    Disconnected {
        /// last time the peer was connected or discovered.
        since: Instant,
    },
    /// The peer has been banned and is disconnected.
    Banned {
        /// moment when the peer was banned.
        since: Instant,
        /// ip addresses this peer had a the moment of the ban
        ip_addresses: Vec<IpAddr>,
    },
    /// We are currently dialing this peer.
    Dialing {
        /// time since we last communicated with the peer.
        since: Instant,
    },
    /// The connection status has not been specified.
    Unknown,
}

/// Serialization for http requests.
impl Serialize for PeerConnectionStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("connection_status", 5)?;
        match self {
            Connected { n_in, n_out } => {
                s.serialize_field("status", "connected")?;
                s.serialize_field("connections_in", n_in)?;
                s.serialize_field("connections_out", n_out)?;
                s.serialize_field("last_seen", &0)?;
                s.serialize_field("banned_ips", &Vec::<IpAddr>::new())?;
                s.end()
            }
            Disconnected { since } => {
                s.serialize_field("status", "disconnected")?;
                s.serialize_field("connections_in", &0)?;
                s.serialize_field("connections_out", &0)?;
                s.serialize_field("last_seen", &since.elapsed().as_secs())?;
                s.serialize_field("banned_ips", &Vec::<IpAddr>::new())?;
                s.end()
            }
            Banned {
                since,
                ip_addresses,
            } => {
                s.serialize_field("status", "banned")?;
                s.serialize_field("connections_in", &0)?;
                s.serialize_field("connections_out", &0)?;
                s.serialize_field("last_seen", &since.elapsed().as_secs())?;
                s.serialize_field("banned_ips", &ip_addresses)?;
                s.end()
            }
            Dialing { since } => {
                s.serialize_field("status", "dialing")?;
                s.serialize_field("connections_in", &0)?;
                s.serialize_field("connections_out", &0)?;
                s.serialize_field("last_seen", &since.elapsed().as_secs())?;
                s.serialize_field("banned_ips", &Vec::<IpAddr>::new())?;
                s.end()
            }
            Unknown => {
                s.serialize_field("status", "unknown")?;
                s.serialize_field("connections_in", &0)?;
                s.serialize_field("connections_out", &0)?;
                s.serialize_field("last_seen", &0)?;
                s.serialize_field("banned_ips", &Vec::<IpAddr>::new())?;
                s.end()
            }
        }
    }
}

impl Default for PeerConnectionStatus {
    fn default() -> Self {
        PeerConnectionStatus::Unknown
    }
}

impl PeerConnectionStatus {
    /// Checks if the status is connected.
    pub fn is_connected(&self) -> bool {
        match self {
            PeerConnectionStatus::Connected { .. } => true,
            _ => false,
        }
    }

    /// Checks if the status is connected.
    pub fn is_dialing(&self) -> bool {
        match self {
            PeerConnectionStatus::Dialing { .. } => true,
            _ => false,
        }
    }

    /// The peer is either connected or in the process of being dialed.
    pub fn is_connected_or_dialing(&self) -> bool {
        self.is_connected() || self.is_dialing()
    }

    /// Checks if the status is banned.
    pub fn is_banned(&self) -> bool {
        match self {
            PeerConnectionStatus::Banned { .. } => true,
            _ => false,
        }
    }

    /// Checks if the status is disconnected.
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
            Disconnected { .. } | Banned { .. } | Dialing { .. } | Unknown => {
                *self = Connected { n_in: 1, n_out: 0 }
            }
        }
    }

    /// Modifies the status to Connected and increases the number of outgoing
    /// connections by one
    pub fn connect_outgoing(&mut self) {
        match self {
            Connected { n_out, .. } => *n_out += 1,
            Disconnected { .. } | Banned { .. } | Dialing { .. } | Unknown => {
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
    pub fn ban(&mut self, ip_addresses: Vec<IpAddr>) {
        *self = Banned {
            since: Instant::now(),
            ip_addresses,
        };
    }

    /// The score system has unbanned the peer. Update the connection status
    pub fn unban(&mut self) {
        if let PeerConnectionStatus::Banned { since, .. } = self {
            *self = PeerConnectionStatus::Disconnected { since: *since }
        }
    }

    pub fn connections(&self) -> (u8, u8) {
        match self {
            Connected { n_in, n_out } => (*n_in, *n_out),
            _ => (0, 0),
        }
    }
}
