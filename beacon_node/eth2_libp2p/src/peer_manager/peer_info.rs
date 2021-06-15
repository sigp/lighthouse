use super::client::Client;
use super::score::{PeerAction, Score, ScoreState};
use super::PeerSyncStatus;
use crate::rpc::MetaData;
use crate::Multiaddr;
use discv5::Enr;
use serde::{
    ser::{SerializeStruct, Serializer},
    Serialize,
};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use strum::AsRefStr;
use types::{EthSpec, SubnetId};
use PeerConnectionStatus::*;

/// Information about a given connected peer.
#[derive(Clone, Debug, Serialize)]
#[serde(bound = "T: EthSpec")]
pub struct PeerInfo<T: EthSpec> {
    /// The connection status of the peer
    _status: PeerStatus,
    /// The peers reputation
    score: Score,
    /// Client managing this peer
    pub client: Client,
    /// Connection status of this peer
    connection_status: PeerConnectionStatus,
    /// The known listening addresses of this peer. This is given by identify and can be arbitrary
    /// (including local IPs).
    pub listening_addresses: Vec<Multiaddr>,
    /// This is addresses we have physically seen and this is what we use for banning/un-banning
    /// peers.
    pub seen_addresses: HashSet<SocketAddr>,
    /// The current syncing state of the peer. The state may be determined after it's initial
    /// connection.
    pub sync_status: PeerSyncStatus,
    /// The ENR subnet bitfield of the peer. This may be determined after it's initial
    /// connection.
    pub meta_data: Option<MetaData<T>>,
    /// Subnets the peer is connected to.
    pub subnets: HashSet<SubnetId>,
    /// The time we would like to retain this peer. After this time, the peer is no longer
    /// necessary.
    #[serde(skip)]
    pub min_ttl: Option<Instant>,
    /// Is the peer a trusted peer.
    pub is_trusted: bool,
    /// Direction of the first connection of the last (or current) connected session with this peer.
    /// None if this peer was never connected.
    pub connection_direction: Option<ConnectionDirection>,
    /// The enr of the peer, if known.
    pub enr: Option<Enr>,
}

impl<TSpec: EthSpec> Default for PeerInfo<TSpec> {
    fn default() -> PeerInfo<TSpec> {
        PeerInfo {
            _status: Default::default(),
            score: Score::default(),
            client: Client::default(),
            connection_status: Default::default(),
            listening_addresses: Vec::new(),
            seen_addresses: HashSet::new(),
            subnets: HashSet::new(),
            sync_status: PeerSyncStatus::Unknown,
            meta_data: None,
            min_ttl: None,
            is_trusted: false,
            connection_direction: None,
            enr: None,
        }
    }
}

impl<T: EthSpec> PeerInfo<T> {
    /// Return a PeerInfo struct for a trusted peer.
    pub fn trusted_peer_info() -> Self {
        PeerInfo {
            score: Score::max_score(),
            is_trusted: true,
            ..Default::default()
        }
    }

    /// Returns if the peer is subscribed to a given `SubnetId` from the metadata attnets field.
    pub fn on_subnet_metadata(&self, subnet_id: SubnetId) -> bool {
        if let Some(meta_data) = &self.meta_data {
            return meta_data.attnets.get(*subnet_id as usize).unwrap_or(false);
        }
        false
    }

    /// Returns if the peer is subscribed to a given `SubnetId` from the gossipsub subscriptions.
    pub fn on_subnet_gossipsub(&self, subnet_id: SubnetId) -> bool {
        self.subnets.contains(&subnet_id)
    }

    /// Returns the seen IP addresses of the peer.
    pub fn seen_addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
        self.seen_addresses
            .iter()
            .map(|socket_addr| socket_addr.ip())
    }

    /// Returns the connection status of the peer.
    pub fn connection_status(&self) -> &PeerConnectionStatus {
        &self.connection_status
    }

    /// Reports if this peer has some future validator duty in which case it is valuable to keep it.
    pub fn has_future_duty(&self) -> bool {
        self.min_ttl.map_or(false, |i| i >= Instant::now())
    }

    /// Returns score of the peer.
    pub fn score(&self) -> &Score {
        &self.score
    }

    /// Returns the state of the peer based on the score.
    pub(crate) fn score_state(&self) -> ScoreState {
        self.score.state()
    }

    /// Applies decay rates to a non-trusted peer's score.
    pub fn score_update(&mut self) {
        if !self.is_trusted {
            self.score.update()
        }
    }

    /// Apply peer action to a non-trusted peer's score.
    pub fn apply_peer_action_to_score(&mut self, peer_action: PeerAction) {
        if !self.is_trusted {
            self.score.apply_peer_action(peer_action)
        }
    }

    pub(crate) fn update_gossipsub_score(&mut self, new_score: f64, ignore: bool) {
        self.score.update_gossipsub_score(new_score, ignore);
    }

    pub fn is_good_gossipsub_peer(&self) -> bool {
        self.score.is_good_gossipsub_peer()
    }

    #[cfg(test)]
    /// Resets the peers score.
    pub fn reset_score(&mut self) {
        self.score.test_reset();
    }

    /* Peer connection status API */

    /// Checks if the status is connected.
    pub fn is_connected(&self) -> bool {
        matches!(
            self.connection_status,
            PeerConnectionStatus::Connected { .. }
        )
    }

    /// Checks if the status is connected.
    pub fn is_dialing(&self) -> bool {
        matches!(self.connection_status, PeerConnectionStatus::Dialing { .. })
    }

    /// The peer is either connected or in the process of being dialed.
    pub fn is_connected_or_dialing(&self) -> bool {
        self.is_connected() || self.is_dialing()
    }

    /// Checks if the status is banned.
    pub fn is_banned(&self) -> bool {
        matches!(self.connection_status, PeerConnectionStatus::Banned { .. })
    }

    /// Checks if the status is disconnected.
    pub fn is_disconnected(&self) -> bool {
        matches!(self.connection_status, Disconnected { .. })
    }

    /// Checks if the peer is outbound-only
    pub fn is_outbound_only(&self) -> bool {
        matches!(self.connection_status, Connected {n_in, n_out} if n_in == 0 && n_out > 0)
    }

    /// Returns the number of connections with this peer.
    pub fn connections(&self) -> (u8, u8) {
        match self.connection_status {
            Connected { n_in, n_out } => (n_in, n_out),
            _ => (0, 0),
        }
    }

    // Setters

    /// Modifies the status to Disconnected and sets the last seen instant to now. Returns None if
    /// no changes were made. Returns Some(bool) where the bool represents if peer became banned or
    /// simply just disconnected.
    pub fn notify_disconnect(&mut self) -> Option<bool> {
        match self.connection_status {
            Banned { .. } | Disconnected { .. } => None,
            Disconnecting { to_ban } => {
                // If we are disconnecting this peer in the process of banning, we now ban the
                // peer.
                if to_ban {
                    self.connection_status = Banned {
                        since: Instant::now(),
                    };
                    Some(true)
                } else {
                    self.connection_status = Disconnected {
                        since: Instant::now(),
                    };
                    Some(false)
                }
            }
            Connected { .. } | Dialing { .. } | Unknown => {
                self.connection_status = Disconnected {
                    since: Instant::now(),
                };
                Some(false)
            }
        }
    }

    /// Notify the we are currently disconnecting this peer, after which the peer will be
    /// considered banned.
    // This intermediate state is required to inform the network behaviours that the sub-protocols
    // are aware this peer exists and it is in the process of being banned. Compared to nodes that
    // try to connect to us and are already banned (sub protocols do not know of these peers).
    pub fn disconnecting(&mut self, to_ban: bool) {
        self.connection_status = Disconnecting { to_ban }
    }

    /// Modifies the status to Banned
    pub fn ban(&mut self) {
        self.connection_status = Banned {
            since: Instant::now(),
        };
    }

    /// The score system has unbanned the peer. Update the connection status
    pub fn unban(&mut self) {
        if let PeerConnectionStatus::Banned { since, .. } = self.connection_status {
            self.connection_status = PeerConnectionStatus::Disconnected { since };
        }
    }

    /// Modifies the status to Dialing
    /// Returns an error if the current state is unexpected.
    pub(crate) fn dialing_peer(&mut self) -> Result<(), &'static str> {
        match &mut self.connection_status {
            Connected { .. } => return Err("Dialing connected peer"),
            Dialing { .. } => return Err("Dialing an already dialing peer"),
            Disconnecting { .. } => return Err("Dialing a disconnecting peer"),
            Disconnected { .. } | Banned { .. } | Unknown => {}
        }
        self.connection_status = Dialing {
            since: Instant::now(),
        };
        Ok(())
    }

    /// Modifies the status to Connected and increases the number of ingoing
    /// connections by one
    pub(crate) fn connect_ingoing(&mut self, seen_address: Option<SocketAddr>) {
        match &mut self.connection_status {
            Connected { n_in, .. } => *n_in += 1,
            Disconnected { .. }
            | Banned { .. }
            | Dialing { .. }
            | Disconnecting { .. }
            | Unknown => {
                self.connection_status = Connected { n_in: 1, n_out: 0 };
                self.connection_direction = Some(ConnectionDirection::Incoming);
            }
        }

        if let Some(socket_addr) = seen_address {
            self.seen_addresses.insert(socket_addr);
        }
    }

    /// Modifies the status to Connected and increases the number of outgoing
    /// connections by one
    pub(crate) fn connect_outgoing(&mut self, seen_address: Option<SocketAddr>) {
        match &mut self.connection_status {
            Connected { n_out, .. } => *n_out += 1,
            Disconnected { .. }
            | Banned { .. }
            | Dialing { .. }
            | Disconnecting { .. }
            | Unknown => {
                self.connection_status = Connected { n_in: 0, n_out: 1 };
                self.connection_direction = Some(ConnectionDirection::Outgoing);
            }
        }
        if let Some(ip_addr) = seen_address {
            self.seen_addresses.insert(ip_addr);
        }
    }

    #[cfg(test)]
    /// Add an f64 to a non-trusted peer's score abiding by the limits.
    pub fn add_to_score(&mut self, score: f64) {
        if !self.is_trusted {
            self.score.test_add(score)
        }
    }

    #[cfg(test)]
    pub fn set_gossipsub_score(&mut self, score: f64) {
        self.score.set_gossipsub_score(score);
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

/// Connection Direction of connection.
#[derive(Debug, Clone, Serialize, AsRefStr)]
#[strum(serialize_all = "snake_case")]
pub enum ConnectionDirection {
    Incoming,
    Outgoing,
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
    /// The peer is being disconnected.
    Disconnecting {
        // After the disconnection the peer will be considered banned.
        to_ban: bool,
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
        let mut s = serializer.serialize_struct("connection_status", 6)?;
        match self {
            Connected { n_in, n_out } => {
                s.serialize_field("status", "connected")?;
                s.serialize_field("connections_in", n_in)?;
                s.serialize_field("connections_out", n_out)?;
                s.serialize_field("last_seen", &0)?;
                s.end()
            }
            Disconnecting { .. } => {
                s.serialize_field("status", "disconnecting")?;
                s.serialize_field("connections_in", &0)?;
                s.serialize_field("connections_out", &0)?;
                s.serialize_field("last_seen", &0)?;
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
            Banned { since } => {
                s.serialize_field("status", "banned")?;
                s.serialize_field("connections_in", &0)?;
                s.serialize_field("connections_out", &0)?;
                s.serialize_field("last_seen", &since.elapsed().as_secs())?;
                s.end()
            }
            Dialing { since } => {
                s.serialize_field("status", "dialing")?;
                s.serialize_field("connections_in", &0)?;
                s.serialize_field("connections_out", &0)?;
                s.serialize_field("last_seen", &since.elapsed().as_secs())?;
                s.end()
            }
            Unknown => {
                s.serialize_field("status", "unknown")?;
                s.serialize_field("connections_in", &0)?;
                s.serialize_field("connections_out", &0)?;
                s.serialize_field("last_seen", &0)?;
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
