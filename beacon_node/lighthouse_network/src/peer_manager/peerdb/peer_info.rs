use super::client::Client;
use super::score::{PeerAction, Score, ScoreState};
use super::sync_status::SyncStatus;
use crate::Multiaddr;
use crate::{rpc::MetaData, types::Subnet};
use discv5::Enr;
use serde::{
    ser::{SerializeStruct, Serializer},
    Serialize,
};
use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use strum::AsRefStr;
use types::EthSpec;
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
    client: Client,
    /// Connection status of this peer
    connection_status: PeerConnectionStatus,
    /// The known listening addresses of this peer. This is given by identify and can be arbitrary
    /// (including local IPs).
    listening_addresses: Vec<Multiaddr>,
    /// This is addresses we have physically seen and this is what we use for banning/un-banning
    /// peers.
    seen_addresses: HashSet<SocketAddr>,
    /// The current syncing state of the peer. The state may be determined after it's initial
    /// connection.
    sync_status: SyncStatus,
    /// The ENR subnet bitfield of the peer. This may be determined after it's initial
    /// connection.
    meta_data: Option<MetaData<T>>,
    /// Subnets the peer is connected to.
    subnets: HashSet<Subnet>,
    /// The time we would like to retain this peer. After this time, the peer is no longer
    /// necessary.
    #[serde(skip)]
    min_ttl: Option<Instant>,
    /// Is the peer a trusted peer.
    is_trusted: bool,
    /// Direction of the first connection of the last (or current) connected session with this peer.
    /// None if this peer was never connected.
    connection_direction: Option<ConnectionDirection>,
    /// The enr of the peer, if known.
    enr: Option<Enr>,
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
            sync_status: SyncStatus::Unknown,
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

    /// Returns if the peer is subscribed to a given `Subnet` from the metadata attnets/syncnets field.
    pub fn on_subnet_metadata(&self, subnet: &Subnet) -> bool {
        if let Some(meta_data) = &self.meta_data {
            match subnet {
                Subnet::Attestation(id) => {
                    return meta_data.attnets().get(**id as usize).unwrap_or(false)
                }
                Subnet::SyncCommittee(id) => {
                    return meta_data
                        .syncnets()
                        .map_or(false, |s| s.get(**id as usize).unwrap_or(false))
                }
            }
        }
        false
    }

    /// Obtains the client of the peer.
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Returns the listening addresses of the Peer.
    pub fn listening_addresses(&self) -> &Vec<Multiaddr> {
        &self.listening_addresses
    }

    /// Returns the connection direction for the peer.
    pub fn connection_direction(&self) -> Option<&ConnectionDirection> {
        self.connection_direction.as_ref()
    }

    /// Returns the sync status of the peer.
    pub fn sync_status(&self) -> &SyncStatus {
        &self.sync_status
    }

    /// Returns the metadata for the peer if currently known.
    pub fn meta_data(&self) -> Option<&MetaData<T>> {
        self.meta_data.as_ref()
    }

    /// Returns whether the peer is a trusted peer or not.
    pub fn is_trusted(&self) -> bool {
        self.is_trusted
    }

    /// The time a peer is expected to be useful until for an attached validator. If this is set to
    /// None, the peer is not required for any upcoming duty.
    pub fn min_ttl(&self) -> Option<&Instant> {
        self.min_ttl.as_ref()
    }

    /// The ENR of the peer if it is known.
    pub fn enr(&self) -> Option<&Enr> {
        self.enr.as_ref()
    }

    /// Returns if the peer is subscribed to a given `Subnet` from the gossipsub subscriptions.
    pub fn on_subnet_gossipsub(&self, subnet: &Subnet) -> bool {
        self.subnets.contains(subnet)
    }

    /// Returns the seen addresses of the peer.
    pub fn seen_addresses(&self) -> impl Iterator<Item = &SocketAddr> + '_ {
        self.seen_addresses.iter()
    }

    /// Returns a list of seen IP addresses for the peer.
    pub fn seen_ip_addresses(&self) -> impl Iterator<Item = IpAddr> + '_ {
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

    /// Returns true if the gossipsub score is sufficient.
    pub fn is_good_gossipsub_peer(&self) -> bool {
        self.score.is_good_gossipsub_peer()
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

    /// Checks if the connection status is banned. This can lag behind the score state
    /// temporarily.
    pub fn is_banned(&self) -> bool {
        matches!(self.connection_status, PeerConnectionStatus::Banned { .. })
    }

    /// Checks if the peer's score is banned.
    pub fn score_is_banned(&self) -> bool {
        matches!(self.score.state(), ScoreState::Banned)
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

    /* Mutable Functions */

    /// Updates the sync status. Returns true if the status was changed.
    // VISIBILITY: Both the peer manager the network sync is able to update the sync state of a peer
    pub fn update_sync_status(&mut self, sync_status: SyncStatus) -> bool {
        self.sync_status.update(sync_status)
    }

    /// Sets the client of the peer.
    // VISIBILITY: The peer manager is able to set the client
    pub(in crate::peer_manager) fn set_client(&mut self, client: Client) {
        self.client = client
    }

    /// Replaces the current listening addresses with those specified, returning the current
    /// listening addresses.
    // VISIBILITY: The peer manager is able to set the listening addresses
    pub(in crate::peer_manager) fn set_listening_addresses(
        &mut self,
        listening_addresses: Vec<Multiaddr>,
    ) -> Vec<Multiaddr> {
        std::mem::replace(&mut self.listening_addresses, listening_addresses)
    }

    /// Sets an explicit value for the meta data.
    // VISIBILITY: The peer manager is able to adjust the meta_data
    pub(in crate::peer_manager) fn set_meta_data(&mut self, meta_data: MetaData<T>) {
        self.meta_data = Some(meta_data)
    }

    /// Sets the connection status of the peer.
    pub(super) fn set_connection_status(&mut self, connection_status: PeerConnectionStatus) {
        self.connection_status = connection_status
    }

    /// Sets the ENR of the peer if one is known.
    pub(super) fn set_enr(&mut self, enr: Enr) {
        self.enr = Some(enr)
    }

    /// Sets the time that the peer is expected to be needed until for an attached validator duty.
    pub(super) fn set_min_ttl(&mut self, min_ttl: Instant) {
        self.min_ttl = Some(min_ttl)
    }

    /// Adds a known subnet for the peer.
    pub(super) fn insert_subnet(&mut self, subnet: Subnet) {
        self.subnets.insert(subnet);
    }

    /// Removes a subnet from the peer.
    pub(super) fn remove_subnet(&mut self, subnet: &Subnet) {
        self.subnets.remove(subnet);
    }

    /// Removes all subnets from the peer.
    pub(super) fn clear_subnets(&mut self) {
        self.subnets.clear()
    }

    /// Applies decay rates to a non-trusted peer's score.
    pub(super) fn score_update(&mut self) {
        if !self.is_trusted {
            self.score.update()
        }
    }

    /// Apply peer action to a non-trusted peer's score.
    // VISIBILITY: The peer manager is able to modify the score of a peer.
    pub(in crate::peer_manager) fn apply_peer_action_to_score(&mut self, peer_action: PeerAction) {
        if !self.is_trusted {
            self.score.apply_peer_action(peer_action)
        }
    }

    /// Updates the gossipsub score with a new score. Optionally ignore the gossipsub score.
    pub(super) fn update_gossipsub_score(&mut self, new_score: f64, ignore: bool) {
        self.score.update_gossipsub_score(new_score, ignore);
    }

    #[cfg(test)]
    /// Resets the peers score.
    pub fn reset_score(&mut self) {
        self.score.test_reset();
    }

    /// Modifies the status to Dialing
    /// Returns an error if the current state is unexpected.
    pub(super) fn dialing_peer(&mut self) -> Result<(), &'static str> {
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
    pub(super) fn connect_ingoing(&mut self, seen_address: Option<SocketAddr>) {
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
    pub(super) fn connect_outgoing(&mut self, seen_address: Option<SocketAddr>) {
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
    /// The connection was established by a peer dialing us.
    Incoming,
    /// The connection was established by us dialing a peer.
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
