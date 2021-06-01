use super::peer_info::{ConnectionDirection, PeerConnectionStatus, PeerInfo};
use super::peer_sync_status::PeerSyncStatus;
use super::score::{Score, ScoreState};
use crate::multiaddr::{Multiaddr, Protocol};
use crate::rpc::methods::MetaData;
use crate::Enr;
use crate::PeerId;
use rand::seq::SliceRandom;
use slog::{crit, debug, error, trace, warn};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;
use types::{EthSpec, SubnetId};

/// Max number of disconnected nodes to remember.
const MAX_DC_PEERS: usize = 500;
/// The maximum number of banned nodes to remember.
const MAX_BANNED_PEERS: usize = 1000;
/// We ban an IP if there are more than `BANNED_PEERS_PER_IP_THRESHOLD` banned peers with this IP.
const BANNED_PEERS_PER_IP_THRESHOLD: usize = 5;

/// Storage of known peers, their reputation and information
pub struct PeerDB<TSpec: EthSpec> {
    /// The collection of known connected peers, their status and reputation
    peers: HashMap<PeerId, PeerInfo<TSpec>>,
    /// The number of disconnected nodes in the database.
    disconnected_peers: usize,
    /// Counts banned peers in total and per ip
    banned_peers_count: BannedPeersCount,
    /// PeerDB's logger
    log: slog::Logger,
}

pub struct BannedPeersCount {
    /// The number of banned peers in the database.
    banned_peers: usize,
    /// maps ips to number of banned peers with this ip
    banned_peers_per_ip: HashMap<IpAddr, usize>,
}

impl BannedPeersCount {
    /// Removes the peer from the counts if it is banned. Returns true if the peer was banned and
    /// false otherwise.
    pub fn remove_banned_peer(&mut self, ip_addresses: impl Iterator<Item = IpAddr>) {
        self.banned_peers = self.banned_peers.saturating_sub(1);
        for address in ip_addresses {
            if let Some(count) = self.banned_peers_per_ip.get_mut(&address) {
                *count = count.saturating_sub(1);
            }
        }
    }

    pub fn add_banned_peer(&mut self, ip_addresses: impl Iterator<Item = IpAddr>) {
        self.banned_peers = self.banned_peers.saturating_add(1);
        for address in ip_addresses {
            *self.banned_peers_per_ip.entry(address).or_insert(0) += 1;
        }
    }

    pub fn banned_peers(&self) -> usize {
        self.banned_peers
    }

    /// An IP is considered banned if more than BANNED_PEERS_PER_IP_THRESHOLD banned peers
    /// exist with this IP
    pub fn ip_is_banned(&self, ip: &IpAddr) -> bool {
        self.banned_peers_per_ip
            .get(ip)
            .map_or(false, |count| *count > BANNED_PEERS_PER_IP_THRESHOLD)
    }

    pub fn new() -> Self {
        BannedPeersCount {
            banned_peers: 0,
            banned_peers_per_ip: HashMap::new(),
        }
    }
}

impl<TSpec: EthSpec> PeerDB<TSpec> {
    pub fn new(trusted_peers: Vec<PeerId>, log: &slog::Logger) -> Self {
        // Initialize the peers hashmap with trusted peers
        let peers = trusted_peers
            .into_iter()
            .map(|peer_id| (peer_id, PeerInfo::trusted_peer_info()))
            .collect();
        Self {
            log: log.clone(),
            disconnected_peers: 0,
            banned_peers_count: BannedPeersCount::new(),
            peers,
        }
    }

    /* Getters */

    /// Gives the score of a peer, or default score if it is unknown.
    pub fn score(&self, peer_id: &PeerId) -> f64 {
        self.peers
            .get(peer_id)
            .map_or(&Score::default(), |info| info.score())
            .score()
    }

    /// Returns an iterator over all peers in the db.
    pub fn peers(&self) -> impl Iterator<Item = (&PeerId, &PeerInfo<TSpec>)> {
        self.peers.iter()
    }

    /// Returns an iterator over all peers in the db.
    pub(super) fn peers_mut(&mut self) -> impl Iterator<Item = (&PeerId, &mut PeerInfo<TSpec>)> {
        self.peers.iter_mut()
    }

    /// Gives the ids of all known peers.
    pub fn peer_ids(&self) -> impl Iterator<Item = &PeerId> {
        self.peers.keys()
    }

    /// Returns a peer's info, if known.
    pub fn peer_info(&self, peer_id: &PeerId) -> Option<&PeerInfo<TSpec>> {
        self.peers.get(peer_id)
    }

    /// Returns a mutable reference to a peer's info if known.
    pub fn peer_info_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo<TSpec>> {
        self.peers.get_mut(peer_id)
    }

    /// Returns if the peer is already connected.
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        matches!(
            self.connection_status(peer_id),
            Some(PeerConnectionStatus::Connected { .. })
        )
    }

    /// If we are connected or currently dialing the peer returns true.
    pub fn is_connected_or_dialing(&self, peer_id: &PeerId) -> bool {
        matches!(
            self.connection_status(peer_id),
            Some(PeerConnectionStatus::Connected { .. })
                | Some(PeerConnectionStatus::Dialing { .. })
        )
    }

    /// If we are connected or in the process of disconnecting
    pub fn is_connected_or_disconnecting(&self, peer_id: &PeerId) -> bool {
        matches!(
            self.connection_status(peer_id),
            Some(PeerConnectionStatus::Connected { .. })
                | Some(PeerConnectionStatus::Disconnecting { .. })
        )
    }

    /// Returns true if the peer should be dialed. This checks the connection state and the
    /// score state and determines if the peer manager should dial this peer.
    pub fn should_dial(&self, peer_id: &PeerId) -> bool {
        matches!(
            self.connection_status(peer_id),
            Some(PeerConnectionStatus::Disconnected { .. })
                | Some(PeerConnectionStatus::Unknown { .. })
                | None
        ) && !self.is_banned_or_disconnected(peer_id)
    }

    /// Returns true if the peer is synced at least to our current head.
    pub fn is_synced(&self, peer_id: &PeerId) -> bool {
        match self.peers.get(peer_id).map(|info| &info.sync_status) {
            Some(PeerSyncStatus::Synced { .. }) => true,
            Some(_) => false,
            None => false,
        }
    }

    /// Returns true if the Peer is banned. This doesn't check the connection state, rather the
    /// underlying score of the peer. A peer may be banned but still in the connected state
    /// temporarily.
    ///
    /// This is used to determine if we should accept incoming connections or not.
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        if let Some(peer) = self.peers.get(peer_id) {
            match peer.score_state() {
                ScoreState::Banned => true,
                _ => self.ip_is_banned(peer),
            }
        } else {
            false
        }
    }

    fn ip_is_banned(&self, peer: &PeerInfo<TSpec>) -> bool {
        peer.seen_addresses()
            .any(|ip| self.banned_peers_count.ip_is_banned(&ip))
    }

    /// Returns true if the IP is banned.
    pub fn is_ip_banned(&self, ip: &IpAddr) -> bool {
        self.banned_peers_count.ip_is_banned(ip)
    }

    /// Returns true if the Peer is either banned or in the disconnected state.
    pub fn is_banned_or_disconnected(&self, peer_id: &PeerId) -> bool {
        if let Some(peer) = self.peers.get(peer_id) {
            match peer.score_state() {
                ScoreState::Banned | ScoreState::Disconnected => true,
                _ => self.ip_is_banned(peer),
            }
        } else {
            false
        }
    }

    /// Gives the ids and info of all known connected peers.
    pub fn connected_peers(&self) -> impl Iterator<Item = (&PeerId, &PeerInfo<TSpec>)> {
        self.peers.iter().filter(|(_, info)| info.is_connected())
    }

    /// Gives the ids of all known connected peers.
    pub fn connected_peer_ids(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.is_connected())
            .map(|(peer_id, _)| peer_id)
    }

    /// Connected or dialing peers
    pub fn connected_or_dialing_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.is_connected() || info.is_dialing())
            .map(|(peer_id, _)| peer_id)
    }

    /// Connected outbound-only peers
    pub fn connected_outbound_only_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.is_outbound_only())
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives the `peer_id` of all known connected and synced peers.
    pub fn synced_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| {
                if info.sync_status.is_synced() || info.sync_status.is_advanced() {
                    return info.is_connected();
                }
                false
            })
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives the `peer_id` of all known connected and advanced peers.
    pub fn advanced_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| {
                if info.sync_status.is_advanced() {
                    return info.is_connected();
                }
                false
            })
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives an iterator of all peers on a given subnet.
    pub fn good_peers_on_subnet(&self, subnet_id: SubnetId) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(move |(_, info)| {
                // We check both the metadata and gossipsub data as we only want to count long-lived subscribed peers
                info.is_connected()
                    && info.on_subnet_metadata(subnet_id)
                    && info.on_subnet_gossipsub(subnet_id)
                    && info.is_good_gossipsub_peer()
            })
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives the ids of all known disconnected peers.
    pub fn disconnected_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.is_disconnected())
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives the ids of all known banned peers.
    pub fn banned_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.is_banned())
            .map(|(peer_id, _)| peer_id)
    }

    /// Returns a vector of all connected peers sorted by score beginning with the worst scores.
    /// Ties get broken randomly.
    pub fn worst_connected_peers(&self) -> Vec<(&PeerId, &PeerInfo<TSpec>)> {
        let mut connected = self
            .peers
            .iter()
            .filter(|(_, info)| info.is_connected())
            .collect::<Vec<_>>();

        connected.shuffle(&mut rand::thread_rng());
        connected.sort_by_key(|(_, info)| info.score());
        connected
    }

    /// Returns a vector containing peers (their ids and info), sorted by
    /// score from highest to lowest, and filtered using `is_status`
    pub fn best_peers_by_status<F>(&self, is_status: F) -> Vec<(&PeerId, &PeerInfo<TSpec>)>
    where
        F: Fn(&PeerInfo<TSpec>) -> bool,
    {
        let mut by_status = self
            .peers
            .iter()
            .filter(|(_, info)| is_status(&info))
            .collect::<Vec<_>>();
        by_status.sort_by_key(|(_, info)| info.score());
        by_status.into_iter().rev().collect()
    }

    /// Returns the peer with highest reputation that satisfies `is_status`
    pub fn best_by_status<F>(&self, is_status: F) -> Option<&PeerId>
    where
        F: Fn(&PeerInfo<TSpec>) -> bool,
    {
        self.peers
            .iter()
            .filter(|(_, info)| is_status(&info))
            .max_by_key(|(_, info)| info.score())
            .map(|(id, _)| id)
    }

    /// Returns the peer's connection status. Returns unknown if the peer is not in the DB.
    pub fn connection_status(&self, peer_id: &PeerId) -> Option<PeerConnectionStatus> {
        self.peer_info(peer_id)
            .map(|info| info.connection_status().clone())
    }

    /* Setters */

    /// A peer is being dialed.
    pub fn dialing_peer(&mut self, peer_id: &PeerId, enr: Option<Enr>) {
        let info = self.peers.entry(*peer_id).or_default();
        info.enr = enr;

        if info.is_disconnected() {
            self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
        }

        if info.is_banned() {
            self.banned_peers_count
                .remove_banned_peer(info.seen_addresses());
        }

        if let Err(e) = info.dialing_peer() {
            error!(self.log, "{}", e; "peer_id" => %peer_id);
        }
    }

    /// Update min ttl of a peer.
    pub fn update_min_ttl(&mut self, peer_id: &PeerId, min_ttl: Instant) {
        let info = self.peers.entry(*peer_id).or_default();

        // only update if the ttl is longer
        if info.min_ttl.is_none() || Some(min_ttl) > info.min_ttl {
            info.min_ttl = Some(min_ttl);

            let min_ttl_secs = min_ttl
                .checked_duration_since(Instant::now())
                .map(|duration| duration.as_secs())
                .unwrap_or_else(|| 0);
            debug!(self.log, "Updating the time a peer is required for"; "peer_id" => %peer_id, "future_min_ttl_secs" => min_ttl_secs);
        }
    }

    /// Extends the ttl of all peers on the given subnet that have a shorter
    /// min_ttl than what's given.
    pub fn extend_peers_on_subnet(&mut self, subnet_id: SubnetId, min_ttl: Instant) {
        let log = &self.log;
        self.peers.iter_mut()
            .filter(move |(_, info)| {
                info.is_connected() && info.on_subnet_metadata(subnet_id) && info.on_subnet_gossipsub(subnet_id)
            })
            .for_each(|(peer_id,info)| {
                if info.min_ttl.is_none() || Some(min_ttl) > info.min_ttl {
                    info.min_ttl = Some(min_ttl);
                }
                let min_ttl_secs = min_ttl
                    .checked_duration_since(Instant::now())
                    .map(|duration| duration.as_secs())
                    .unwrap_or_else(|| 0);
                trace!(log, "Updating minimum duration a peer is required for"; "peer_id" => %peer_id, "min_ttl" => min_ttl_secs);
            });
    }

    fn connect(
        &mut self,
        peer_id: &PeerId,
        multiaddr: Multiaddr,
        enr: Option<Enr>,
        direction: ConnectionDirection,
    ) {
        let info = self.peers.entry(*peer_id).or_default();
        info.enr = enr;

        if info.is_disconnected() {
            self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
        }

        if info.is_banned() {
            error!(self.log, "Accepted a connection from a banned peer"; "peer_id" => %peer_id);
            self.banned_peers_count
                .remove_banned_peer(info.seen_addresses());
        }

        // Add the seen ip address and port to the peer's info
        let socket_addr = match multiaddr.iter().fold(
            (None, None),
            |(found_ip, found_port), protocol| match protocol {
                Protocol::Ip4(ip) => (Some(ip.into()), found_port),
                Protocol::Ip6(ip) => (Some(ip.into()), found_port),
                Protocol::Tcp(port) => (found_ip, Some(port)),
                _ => (found_ip, found_port),
            },
        ) {
            (Some(ip), Some(port)) => Some(SocketAddr::new(ip, port)),
            (Some(_ip), None) => {
                crit!(self.log, "Connected peer has an IP but no TCP port"; "peer_id" => %peer_id);
                None
            }
            _ => None,
        };

        match direction {
            ConnectionDirection::Incoming => info.connect_ingoing(socket_addr),
            ConnectionDirection::Outgoing => info.connect_outgoing(socket_addr),
        }
    }
    /// Sets a peer as connected with an ingoing connection.
    pub fn connect_ingoing(&mut self, peer_id: &PeerId, multiaddr: Multiaddr, enr: Option<Enr>) {
        self.connect(peer_id, multiaddr, enr, ConnectionDirection::Incoming)
    }

    /// Sets a peer as connected with an outgoing connection.
    pub fn connect_outgoing(&mut self, peer_id: &PeerId, multiaddr: Multiaddr, enr: Option<Enr>) {
        self.connect(peer_id, multiaddr, enr, ConnectionDirection::Outgoing)
    }

    /// Sets the peer as disconnected. A banned peer remains banned
    pub fn notify_disconnect(&mut self, peer_id: &PeerId) {
        // Note that it could be the case we prevent new nodes from joining. In this instance,
        // we don't bother tracking the new node.
        if let Some(info) = self.peers.get_mut(peer_id) {
            if let Some(became_banned) = info.notify_disconnect() {
                if became_banned {
                    self.banned_peers_count
                        .add_banned_peer(info.seen_addresses());
                } else {
                    self.disconnected_peers += 1;
                }
            }
            self.shrink_to_fit();
        }
    }

    /// Notifies the peer manager that the peer is undergoing a normal disconnect (without banning
    /// afterwards.
    pub fn notify_disconnecting(&mut self, peer_id: &PeerId) {
        if let Some(info) = self.peers.get_mut(peer_id) {
            info.disconnecting(false);
        }
    }

    /// Marks a peer to be disconnected and then banned.
    /// Returns true if the peer is currently connected and false otherwise.
    // NOTE: If the peer's score is not already low enough to be banned, this will decrease the
    // peer's score to be a banned state.
    pub fn disconnect_and_ban(&mut self, peer_id: &PeerId) -> bool {
        let log_ref = &self.log;
        let info = self.peers.entry(*peer_id).or_insert_with(|| {
            warn!(log_ref, "Banning unknown peer";
                "peer_id" => %peer_id);
            PeerInfo::default()
        });

        // Ban the peer if the score is not already low enough.
        match info.score_state() {
            ScoreState::Banned => {}
            _ => {
                // If score isn't low enough to ban, this function has been called incorrectly.
                error!(self.log, "Banning a peer with a good score"; "peer_id" => %peer_id);
                info.apply_peer_action_to_score(super::score::PeerAction::Fatal);
            }
        }

        // Check and verify all the connection states
        match info.connection_status() {
            PeerConnectionStatus::Disconnected { .. } => {
                // It is possible to ban a peer that has a disconnected score, if there are many
                // events that score it poorly and are processed after it has disconnected.
                debug!(log_ref, "Banning a disconnected peer"; "peer_id" => %peer_id);
                self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
                info.ban();
                self.banned_peers_count
                    .add_banned_peer(info.seen_addresses());
                false
            }
            PeerConnectionStatus::Disconnecting { .. } => {
                warn!(log_ref, "Banning peer that is currently disconnecting"; "peer_id" => %peer_id);
                info.disconnecting(true);
                false
            }
            PeerConnectionStatus::Banned { .. } => {
                error!(log_ref, "Banning already banned peer"; "peer_id" => %peer_id);
                false
            }
            PeerConnectionStatus::Connected { .. } | PeerConnectionStatus::Dialing { .. } => {
                // update the state
                info.disconnecting(true);
                true
            }
            PeerConnectionStatus::Unknown => {
                // shift the peer straight to banned
                warn!(log_ref, "Banning a peer of unknown connection state"; "peer_id" => %peer_id);
                self.banned_peers_count
                    .add_banned_peer(info.seen_addresses());
                info.ban();
                false
            }
        }
    }

    /// Unbans a peer.
    /// This should only be called once a peer's score is no longer banned.
    /// If this is called for a banned peer, it will error.
    pub fn unban(&mut self, peer_id: &PeerId) -> Result<(), &'static str> {
        let log_ref = &self.log;
        let info = self.peers.entry(*peer_id).or_insert_with(|| {
            warn!(log_ref, "UnBanning unknown peer";
                "peer_id" => %peer_id);
            PeerInfo::default()
        });

        if !info.is_banned() {
            return Err("Unbanning peer that is not banned");
        }

        if let ScoreState::Banned = info.score_state() {
            return Err("Attempted to unban (connection status) a banned peer");
        }

        self.banned_peers_count
            .remove_banned_peer(info.seen_addresses());
        info.unban();
        // This transitions a banned peer to a disconnected peer
        self.disconnected_peers = self.disconnected_peers.saturating_add(1);
        self.shrink_to_fit();
        Ok(())
    }

    /// Removes banned and disconnected peers from the DB if we have reached any of our limits.
    /// Drops the peers with the lowest reputation so that the number of
    /// disconnected peers is less than MAX_DC_PEERS
    pub fn shrink_to_fit(&mut self) {
        // Remove excess banned peers
        while self.banned_peers_count.banned_peers() > MAX_BANNED_PEERS {
            if let Some(to_drop) = if let Some((id, info, _)) = self
                .peers
                .iter()
                .filter_map(|(id, info)| match info.connection_status() {
                    PeerConnectionStatus::Banned { since } => Some((id, info, since)),
                    _ => None,
                })
                .min_by_key(|(_, _, since)| *since)
            {
                self.banned_peers_count
                    .remove_banned_peer(info.seen_addresses());
                Some(*id)
            } else {
                // If there is no minimum, this is a coding error.
                crit!(
                    self.log,
                    "banned_peers > MAX_BANNED_PEERS despite no banned peers in db!"
                );
                // reset banned_peers this will also exit the loop
                self.banned_peers_count = BannedPeersCount::new();
                None
            } {
                debug!(self.log, "Removing old banned peer"; "peer_id" => %to_drop);
                self.peers.remove(&to_drop);
            }
        }

        // Remove excess disconnected peers
        while self.disconnected_peers > MAX_DC_PEERS {
            if let Some(to_drop) = self
                .peers
                .iter()
                .filter(|(_, info)| info.is_disconnected())
                .filter_map(|(id, info)| match info.connection_status() {
                    PeerConnectionStatus::Disconnected { since } => Some((id, since)),
                    _ => None,
                })
                .min_by_key(|(_, since)| *since)
                .map(|(id, _)| *id)
            {
                debug!(self.log, "Removing old disconnected peer"; "peer_id" => %to_drop);
                self.peers.remove(&to_drop);
            }
            // If there is no minimum, this is a coding error. For safety we decrease
            // the count to avoid a potential infinite loop.
            self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
        }
    }

    /// Add the meta data of a peer.
    pub fn add_metadata(&mut self, peer_id: &PeerId, meta_data: MetaData<TSpec>) {
        if let Some(peer_info) = self.peers.get_mut(peer_id) {
            peer_info.meta_data = Some(meta_data);
        } else {
            warn!(self.log, "Tried to add meta data for a non-existent peer"; "peer_id" => %peer_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::core::Multiaddr;
    use slog::{o, Drain};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use types::MinimalEthSpec;

    type M = MinimalEthSpec;

    pub fn build_log(level: slog::Level, enabled: bool) -> slog::Logger {
        let decorator = slog_term::TermDecorator::new().build();
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        let drain = slog_async::Async::new(drain).build().fuse();

        if enabled {
            slog::Logger::root(drain.filter_level(level).fuse(), o!())
        } else {
            slog::Logger::root(drain.filter(|_| false).fuse(), o!())
        }
    }

    fn add_score<TSpec: EthSpec>(db: &mut PeerDB<TSpec>, peer_id: &PeerId, score: f64) {
        if let Some(info) = db.peer_info_mut(peer_id) {
            info.add_to_score(score);
        }
    }

    fn reset_score<TSpec: EthSpec>(db: &mut PeerDB<TSpec>, peer_id: &PeerId) {
        if let Some(info) = db.peer_info_mut(peer_id) {
            info.reset_score();
        }
    }

    fn get_db() -> PeerDB<M> {
        let log = build_log(slog::Level::Debug, false);
        PeerDB::new(vec![], &log)
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_peer_connected_successfully() {
        let mut pdb = get_db();
        let random_peer = PeerId::random();

        let (n_in, n_out) = (10, 20);
        for _ in 0..n_in {
            pdb.connect_ingoing(&random_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
        }
        for _ in 0..n_out {
            pdb.connect_outgoing(&random_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
        }

        // the peer is known
        let peer_info = pdb.peer_info(&random_peer);
        assert!(peer_info.is_some());
        // this is the only peer
        assert_eq!(pdb.peers().count(), 1);
        // the peer has the default reputation
        assert_eq!(pdb.score(&random_peer), Score::default().score());
        // it should be connected, and therefore not counted as disconnected
        assert_eq!(pdb.disconnected_peers, 0);
        assert!(peer_info.unwrap().is_connected());
        assert_eq!(peer_info.unwrap().connections(), (n_in, n_out));
    }

    #[test]
    fn test_outbound_only_peers_counted_correctly() {
        let mut pdb = get_db();
        let p0 = PeerId::random();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        // Create peer with no connections.
        let _p3 = PeerId::random();

        pdb.connect_ingoing(&p0, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_ingoing(&p1, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_outgoing(&p1, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_outgoing(&p2, "/ip4/0.0.0.0".parse().unwrap(), None);

        // We should only have one outbound-only peer (p2).
        // Peers that are inbound-only, have both types of connections, or no connections should not be counted.
        assert_eq!(pdb.connected_outbound_only_peers().count(), 1);
    }

    #[test]
    fn test_disconnected_are_bounded() {
        let mut pdb = get_db();

        for _ in 0..MAX_DC_PEERS + 1 {
            let p = PeerId::random();
            pdb.connect_ingoing(&p, "/ip4/0.0.0.0".parse().unwrap(), None);
        }
        assert_eq!(pdb.disconnected_peers, 0);

        for p in pdb.connected_peer_ids().cloned().collect::<Vec<_>>() {
            pdb.notify_disconnect(&p);
        }

        assert_eq!(pdb.disconnected_peers, MAX_DC_PEERS);
    }

    #[test]
    fn test_banned_are_bounded() {
        let mut pdb = get_db();

        for _ in 0..MAX_BANNED_PEERS + 1 {
            let p = PeerId::random();
            pdb.connect_ingoing(&p, "/ip4/0.0.0.0".parse().unwrap(), None);
        }
        assert_eq!(pdb.banned_peers_count.banned_peers(), 0);

        for p in pdb.connected_peer_ids().cloned().collect::<Vec<_>>() {
            pdb.disconnect_and_ban(&p);
            pdb.notify_disconnect(&p);
        }

        assert_eq!(pdb.banned_peers_count.banned_peers(), MAX_BANNED_PEERS);
    }

    #[test]
    fn test_best_peers() {
        let mut pdb = get_db();

        let p0 = PeerId::random();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        pdb.connect_ingoing(&p0, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_ingoing(&p1, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_ingoing(&p2, "/ip4/0.0.0.0".parse().unwrap(), None);
        add_score(&mut pdb, &p0, 70.0);
        add_score(&mut pdb, &p1, 100.0);
        add_score(&mut pdb, &p2, 50.0);

        let best_peers: Vec<&PeerId> = pdb
            .best_peers_by_status(PeerInfo::is_connected)
            .iter()
            .map(|p| p.0)
            .collect();
        assert_eq!(vec![&p1, &p0, &p2], best_peers);
    }

    #[test]
    fn test_the_best_peer() {
        let mut pdb = get_db();

        let p0 = PeerId::random();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        pdb.connect_ingoing(&p0, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_ingoing(&p1, "/ip4/0.0.0.0".parse().unwrap(), None);
        pdb.connect_ingoing(&p2, "/ip4/0.0.0.0".parse().unwrap(), None);
        add_score(&mut pdb, &p0, 70.0);
        add_score(&mut pdb, &p1, 100.0);
        add_score(&mut pdb, &p2, 50.0);

        let the_best = pdb.best_by_status(PeerInfo::is_connected);
        assert!(the_best.is_some());
        // Consistency check
        let best_peers = pdb.best_peers_by_status(PeerInfo::is_connected);
        assert_eq!(the_best.unwrap(), best_peers.get(0).unwrap().0);
    }

    #[test]
    fn test_disconnected_consistency() {
        let mut pdb = get_db();

        let random_peer = PeerId::random();

        pdb.connect_ingoing(&random_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());

        pdb.connect_ingoing(&random_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        pdb.notify_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());

        pdb.connect_outgoing(&random_peer, "/ip4/0.0.0.0".parse().unwrap(), None);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        pdb.notify_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());

        pdb.disconnect_and_ban(&random_peer);
        pdb.notify_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        pdb.notify_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());

        pdb.notify_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        pdb.notify_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
    }

    #[test]
    fn test_disconnected_ban_consistency() {
        let mut pdb = get_db();
        let mut multiaddr = Multiaddr::empty();
        multiaddr.push(Protocol::Tcp(9000));
        multiaddr.push(Protocol::Ip4("0.0.0.0".parse().unwrap()));

        let random_peer = PeerId::random();
        let random_peer1 = PeerId::random();
        let random_peer2 = PeerId::random();
        let random_peer3 = PeerId::random();

        pdb.connect_ingoing(&random_peer, multiaddr.clone(), None);
        pdb.connect_ingoing(&random_peer1, multiaddr.clone(), None);
        pdb.connect_ingoing(&random_peer2, multiaddr.clone(), None);
        pdb.connect_ingoing(&random_peer3, multiaddr.clone(), None);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );

        pdb.connect_ingoing(&random_peer, multiaddr.clone(), None);
        pdb.notify_disconnect(&random_peer1);
        pdb.disconnect_and_ban(&random_peer2);
        pdb.notify_disconnect(&random_peer2);
        pdb.connect_ingoing(&random_peer3, multiaddr.clone(), None);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );
        pdb.disconnect_and_ban(&random_peer1);
        pdb.notify_disconnect(&random_peer1);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );

        pdb.connect_outgoing(&random_peer2, multiaddr.clone(), None);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );
        pdb.disconnect_and_ban(&random_peer3);
        pdb.notify_disconnect(&random_peer3);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );

        pdb.disconnect_and_ban(&random_peer3);
        pdb.notify_disconnect(&random_peer3);
        pdb.connect_ingoing(&random_peer1, multiaddr.clone(), None);
        pdb.notify_disconnect(&random_peer2);
        pdb.disconnect_and_ban(&random_peer3);
        pdb.notify_disconnect(&random_peer3);
        pdb.connect_ingoing(&random_peer, multiaddr, None);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );
        pdb.notify_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );

        pdb.notify_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(
            pdb.banned_peers_count.banned_peers(),
            pdb.banned_peers().count()
        );
        pdb.disconnect_and_ban(&random_peer);
        pdb.notify_disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
    }

    fn connect_peer_with_ips(pdb: &mut PeerDB<M>, ips: Vec<IpAddr>) -> PeerId {
        let p = PeerId::random();

        for ip in ips {
            let mut addr = Multiaddr::empty();
            addr.push(Protocol::from(ip));
            addr.push(Protocol::Tcp(9000));
            pdb.connect_ingoing(&p, addr, None);
        }
        p
    }

    #[test]
    fn test_ban_address() {
        let mut pdb = get_db();

        let ip1 = Ipv4Addr::new(1, 2, 3, 4).into();
        let ip2 = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8).into();
        let ip3 = Ipv4Addr::new(1, 2, 3, 5).into();
        let ip4 = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 9).into();
        let ip5 = Ipv4Addr::new(2, 2, 3, 4).into();

        let mut peers = Vec::new();
        for i in 0..BANNED_PEERS_PER_IP_THRESHOLD + 2 {
            peers.push(connect_peer_with_ips(
                &mut pdb,
                if i == 0 {
                    vec![ip1, ip2]
                } else {
                    vec![ip1, ip2, ip3, ip4]
                },
            ));
        }

        let p1 = connect_peer_with_ips(&mut pdb, vec![ip1]);
        let p2 = connect_peer_with_ips(&mut pdb, vec![ip2, ip5]);
        let p3 = connect_peer_with_ips(&mut pdb, vec![ip3, ip5]);
        let p4 = connect_peer_with_ips(&mut pdb, vec![ip5, ip4]);
        let p5 = connect_peer_with_ips(&mut pdb, vec![ip5]);

        for p in &peers[..BANNED_PEERS_PER_IP_THRESHOLD + 1] {
            pdb.disconnect_and_ban(p);
            pdb.notify_disconnect(p);
        }

        //check that ip1 and ip2 are banned but ip3-5 not
        assert!(pdb.is_banned(&p1));
        assert!(pdb.is_banned(&p2));
        assert!(!pdb.is_banned(&p3));
        assert!(!pdb.is_banned(&p4));
        assert!(!pdb.is_banned(&p5));

        //ban also the last peer in peers
        pdb.disconnect_and_ban(&peers[BANNED_PEERS_PER_IP_THRESHOLD + 1]);
        pdb.notify_disconnect(&peers[BANNED_PEERS_PER_IP_THRESHOLD + 1]);

        //check that ip1-ip4 are banned but ip5 not
        assert!(pdb.is_banned(&p1));
        assert!(pdb.is_banned(&p2));
        assert!(pdb.is_banned(&p3));
        assert!(pdb.is_banned(&p4));
        assert!(!pdb.is_banned(&p5));

        //peers[0] gets unbanned
        reset_score(&mut pdb, &peers[0]);
        pdb.unban(&peers[0]).unwrap();

        //nothing changed
        assert!(pdb.is_banned(&p1));
        assert!(pdb.is_banned(&p2));
        assert!(pdb.is_banned(&p3));
        assert!(pdb.is_banned(&p4));
        assert!(!pdb.is_banned(&p5));

        //peers[1] gets unbanned
        reset_score(&mut pdb, &peers[1]);
        pdb.unban(&peers[1]).unwrap();

        //all ips are unbanned
        assert!(!pdb.is_banned(&p1));
        assert!(!pdb.is_banned(&p2));
        assert!(!pdb.is_banned(&p3));
        assert!(!pdb.is_banned(&p4));
        assert!(!pdb.is_banned(&p5));
    }

    #[test]
    fn test_banned_ip_consistent_after_changing_ips() {
        let mut pdb = get_db();

        let ip1: IpAddr = Ipv4Addr::new(1, 2, 3, 4).into();
        let ip2: IpAddr = Ipv6Addr::new(1, 2, 3, 4, 5, 6, 7, 8).into();

        let mut peers = Vec::new();
        for _ in 0..BANNED_PEERS_PER_IP_THRESHOLD + 1 {
            peers.push(connect_peer_with_ips(&mut pdb, vec![ip1]));
        }

        let p1 = connect_peer_with_ips(&mut pdb, vec![ip1]);
        let p2 = connect_peer_with_ips(&mut pdb, vec![ip2]);

        // ban all peers
        for p in &peers {
            pdb.disconnect_and_ban(p);
            pdb.notify_disconnect(p);
        }

        // check ip is banned
        assert!(pdb.is_banned(&p1));
        assert!(!pdb.is_banned(&p2));

        // unban a peer
        reset_score(&mut pdb, &peers[0]);
        pdb.unban(&peers[0]).unwrap();

        // check not banned anymore
        assert!(!pdb.is_banned(&p1));
        assert!(!pdb.is_banned(&p2));

        // add ip2 to all peers and ban them.
        let mut socker_addr = Multiaddr::from(ip2);
        socker_addr.push(Protocol::Tcp(8080));
        for p in &peers {
            pdb.connect_ingoing(&p, socker_addr.clone(), None);
            pdb.disconnect_and_ban(p);
            pdb.notify_disconnect(p);
        }

        // both IP's are now banned
        assert!(pdb.is_banned(&p1));
        assert!(pdb.is_banned(&p2));

        // unban all peers
        for p in &peers {
            reset_score(&mut pdb, &p);
            pdb.unban(p).unwrap();
        }

        // reban every peer except one
        for p in &peers[1..] {
            pdb.disconnect_and_ban(p);
            pdb.notify_disconnect(p);
        }

        // nothing is banned
        assert!(!pdb.is_banned(&p1));
        assert!(!pdb.is_banned(&p2));

        //reban last peer
        pdb.disconnect_and_ban(&peers[0]);
        pdb.notify_disconnect(&peers[0]);

        //Ip's are banned again
        assert!(pdb.is_banned(&p1));
        assert!(pdb.is_banned(&p2));
    }

    #[test]
    #[allow(clippy::float_cmp)]
    fn test_trusted_peers_score() {
        let trusted_peer = PeerId::random();
        let log = build_log(slog::Level::Debug, false);
        let mut pdb: PeerDB<M> = PeerDB::new(vec![trusted_peer], &log);

        pdb.connect_ingoing(&trusted_peer, "/ip4/0.0.0.0".parse().unwrap(), None);

        // Check trusted status and score
        assert!(pdb.peer_info(&trusted_peer).unwrap().is_trusted);
        assert_eq!(
            pdb.peer_info(&trusted_peer).unwrap().score().score(),
            Score::max_score().score()
        );

        // Adding/Subtracting score should have no effect on a trusted peer
        add_score(&mut pdb, &trusted_peer, -50.0);

        assert_eq!(
            pdb.peer_info(&trusted_peer).unwrap().score().score(),
            Score::max_score().score()
        );
    }
}
