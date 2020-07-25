use super::peer_info::{PeerConnectionStatus, PeerInfo};
use super::peer_sync_status::PeerSyncStatus;
use super::score::Score;
use crate::rpc::methods::MetaData;
use crate::PeerId;
use rand::seq::SliceRandom;
use slog::{crit, debug, trace, warn};
use std::collections::HashMap;
use std::time::Instant;
use types::{EthSpec, SubnetId};

/// Max number of disconnected nodes to remember.
const MAX_DC_PEERS: usize = 100;
/// The maximum number of banned nodes to remember.
const MAX_BANNED_PEERS: usize = 300;

/// Storage of known peers, their reputation and information
pub struct PeerDB<TSpec: EthSpec> {
    /// The collection of known connected peers, their status and reputation
    peers: HashMap<PeerId, PeerInfo<TSpec>>,
    /// The number of disconnected nodes in the database.
    disconnected_peers: usize,
    /// The number of banned peers in the database.
    banned_peers: usize,
    /// PeerDB's logger
    log: slog::Logger,
}

impl<TSpec: EthSpec> PeerDB<TSpec> {
    pub fn new(log: &slog::Logger) -> Self {
        Self {
            log: log.clone(),
            disconnected_peers: 0,
            banned_peers: 0,
            peers: HashMap::new(),
        }
    }

    /* Getters */

    /// Gives the score of a peer, or default score if it is unknown.
    pub fn score(&self, peer_id: &PeerId) -> Score {
        self.peers
            .get(peer_id)
            .map_or(Score::default(), |info| info.score)
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
    /// TODO: make pub(super) to ensure that peer management is unified
    pub fn peer_info_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo<TSpec>> {
        self.peers.get_mut(peer_id)
    }

    /// Returns if the peer is already connected.
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        if let Some(PeerConnectionStatus::Connected { .. }) = self.connection_status(peer_id) {
            true
        } else {
            false
        }
    }

    /// If we are connected or currently dialing the peer returns true.
    pub fn is_connected_or_dialing(&self, peer_id: &PeerId) -> bool {
        match self.connection_status(peer_id) {
            Some(PeerConnectionStatus::Connected { .. })
            | Some(PeerConnectionStatus::Dialing { .. }) => true,
            _ => false,
        }
    }
    /// Returns true if the peer is synced at least to our current head.
    pub fn is_synced(&self, peer_id: &PeerId) -> bool {
        match self.peers.get(peer_id).map(|info| &info.sync_status) {
            Some(PeerSyncStatus::Synced { .. }) => true,
            Some(_) => false,
            None => false,
        }
    }

    /// Returns true if the Peer is banned.
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        match self.peers.get(peer_id).map(|info| &info.connection_status) {
            Some(status) => status.is_banned(),
            None => false,
        }
    }

    /// Gives the ids of all known connected peers.
    pub fn connected_peers(&self) -> impl Iterator<Item = (&PeerId, &PeerInfo<TSpec>)> {
        self.peers
            .iter()
            .filter(|(_, info)| info.connection_status.is_connected())
    }

    /// Gives the ids of all known connected peers.
    pub fn connected_peer_ids(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.connection_status.is_connected())
            .map(|(peer_id, _)| peer_id)
    }

    /// Connected or dialing peers
    pub fn connected_or_dialing_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| {
                info.connection_status.is_connected() || info.connection_status.is_dialing()
            })
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives the `peer_id` of all known connected and synced peers.
    pub fn synced_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| {
                if info.sync_status.is_synced() || info.sync_status.is_advanced() {
                    return info.connection_status.is_connected();
                }
                false
            })
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives an iterator of all peers on a given subnet.
    pub fn peers_on_subnet(&self, subnet_id: SubnetId) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(move |(_, info)| {
                info.connection_status.is_connected() && info.on_subnet(subnet_id)
            })
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives the ids of all known disconnected peers.
    pub fn disconnected_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.connection_status.is_disconnected())
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives the ids of all known banned peers.
    pub fn banned_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.connection_status.is_banned())
            .map(|(peer_id, _)| peer_id)
    }

    /// Returns a vector of all connected peers sorted by score beginning with the worst scores.
    /// Ties get broken randomly.
    pub fn worst_connected_peers(&self) -> Vec<(&PeerId, &PeerInfo<TSpec>)> {
        let mut connected = self
            .peers
            .iter()
            .filter(|(_, info)| info.connection_status.is_connected())
            .collect::<Vec<_>>();

        connected.shuffle(&mut rand::thread_rng());
        connected.sort_by_key(|(_, info)| info.score);
        connected
    }

    /// Returns a vector containing peers (their ids and info), sorted by
    /// score from highest to lowest, and filtered using `is_status`
    pub fn best_peers_by_status<F>(&self, is_status: F) -> Vec<(&PeerId, &PeerInfo<TSpec>)>
    where
        F: Fn(&PeerConnectionStatus) -> bool,
    {
        let mut by_status = self
            .peers
            .iter()
            .filter(|(_, info)| is_status(&info.connection_status))
            .collect::<Vec<_>>();
        by_status.sort_by_key(|(_, info)| info.score);
        by_status.into_iter().rev().collect()
    }

    /// Returns the peer with highest reputation that satisfies `is_status`
    pub fn best_by_status<F>(&self, is_status: F) -> Option<&PeerId>
    where
        F: Fn(&PeerConnectionStatus) -> bool,
    {
        self.peers
            .iter()
            .filter(|(_, info)| is_status(&info.connection_status))
            .max_by_key(|(_, info)| info.score)
            .map(|(id, _)| id)
    }

    /// Returns the peer's connection status. Returns unknown if the peer is not in the DB.
    pub fn connection_status(&self, peer_id: &PeerId) -> Option<PeerConnectionStatus> {
        self.peer_info(peer_id)
            .map(|info| info.connection_status.clone())
    }

    /* Setters */

    /// A peer is being dialed.
    pub fn dialing_peer(&mut self, peer_id: &PeerId) {
        let info = self.peers.entry(peer_id.clone()).or_default();

        if info.connection_status.is_disconnected() {
            self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
        }
        if info.connection_status.is_banned() {
            self.banned_peers = self.banned_peers.saturating_sub(1);
        }
        info.connection_status = PeerConnectionStatus::Dialing {
            since: Instant::now(),
        };
    }

    /// Update min ttl of a peer.
    pub fn update_min_ttl(&mut self, peer_id: &PeerId, min_ttl: Instant) {
        let info = self.peers.entry(peer_id.clone()).or_default();

        // only update if the ttl is longer
        if info.min_ttl.is_none() || Some(min_ttl) > info.min_ttl {
            info.min_ttl = Some(min_ttl);

            let min_ttl_secs = min_ttl
                .checked_duration_since(Instant::now())
                .map(|duration| duration.as_secs())
                .unwrap_or_else(|| 0);
            debug!(self.log, "Updating the time a peer is required for"; "peer_id" => peer_id.to_string(), "future_min_ttl_secs" => min_ttl_secs);
        }
    }

    /// Extends the ttl of all peers on the given subnet that have a shorter
    /// min_ttl than what's given.
    pub fn extend_peers_on_subnet(&mut self, subnet_id: SubnetId, min_ttl: Instant) {
        let log = &self.log;
        self.peers.iter_mut()
            .filter(move |(_, info)| {
                info.connection_status.is_connected() && info.on_subnet(subnet_id)
            })
            .for_each(|(peer_id,info)| {
                if info.min_ttl.is_none() || Some(min_ttl) > info.min_ttl {
                    info.min_ttl = Some(min_ttl);
                }
                let min_ttl_secs = min_ttl
                    .checked_duration_since(Instant::now())
                    .map(|duration| duration.as_secs())
                    .unwrap_or_else(|| 0);
                trace!(log, "Updating minimum duration a peer is required for"; "peer_id" => peer_id.to_string(), "min_ttl" => min_ttl_secs);
            });
    }

    /// Sets a peer as connected with an ingoing connection.
    pub fn connect_ingoing(&mut self, peer_id: &PeerId) {
        let info = self.peers.entry(peer_id.clone()).or_default();

        if info.connection_status.is_disconnected() {
            self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
        }
        if info.connection_status.is_banned() {
            self.banned_peers = self.banned_peers.saturating_sub(1);
        }
        info.connection_status.connect_ingoing();
    }

    /// Sets a peer as connected with an outgoing connection.
    pub fn connect_outgoing(&mut self, peer_id: &PeerId) {
        let info = self.peers.entry(peer_id.clone()).or_default();

        if info.connection_status.is_disconnected() {
            self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
        }
        if info.connection_status.is_banned() {
            self.banned_peers = self.banned_peers.saturating_sub(1);
        }
        info.connection_status.connect_outgoing();
    }

    /// Sets the peer as disconnected. A banned peer remains banned
    pub fn disconnect(&mut self, peer_id: &PeerId) {
        let log_ref = &self.log;
        let info = self.peers.entry(peer_id.clone()).or_insert_with(|| {
            warn!(log_ref, "Disconnecting unknown peer";
                "peer_id" => peer_id.to_string());
            PeerInfo::default()
        });
        if !info.connection_status.is_disconnected() && !info.connection_status.is_banned() {
            info.connection_status.disconnect();
            self.disconnected_peers += 1;
        }
        self.shrink_to_fit();
    }

    /// Marks a peer as banned.
    pub fn ban(&mut self, peer_id: &PeerId) {
        let log_ref = &self.log;
        let info = self.peers.entry(peer_id.clone()).or_insert_with(|| {
            warn!(log_ref, "Banning unknown peer";
                "peer_id" => peer_id.to_string());
            PeerInfo::default()
        });

        if info.connection_status.is_disconnected() {
            self.disconnected_peers = self.disconnected_peers.saturating_sub(1);
        }
        if !info.connection_status.is_banned() {
            info.connection_status.ban();
            self.banned_peers += 1;
        }
        self.shrink_to_fit();
    }

    /// Unbans a peer.
    pub fn unban(&mut self, peer_id: &PeerId) {
        let log_ref = &self.log;
        let info = self.peers.entry(peer_id.clone()).or_insert_with(|| {
            warn!(log_ref, "UnBanning unknown peer";
                "peer_id" => peer_id.to_string());
            PeerInfo::default()
        });

        if info.connection_status.is_banned() {
            info.connection_status.unban();
            self.banned_peers = self.banned_peers.saturating_sub(1);
        }
        self.shrink_to_fit();
    }

    /// Removes banned and disconnected peers from the DB if we have reached any of our limits.
    /// Drops the peers with the lowest reputation so that the number of
    /// disconnected peers is less than MAX_DC_PEERS
    pub fn shrink_to_fit(&mut self) {
        // Remove excess baned peers
        while self.banned_peers > MAX_BANNED_PEERS {
            if let Some(to_drop) = self
                .peers
                .iter()
                .filter(|(_, info)| info.connection_status.is_banned())
                .min_by(|(_, info_a), (_, info_b)| {
                    info_a
                        .score
                        .partial_cmp(&info_b.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(id, _)| id.clone())
            {
                debug!(self.log, "Removing old banned peer"; "peer_id" => to_drop.to_string());
                self.peers.remove(&to_drop);
            }
            // If there is no minimum, this is a coding error. For safety we decrease
            // the count to avoid a potential infinite loop.
            self.banned_peers = self.banned_peers.saturating_sub(1);
        }

        // Remove excess disconnected peers
        while self.disconnected_peers > MAX_DC_PEERS {
            if let Some(to_drop) = self
                .peers
                .iter()
                .filter(|(_, info)| info.connection_status.is_disconnected())
                .min_by(|(_, info_a), (_, info_b)| {
                    info_a
                        .score
                        .partial_cmp(&info_b.score)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .map(|(id, _)| id.clone())
            {
                debug!(self.log, "Removing old disconnected peer"; "peer_id" => to_drop.to_string());
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
            warn!(self.log, "Tried to add meta data for a non-existant peer"; "peer_id" => peer_id.to_string());
        }
    }

    /// Sets the syncing status of a peer.
    pub fn set_sync_status(&mut self, peer_id: &PeerId, sync_status: PeerSyncStatus) {
        if let Some(peer_info) = self.peers.get_mut(peer_id) {
            peer_info.sync_status = sync_status;
        } else {
            crit!(self.log, "Tried to the sync status for an unknown peer"; "peer_id" => peer_id.to_string());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use slog::{o, Drain};
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
            info.score.add(score);
        }
    }

    fn get_db() -> PeerDB<M> {
        let log = build_log(slog::Level::Debug, false);
        PeerDB::new(&log)
    }

    #[test]
    fn test_peer_connected_successfully() {
        let mut pdb = get_db();
        let random_peer = PeerId::random();

        let (n_in, n_out) = (10, 20);
        for _ in 0..n_in {
            pdb.connect_ingoing(&random_peer);
        }
        for _ in 0..n_out {
            pdb.connect_outgoing(&random_peer);
        }

        // the peer is known
        let peer_info = pdb.peer_info(&random_peer);
        assert!(peer_info.is_some());
        // this is the only peer
        assert_eq!(pdb.peers().count(), 1);
        // the peer has the default reputation
        assert_eq!(pdb.score(&random_peer).score(), Score::default().score());
        // it should be connected, and therefore not counted as disconnected
        assert_eq!(pdb.disconnected_peers, 0);
        assert!(peer_info.unwrap().connection_status.is_connected());
        assert_eq!(
            peer_info.unwrap().connection_status.connections(),
            (n_in, n_out)
        );
    }

    #[test]
    fn test_disconnected_are_bounded() {
        let mut pdb = get_db();

        for _ in 0..MAX_DC_PEERS + 1 {
            let p = PeerId::random();
            pdb.connect_ingoing(&p);
        }
        assert_eq!(pdb.disconnected_peers, 0);

        for p in pdb.connected_peer_ids().cloned().collect::<Vec<_>>() {
            pdb.disconnect(&p);
        }

        assert_eq!(pdb.disconnected_peers, MAX_DC_PEERS);
    }

    #[test]
    fn test_banned_are_bounded() {
        let mut pdb = get_db();

        for _ in 0..MAX_BANNED_PEERS + 1 {
            let p = PeerId::random();
            pdb.connect_ingoing(&p);
        }
        assert_eq!(pdb.banned_peers, 0);

        for p in pdb.connected_peer_ids().cloned().collect::<Vec<_>>() {
            pdb.ban(&p);
        }

        assert_eq!(pdb.banned_peers, MAX_BANNED_PEERS);
    }

    #[test]
    fn test_best_peers() {
        let mut pdb = get_db();

        let p0 = PeerId::random();
        let p1 = PeerId::random();
        let p2 = PeerId::random();
        pdb.connect_ingoing(&p0);
        pdb.connect_ingoing(&p1);
        pdb.connect_ingoing(&p2);
        add_score(&mut pdb, &p0, 70.0);
        add_score(&mut pdb, &p1, 100.0);
        add_score(&mut pdb, &p2, 50.0);

        let best_peers: Vec<&PeerId> = pdb
            .best_peers_by_status(PeerConnectionStatus::is_connected)
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
        pdb.connect_ingoing(&p0);
        pdb.connect_ingoing(&p1);
        pdb.connect_ingoing(&p2);
        add_score(&mut pdb, &p0, 70.0);
        add_score(&mut pdb, &p1, 100.0);
        add_score(&mut pdb, &p2, 50.0);

        let the_best = pdb.best_by_status(PeerConnectionStatus::is_connected);
        assert!(the_best.is_some());
        // Consistency check
        let best_peers = pdb.best_peers_by_status(PeerConnectionStatus::is_connected);
        assert_eq!(the_best, best_peers.iter().next().map(|p| p.0));
    }

    #[test]
    fn test_disconnected_consistency() {
        let mut pdb = get_db();

        let random_peer = PeerId::random();

        pdb.connect_ingoing(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        dbg!("1");

        pdb.connect_ingoing(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        dbg!("1");
        pdb.disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        dbg!("1");

        pdb.connect_outgoing(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        dbg!("1");
        pdb.disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        dbg!("1");

        pdb.ban(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        dbg!("1");
        pdb.disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        dbg!("1");

        pdb.disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        dbg!("1");
        pdb.disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        dbg!("1");
    }

    #[test]
    fn test_disconnected_ban_consistency() {
        let mut pdb = get_db();

        let random_peer = PeerId::random();
        let random_peer1 = PeerId::random();
        let random_peer2 = PeerId::random();
        let random_peer3 = PeerId::random();

        pdb.connect_ingoing(&random_peer);
        pdb.connect_ingoing(&random_peer1);
        pdb.connect_ingoing(&random_peer2);
        pdb.connect_ingoing(&random_peer3);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(pdb.banned_peers, pdb.banned_peers().count());

        pdb.connect_ingoing(&random_peer);
        pdb.disconnect(&random_peer1);
        pdb.ban(&random_peer2);
        pdb.connect_ingoing(&random_peer3);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(pdb.banned_peers, pdb.banned_peers().count());
        pdb.ban(&random_peer1);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(pdb.banned_peers, pdb.banned_peers().count());

        pdb.connect_outgoing(&random_peer2);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(pdb.banned_peers, pdb.banned_peers().count());
        pdb.ban(&random_peer3);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(pdb.banned_peers, pdb.banned_peers().count());

        pdb.ban(&random_peer3);
        pdb.connect_ingoing(&random_peer1);
        pdb.disconnect(&random_peer2);
        pdb.ban(&random_peer3);
        pdb.connect_ingoing(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(pdb.banned_peers, pdb.banned_peers().count());
        pdb.disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(pdb.banned_peers, pdb.banned_peers().count());

        pdb.disconnect(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
        assert_eq!(pdb.banned_peers, pdb.banned_peers().count());
        pdb.ban(&random_peer);
        assert_eq!(pdb.disconnected_peers, pdb.disconnected_peers().count());
    }
}
