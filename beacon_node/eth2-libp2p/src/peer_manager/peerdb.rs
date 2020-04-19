use super::peer_info::{PeerConnectionStatus, PeerInfo, PeerSyncStatus};
use crate::rpc::methods::MetaData;
use crate::PeerId;
use slog::{crit, warn};
use std::collections::HashMap;
use types::{EthSpec, SubnetId};

/// A peer's reputation.
pub type Rep = i32;

/// Max number of disconnected nodes to remember
const MAX_DC_PEERS: usize = 30;
/// The default starting reputation for an unknown peer.
pub const DEFAULT_REPUTATION: Rep = 50;

/// Storage of known peers, their reputation and information
pub struct PeerDB<TSpec: EthSpec> {
    /// The collection of known connected peers, their status and reputation
    peers: HashMap<PeerId, PeerInfo<TSpec>>,
    /// Tracking of number of disconnected nodes
    n_dc: usize,
    /// PeerDB's logger
    log: slog::Logger,
}

impl<TSpec: EthSpec> PeerDB<TSpec> {
    pub fn new(log: &slog::Logger) -> Self {
        Self {
            log: log.clone(),
            n_dc: 0,
            peers: HashMap::new(),
        }
    }

    /* Getters */

    /// Gives the reputation of a peer, or DEFAULT_REPUTATION if it is unknown.
    pub fn reputation(&self, peer_id: &PeerId) -> Rep {
        self.peers
            .get(peer_id)
            .map_or(DEFAULT_REPUTATION, |info| info.reputation)
    }

    /// Gives the ids of all known peers.
    pub fn peers(&self) -> impl Iterator<Item = &PeerId> {
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

    /// Returns true if the peer is synced at least to our current head.
    pub fn peer_synced(&self, peer_id: &PeerId) -> bool {
        match self.peers.get(peer_id).map(|info| &info.sync_status) {
            Some(PeerSyncStatus::Synced { .. }) => true,
            Some(_) => false,
            None => false,
        }
    }

    /// Gives the ids of all known connected peers.
    pub fn connected_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| info.connection_status.is_connected())
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives the `peer_id` of all known connected and synced peers.
    pub fn synced_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.peers
            .iter()
            .filter(|(_, info)| {
                if let PeerSyncStatus::Synced { .. } = info.sync_status {
                    return info.connection_status.is_connected();
                }
                false
            })
            .map(|(peer_id, _)| peer_id)
    }

    /// Gives an iterator of all peers on a given subnet.
    pub fn peers_on_subnet(&self, subnet_id: &SubnetId) -> impl Iterator<Item = &PeerId> {
        let subnet_id_filter = subnet_id.clone();
        self.peers
            .iter()
            .filter(move |(_, info)| {
                info.connection_status.is_connected() && info.on_subnet(subnet_id_filter)
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

    /// Returns a vector containing peers (their ids and info), sorted by
    /// reputation from highest to lowest, and filtered using `is_status`
    pub fn best_peers_by_status<F>(&self, is_status: F) -> Vec<(&PeerId, &PeerInfo<TSpec>)>
    where
        F: Fn(&PeerConnectionStatus) -> bool,
    {
        let mut by_status = self
            .peers
            .iter()
            .filter(|(_, info)| is_status(&info.connection_status))
            .collect::<Vec<_>>();
        by_status.sort_by_key(|(_, info)| Rep::max_value() - info.reputation);
        by_status
    }

    /// Returns the peer with highest reputation that satisfies `is_status`
    pub fn best_by_status<F>(&self, is_status: F) -> Option<&PeerId>
    where
        F: Fn(&PeerConnectionStatus) -> bool,
    {
        self.peers
            .iter()
            .filter(|(_, info)| is_status(&info.connection_status))
            .max_by_key(|(_, info)| info.reputation)
            .map(|(id, _)| id)
    }

    /// Returns the peer's connection status. Returns unknown if the peer is not in the DB.
    pub fn connection_status(&self, peer_id: &PeerId) -> PeerConnectionStatus {
        self.peer_info(peer_id)
            .map_or(PeerConnectionStatus::default(), |info| {
                info.connection_status.clone()
            })
    }

    /// Returns if the peer is already connected.
    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        if let PeerConnectionStatus::Connected { .. } = self.connection_status(peer_id) {
            true
        } else {
            false
        }
    }

    /* Setters */

    /// Sets a peer as connected with an ingoing connection
    pub fn connect_ingoing(&mut self, peer_id: &PeerId) {
        let info = self
            .peers
            .entry(peer_id.clone())
            .or_insert_with(|| Default::default());

        if info.connection_status.is_disconnected() {
            self.n_dc -= 1;
        }
        info.connection_status.connect_ingoing();
    }

    /// Sets a peer as connected with an outgoing connection
    pub fn connect_outgoing(&mut self, peer_id: &PeerId) {
        let info = self
            .peers
            .entry(peer_id.clone())
            .or_insert_with(|| Default::default());

        if info.connection_status.is_disconnected() {
            self.n_dc -= 1;
        }
        info.connection_status.connect_outgoing();
    }

    /// Sets the peer as disconnected
    pub fn disconnect(&mut self, peer_id: &PeerId) {
        let log_ref = &self.log;
        let info = self.peers.entry(peer_id.clone()).or_insert_with(|| {
            warn!(log_ref, "Disconnecting unknown peer";
                    "peer_id" => format!("{:?}",peer_id));
            PeerInfo::default()
        });

        if !info.connection_status.is_disconnected() {
            info.connection_status.disconnect();
            self.n_dc += 1;
        }
        self.shrink_to_fit();
    }

    /// Drops the peers with the lowest reputation so that the number of
    /// disconnected peers is less than MAX_DC_PEERS
    pub fn shrink_to_fit(&mut self) {
        // for caution, but the difference should never be > 1
        while self.n_dc > MAX_DC_PEERS {
            let to_drop = self
                .peers
                .iter()
                .filter(|(_, info)| info.connection_status.is_disconnected())
                .min_by_key(|(_, info)| info.reputation)
                .map(|(id, _)| id.clone())
                .unwrap(); // should be safe since n_dc > MAX_DC_PEERS > 0
            self.peers.remove(&to_drop);
            self.n_dc -= 1;
        }
    }

    /// Sets a peer as banned
    pub fn ban(&mut self, peer_id: &PeerId) {
        let log_ref = &self.log;
        let info = self.peers.entry(peer_id.clone()).or_insert_with(|| {
            warn!(log_ref, "Banning unknown peer";
                    "peer_id" => format!("{:?}",peer_id));
            PeerInfo::default()
        });
        if info.connection_status.is_disconnected() {
            self.n_dc -= 1;
        }
        info.connection_status.ban();
    }

    /// Add the meta data of a peer.
    pub fn add_metadata(&mut self, peer_id: &PeerId, meta_data: MetaData<TSpec>) {
        if let Some(peer_info) = self.peers.get_mut(peer_id) {
            peer_info.meta_data = Some(meta_data);
        } else {
            warn!(self.log, "Tried to add meta data for a non-existant peer"; "peer_id" => format!("{}", peer_id));
        }
    }

    /// Sets the reputation of peer.
    pub fn set_reputation(&mut self, peer_id: &PeerId, rep: Rep) {
        if let Some(peer_info) = self.peers.get_mut(peer_id) {
            peer_info.reputation = rep;
        } else {
            crit!(self.log, "Tried to modify reputation for an unknown peer"; "peer_id" => format!("{}",peer_id));
        }
    }

    /// Sets the syncing status of a peer.
    pub fn set_sync_status(&mut self, peer_id: &PeerId, sync_status: PeerSyncStatus) {
        if let Some(peer_info) = self.peers.get_mut(peer_id) {
            peer_info.sync_status = sync_status;
        } else {
            crit!(self.log, "Tried to the sync status for an unknown peer"; "peer_id" => format!("{}",peer_id));
        }
    }

    /// Adds to a peer's reputation by `change`. If the reputation exceeds Rep's
    /// upper (lower) bounds, it stays at the maximum (minimum) value.
    pub fn add_reputation(&mut self, peer_id: &PeerId, change: Rep) {
        let log_ref = &self.log;
        let info = self.peers.entry(peer_id.clone()).or_insert_with(|| {
            warn!(log_ref, "Adding to the reputation of an unknown peer";
                    "peer_id" => format!("{:?}",peer_id));
            PeerInfo::default()
        });
        info.reputation = info.reputation.saturating_add(change);
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

    fn get_db() -> PeerDB<M> {
        let log = build_log(slog::Level::Debug, true);
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
        assert_eq!(pdb.reputation(&random_peer), DEFAULT_REPUTATION);
        // it should be connected, and therefore not counted as disconnected
        assert_eq!(pdb.n_dc, 0);
        assert!(peer_info.unwrap().connection_status.is_connected());
        assert_eq!(
            peer_info.unwrap().connection_status.connections(),
            (n_in, n_out)
        );
    }

    #[test]
    fn test_set_reputation() {
        let mut pdb = get_db();
        let random_peer = PeerId::random();
        pdb.connect_ingoing(&random_peer);

        let mut rep = Rep::min_value();
        pdb.set_reputation(&random_peer, rep);
        assert_eq!(pdb.reputation(&random_peer), rep);

        rep = Rep::max_value();
        pdb.set_reputation(&random_peer, rep);
        assert_eq!(pdb.reputation(&random_peer), rep);

        rep = Rep::max_value() / 100;
        pdb.set_reputation(&random_peer, rep);
        assert_eq!(pdb.reputation(&random_peer), rep);
    }

    #[test]
    fn test_reputation_change() {
        let mut pdb = get_db();

        // 0 change does not change de reputation
        let random_peer = PeerId::random();
        let change: Rep = 0;
        pdb.connect_ingoing(&random_peer);
        pdb.add_reputation(&random_peer, change);
        assert_eq!(pdb.reputation(&random_peer), DEFAULT_REPUTATION);

        // overflowing change is capped
        let random_peer = PeerId::random();
        let change = Rep::max_value();
        pdb.connect_ingoing(&random_peer);
        pdb.add_reputation(&random_peer, change);
        assert_eq!(pdb.reputation(&random_peer), Rep::max_value());
    }

    #[test]
    fn test_disconnected_are_bounded() {
        let mut pdb = get_db();

        for _ in 0..MAX_DC_PEERS + 1 {
            let p = PeerId::random();
            pdb.connect_ingoing(&p);
        }
        assert_eq!(pdb.n_dc, 0);

        for p in pdb.connected_peers().cloned().collect::<Vec<_>>() {
            pdb.disconnect(&p);
        }

        assert_eq!(pdb.n_dc, MAX_DC_PEERS);
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
        pdb.set_reputation(&p0, 70);
        pdb.set_reputation(&p1, 100);
        pdb.set_reputation(&p2, 50);

        let best_peers = pdb.best_peers_by_status(PeerConnectionStatus::is_connected);
        assert!(vec![&p1, &p0, &p2]
            .into_iter()
            .eq(best_peers.into_iter().map(|p| p.0)));
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
        pdb.set_reputation(&p0, 70);
        pdb.set_reputation(&p1, 100);
        pdb.set_reputation(&p2, 50);

        let the_best = pdb.best_by_status(PeerConnectionStatus::is_connected);
        assert!(the_best.is_some());
        // Consistency check
        let best_peers = pdb.best_peers_by_status(PeerConnectionStatus::is_connected);
        assert_eq!(the_best, best_peers.into_iter().map(|p| p.0).next());
    }

    #[test]
    fn test_disconnected_consistency() {
        let mut pdb = get_db();

        let random_peer = PeerId::random();

        pdb.connect_ingoing(&random_peer);
        assert_eq!(pdb.n_dc, pdb.disconnected_peers().count());

        pdb.connect_ingoing(&random_peer);
        assert_eq!(pdb.n_dc, pdb.disconnected_peers().count());
        pdb.disconnect(&random_peer);
        assert_eq!(pdb.n_dc, pdb.disconnected_peers().count());

        pdb.connect_outgoing(&random_peer);
        assert_eq!(pdb.n_dc, pdb.disconnected_peers().count());
        pdb.disconnect(&random_peer);
        assert_eq!(pdb.n_dc, pdb.disconnected_peers().count());

        pdb.ban(&random_peer);
        assert_eq!(pdb.n_dc, pdb.disconnected_peers().count());
        pdb.disconnect(&random_peer);
        assert_eq!(pdb.n_dc, pdb.disconnected_peers().count());

        pdb.disconnect(&random_peer);
        assert_eq!(pdb.n_dc, pdb.disconnected_peers().count());
        pdb.disconnect(&random_peer);
        assert_eq!(pdb.n_dc, pdb.disconnected_peers().count());
    }
}
