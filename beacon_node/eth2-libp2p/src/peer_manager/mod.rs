//! Implementation of a Lighthouse's peer management system.

use crate::PeerId;
use slog::warn;
use smallvec::SmallVec;
use std::collections::HashMap;

/// The default starting reputation for an unknown peer.
const DEFAULT_REPUTATION: usize = 50;

/// The minimum reputation before a peer is disconnected.
const MINIMUM_REPUTATION_BEFORE_DISCONNECT: usize = 20;

/// The main struct that handles peer's reputation and connection status.
pub struct PeerManager {
    /// The collection of known connected peers, their status and their reputation.
    connected_peers: HashMap<PeerId, PeerInfo>,

    /// A collection of known banned peers, their status and reputation
    banned_peers: HashMap<PeerId, PeerInfo>,

    /// A queue of events that the `PeerManager` is waiting to produce.
    events: SmallVec<[PeerManagerEvent; 5]>,

    /// The logger associated with the `PeerManager`.
    log: slog::Logger,
}

/// A collection of information about a peer.
pub struct PeerInfo {
    /// The connection status of the peer.
    _status: PeerStatus,
    /// The peers reputation. Currently modelled as an unsigned integer.
    reputation: usize,
}

pub enum PeerStatus {
    /// The peer is healthy
    Healthy,
    /// The peer is clogged. It has not been responding to requests on time
    Clogged,
}

/// A collection of actions a peer can perform which will adjust it's reputation. Each variant has
/// an associated reputation change.
pub enum PeerAction {
    /// The peer timed out on an RPC request/response.
    TimedOut = -10,
    /// The peer sent and invalid request/response or encoding.
    InvalidMessage = -20,
    /// The peer sent  something objectively malicious
    Malicious = -50,
}

/// The events that the PeerManager outputs.
pub enum PeerManagerEvent {
    /// The peer should be disconnected.
    DisconnectPeer(PeerId),
    /// The peer should be disconnected and banned.
    BanPeer(PeerId),
}

impl Default for PeerInfo {
    fn default() -> PeerInfo {
        PeerInfo {
            _status: PeerStatus::Healthy,
            reputation: DEFAULT_REPUTATION,
        }
    }
}

impl PeerManager {
    pub fn new(log: slog::Logger) -> Self {
        PeerManager {
            connected_peers: HashMap::new(),
            banned_peers: HashMap::new(),
            events: SmallVec::new(),
            log,
        }
    }

    /// Adds a newly connected peer to the peer manager.
    pub fn add_connected_peer(&mut self, peer_id: PeerId) {
        self.connected_peers.insert(peer_id, Default::default());
    }

    /// Provides a given peer's reputation if it exists.
    pub fn get_peer_rep(&self, peer_id: &PeerId) -> Option<usize> {
        self.connected_peers
            .get(peer_id)
            .or_else(|| self.banned_peers.get(peer_id))
            .map(|peer_info| peer_info.reputation)
    }

    /// Reports a peer for some action.
    ///
    /// If the peer doesn't exist, log a warning and insert defaults.
    pub fn report_peer(&mut self, peer_id: &PeerId, action: PeerAction) {
        let log_ref = &self.log;
        let mut peer_info = self.connected_peers.entry(peer_id.clone()).or_insert_with(|| {
            warn!(log_ref, "Peer reported without being connected"; "peer_id" => format!("{:?}",peer_id));
            Default::default()
        });

        // adjust the reputation
        // NOTE: This calculation is lossy. Cannot have negative reputation value
        // TODO: Implement a maximum
        peer_info.reputation = (peer_info.reputation as i32 + action as i32) as usize;

        // if the reputation goes below the minimum disconnect the peer
        if peer_info.reputation <= MINIMUM_REPUTATION_BEFORE_DISCONNECT {
            self.events
                .push(PeerManagerEvent::DisconnectPeer(peer_id.clone()));
        }
    }
}

// TODO: We should implement the stream trait here. So that events get emitted from the queue.

#[cfg(test)]
mod tests {
    use super::*;
    use slog::{o, Drain};

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

    fn get_new_manager() -> PeerManager {
        let log = build_log(slog::Level::Debug, true);
        PeerManager::new(log)
    }

    #[test]
    fn test_peer_added_successfully() {
        let mut pm = get_new_manager();

        let random_peer = PeerId::random();

        // add the peer to the manager
        pm.add_connected_peer(random_peer.clone());

        // the peer should have the default reputation
        assert_eq!(pm.get_peer_rep(&random_peer), Some(DEFAULT_REPUTATION))
    }

    #[test]
    fn test_reputation_change() {
        let mut pm = get_new_manager();

        let random_peer = PeerId::random();

        // add the peer to the manager
        pm.add_connected_peer(random_peer.clone());

        // build an action
        let action = PeerAction::InvalidMessage;
        pm.report_peer(&random_peer, action);

        // the peer should have the default reputation
        assert_eq!(pm.get_peer_rep(&random_peer), Some(DEFAULT_REPUTATION - 20))
    }
}
