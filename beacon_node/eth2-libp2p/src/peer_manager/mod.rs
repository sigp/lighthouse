//! Implementation of a Lighthouse's peer management system.

pub use self::peerdb::*;
use crate::NetworkGlobals;
use crate::PeerId;
use futures::prelude::*;
use futures::Stream;
use smallvec::SmallVec;
use std::sync::Arc;
use std::time::Instant;
use types::EthSpec;

mod peer_info;
mod peerdb;

pub use peer_info::PeerInfo;
/// The minimum reputation before a peer is disconnected.
// Most likely this needs tweaking
const MINIMUM_REPUTATION_BEFORE_BAN: Rep = 20;

/// The main struct that handles peer's reputation and connection status.
pub struct PeerManager<TSpec: EthSpec> {
    /// Storage of network globals to access the PeerDB.
    network_globals: Arc<NetworkGlobals<TSpec>>,
    /// A queue of events that the `PeerManager` is waiting to produce.
    events: SmallVec<[PeerManagerEvent; 5]>,
    /// The logger associated with the `PeerManager`.
    _log: slog::Logger,
    /// Last updated moment
    last_updated: Instant,
}

/// A collection of actions a peer can perform which will adjust its reputation
/// Each variant has an associated reputation change.
pub enum PeerAction {
    /// The peer timed out on an RPC request/response.
    TimedOut = -10,
    /// The peer sent and invalid request/response or encoding.
    InvalidMessage = -20,
    /// The peer sent  something objectively malicious
    Malicious = -50,
    /// Received an expected message
    ValidMessage = 20,
    /// Peer disconnected
    Disconnected = -30,
}

/// The events that the PeerManager outputs (requests)
pub enum PeerManagerEvent {
    /// Sends a PING to a peer.
    Ping(PeerId),
    /// The peer should be disconnected.
    DisconnectPeer(PeerId),
    /// The peer should be disconnected and banned.
    BanPeer(PeerId),
}

impl<TSpec: EthSpec> PeerManager<TSpec> {
    pub fn new(
        network_globals: Arc<NetworkGlobals<TSpec>>,
        max_dc_peers: usize,
        log: &slog::Logger,
    ) -> Self {
        PeerManager {
            network_globals,
            events: SmallVec::new(),
            _log: log.clone(),
            last_updated: Instant::now(),
        }
    }

    /// Gets a readable reference to the PeerDB.
    fn peer_db(&self) -> &PeerDB<TSpec> {
        &self.network_globals.peers.read()
    }

    /// Gets a mutable reference to the PeerDB.
    fn peer_db_mut(&self) -> &mut PeerDB<TSpec> {
        &mut self.network_globals.peers.write()
    }

    /// Checks the reputation of a peer and if it is too low, bans it and
    /// sends the corresponding event. Informs if it got banned
    fn gets_banned(&mut self, peer_id: &PeerId) -> bool {
        // if the peer was already banned don't inform again
        let peerdb = self.peer_db_mut();
        if peerdb.reputation(peer_id) < MINIMUM_REPUTATION_BEFORE_BAN
            && !peerdb.connection_status(peer_id).is_banned()
        {
            peerdb.ban(peer_id);
            self.events.push(PeerManagerEvent::BanPeer(peer_id.clone()));
            return true;
        }
        false
    }

    /// Sets a peer as disconnected. If its reputation gets too low requests
    /// the peer to be banned and to be disconnected otherwise
    pub fn disconnect(&mut self, peer_id: &PeerId) {
        self.update_reputations();
        let peerdb = self.peer_db_mut();
        peerdb.disconnect(peer_id);
        peerdb.add_reputation(peer_id, PeerAction::Disconnected as Rep);
        if !self.gets_banned(peer_id) {
            self.events
                .push(PeerManagerEvent::DisconnectPeer(peer_id.clone()));
        }
    }

    /// Sets a peer as connected as long as their reputation allows it
    /// Informs if the peer was accepted
    pub fn connect_ingoing(&mut self, peer_id: &PeerId) -> bool {
        self.update_reputations();
        let peerdb = self.peer_db_mut();
        peerdb.new_peer(peer_id);
        if !peerdb.connection_status(peer_id).is_banned() {
            peerdb.connect_ingoing(peer_id);
            return true;
        }
        false
    }

    /// Sets a peer as connected as long as their reputation allows it
    /// Informs if the peer was accepted
    pub fn connect_outgoing(&mut self, peer_id: &PeerId) -> bool {
        self.update_reputations();
        let peerdb = self.peer_db_mut();
        peerdb.new_peer(peer_id);
        if !peerdb.connection_status(peer_id).is_banned() {
            peerdb.connect_outgoing(peer_id);
            return true;
        }
        false
    }

    /// Provides a given peer's reputation if it exists.
    pub fn get_peer_rep(&self, peer_id: &PeerId) -> Rep {
        self.peer_db().reputation(peer_id)
    }

    /// Updates the reputation of known peers according to their connection
    /// status and the time that has passed.
    pub fn update_reputations(&mut self) {
        let now = Instant::now();
        let elapsed = (now - self.last_updated).as_secs();
        // 0 seconds means now - last_updated < 0, but (most likely) not = 0.
        // In this case, do nothing (updating last_updated would propagate
        // rounding errors)
        if elapsed > 0 {
            self.last_updated = now;
            // TODO decide how reputations change with time. If they get too low
            // set the peers as banned
        }
    }

    /// Reports a peer for some action.
    ///
    /// If the peer doesn't exist, log a warning and insert defaults.
    pub fn report_peer(&mut self, peer_id: &PeerId, action: PeerAction) {
        self.update_reputations();
        self.peer_db_mut().add_reputation(peer_id, action as Rep);
        self.update_reputations();
    }
}

impl<TSpec: EthSpec> Stream for PeerManager<TSpec> {
    type Item = PeerManagerEvent;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        if !self.events.is_empty() {
            Ok(Async::Ready(Some(self.events.remove(0))))
        } else {
            self.events.shrink_to_fit();
            Ok(Async::NotReady)
        }
    }
}
