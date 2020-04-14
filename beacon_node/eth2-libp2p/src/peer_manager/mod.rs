//! Implementation of a Lighthouse's peer management system.

pub use self::peerdb::*;
use crate::rpc::MetaData;
use crate::{NetworkGlobals, PeerId};
use futures::prelude::*;
use futures::Stream;
use hashmap_delay::HashSetDelay;
use slog::{crit, debug, error, warn};
use smallvec::SmallVec;
use std::sync::Arc;
use std::time::{Duration, Instant};
use types::EthSpec;

mod peer_info;
mod peerdb;

pub use peer_info::{PeerInfo, PeerSyncStatus};
/// The minimum reputation before a peer is disconnected.
// Most likely this needs tweaking
const MINIMUM_REPUTATION_BEFORE_BAN: Rep = 20;
/// The time in seconds between re-status's peers.
const STATUS_INTERVAL: u64 = 300;
/// The time in seconds between PING events. We do not send a ping if the other peer as PING'd us within
/// this time frame (Seconds)
const PING_INTERVAL: u64 = 30;

/// The main struct that handles peer's reputation and connection status.
pub struct PeerManager<TSpec: EthSpec> {
    /// Storage of network globals to access the PeerDB.
    network_globals: Arc<NetworkGlobals<TSpec>>,
    /// A queue of events that the `PeerManager` is waiting to produce.
    events: SmallVec<[PeerManagerEvent; 5]>,
    /// A collection of peers awaiting to be Ping'd.
    ping_peers: HashSetDelay<PeerId>,
    /// A collection of peers awaiting to be Status'd.
    status_peers: HashSetDelay<PeerId>,
    /// Last updated moment.
    last_updated: Instant,
    /// The logger associated with the `PeerManager`.
    log: slog::Logger,
}

/// A collection of actions a peer can perform which will adjust its reputation
/// Each variant has an associated reputation change.
pub enum PeerAction {
    /// The peer timed out on an RPC request/response.
    TimedOut = -10,
    /// The peer sent and invalid request/response or encoding.
    InvalidMessage = -20,
    /// The peer sent  something objectively malicious.
    Malicious = -50,
    /// Received an expected message.
    ValidMessage = 20,
    /// Peer disconnected.
    Disconnected = -30,
}

/// The events that the PeerManager outputs (requests).
pub enum PeerManagerEvent {
    /// Sends a STATUS to a peer.
    Status(PeerId),
    /// Sends a PING to a peer.
    Ping(PeerId),
    /// Request METADATA from a peer.
    MetaData(PeerId),
    /// The peer should be disconnected.
    DisconnectPeer(PeerId),
    /// The peer should be disconnected and banned.
    BanPeer(PeerId),
}

impl<TSpec: EthSpec> PeerManager<TSpec> {
    pub fn new(network_globals: Arc<NetworkGlobals<TSpec>>, log: &slog::Logger) -> Self {
        PeerManager {
            network_globals,
            events: SmallVec::new(),
            last_updated: Instant::now(),
            ping_peers: HashSetDelay::new(Duration::from_secs(PING_INTERVAL)),
            status_peers: HashSetDelay::new(Duration::from_secs(STATUS_INTERVAL)),
            log: log.clone(),
        }
    }

    /* Public accessible functions */

    /// A ping request has been received.
    // NOTE: The behaviour responds with a PONG automatically
    pub fn ping_request(&mut self, peer_id: &PeerId, seq: u64) {
        if let Some(peer_info) = self.network_globals.peers.read().peer_info(peer_id) {
            // received a ping
            // reset the to-ping timer for this peer
            self.ping_peers.insert(peer_id.clone());

            // if the sequence number is unknown send update the meta data of the peer.
            if let Some(meta_data) = &peer_info.meta_data {
                if meta_data.seq_number < seq {
                    debug!(self.log, "Requesting new metadata from peer"; "peer_id" => format!("{}", peer_id), "known_seq_no" => meta_data.seq_number, "ping_seq_no" => seq);
                    self.events
                        .push(PeerManagerEvent::MetaData(peer_id.clone()));
                }
            } else {
                // if we don't know the meta-data, request it
                debug!(self.log, "Requesting first metadata from peer"; "peer_id" => format!("{}", peer_id));
                self.events
                    .push(PeerManagerEvent::MetaData(peer_id.clone()));
            }
        } else {
            crit!(self.log, "Received a PING from an unknown peer"; "peer_id" => format!("{}", peer_id));
        }
    }

    /// A PONG has been returned from a peer.
    pub fn pong_response(&mut self, peer_id: &PeerId, seq: u64) {
        if let Some(peer_info) = self.network_globals.peers.read().peer_info(peer_id) {
            // received a pong

            // if the sequence number is unknown send update the meta data of the peer.
            if let Some(meta_data) = &peer_info.meta_data {
                if meta_data.seq_number < seq {
                    debug!(self.log, "Requesting new metadata from peer"; "peer_id" => format!("{}", peer_id), "known_seq_no" => meta_data.seq_number, "pong_seq_no" => seq);
                    self.events
                        .push(PeerManagerEvent::MetaData(peer_id.clone()));
                }
            } else {
                // if we don't know the meta-data, request it
                debug!(self.log, "Requesting first metadata from peer"; "peer_id" => format!("{}", peer_id));
                self.events
                    .push(PeerManagerEvent::MetaData(peer_id.clone()));
            }
        } else {
            crit!(self.log, "Received a PONG from an unknown peer"; "peer_id" => format!("{}", peer_id));
        }
    }

    /// Received a metadata response from a peer.
    pub fn meta_data_response(&mut self, peer_id: &PeerId, meta_data: MetaData<TSpec>) {
        if let Some(peer_info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            if let Some(known_meta_data) = &peer_info.meta_data {
                if known_meta_data.seq_number < meta_data.seq_number {
                    debug!(self.log, "Updating peer's metadata"; "peer_id" => format!("{}", peer_id), "known_seq_no" => known_meta_data.seq_number, "new_seq_no" => meta_data.seq_number);
                } else {
                    warn!(self.log, "Received old metadata"; "peer_id" => format!("{}", peer_id), "known_seq_no" => known_meta_data.seq_number, "new_seq_no" => meta_data.seq_number);
                }
            } else {
                // we have no meta-data for this peer, update
                debug!(self.log, "Obtained peer's metadata"; "peer_id" => format!("{}", peer_id), "new_seq_no" => meta_data.seq_number);
                peer_info.meta_data = Some(meta_data);
            }
        } else {
            crit!(self.log, "Received METADATA from an unknown peer"; "peer_id" => format!("{}", peer_id));
        }
    }

    /// A STATUS message has been received from a peer. This resets the status timer.
    pub fn peer_statusd(&mut self, peer_id: &PeerId) {
        self.status_peers.insert(peer_id.clone());
    }

    /// Checks the reputation of a peer and if it is too low, bans it and
    /// sends the corresponding event. Informs if it got banned
    fn gets_banned(&mut self, peer_id: &PeerId) -> bool {
        // if the peer was already banned don't inform again
        let mut peerdb = self.network_globals.peers.write();
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
        {
            let mut peerdb = self.network_globals.peers.write();
            peerdb.disconnect(peer_id);
            peerdb.add_reputation(peer_id, PeerAction::Disconnected as Rep);
        }
        if !self.gets_banned(peer_id) {
            self.events
                .push(PeerManagerEvent::DisconnectPeer(peer_id.clone()));
        }

        // remove the ping and status timer for the peer
        self.ping_peers.remove(peer_id);
        self.status_peers.remove(peer_id);
    }

    /// Sets a peer as connected as long as their reputation allows it
    /// Informs if the peer was accepted
    pub fn connect_ingoing(&mut self, peer_id: &PeerId) -> bool {
        self.update_reputations();
        let mut peerdb = self.network_globals.peers.write();
        if !peerdb.connection_status(peer_id).is_banned() {
            peerdb.connect_ingoing(peer_id);
            // start a ping and status timer for the peer
            self.ping_peers.insert(peer_id.clone());
            self.status_peers.insert(peer_id.clone());

            return true;
        }

        false
    }

    /// Sets a peer as connected as long as their reputation allows it
    /// Informs if the peer was accepted
    pub fn connect_outgoing(&mut self, peer_id: &PeerId) -> bool {
        self.update_reputations();
        let mut peerdb = self.network_globals.peers.write();
        if !peerdb.connection_status(peer_id).is_banned() {
            peerdb.connect_outgoing(peer_id);
            // start a ping and status timer for the peer
            self.ping_peers.insert(peer_id.clone());
            self.status_peers.insert(peer_id.clone());

            return true;
        }

        false
    }

    /// Provides a given peer's reputation if it exists.
    pub fn get_peer_rep(&self, peer_id: &PeerId) -> Rep {
        self.network_globals.peers.read().reputation(peer_id)
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
        self.network_globals
            .peers
            .write()
            .add_reputation(peer_id, action as Rep);
        self.update_reputations();
    }
}

impl<TSpec: EthSpec> Stream for PeerManager<TSpec> {
    type Item = PeerManagerEvent;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // poll the timeouts for pings and status'
        while let Async::Ready(Some(peer_id)) = self.ping_peers.poll().map_err(|e| {
            error!(self.log, "Failed to check for peers to ping"; "error" => format!("{}",e));
        })? {
            self.events.push(PeerManagerEvent::Ping(peer_id));
        }

        while let Async::Ready(Some(peer_id)) = self.ping_peers.poll().map_err(|e| {
            error!(self.log, "Failed to check for peers to status"; "error" => format!("{}",e));
        })? {
            self.events.push(PeerManagerEvent::Status(peer_id));
        }

        if !self.events.is_empty() {
            return Ok(Async::Ready(Some(self.events.remove(0))));
        } else {
            self.events.shrink_to_fit();
        }

        Ok(Async::NotReady)
    }
}
