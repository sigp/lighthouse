//! Implementation of a Lighthouse's peer management system.

pub use self::peerdb::*;
use crate::metrics;
use crate::rpc::{MetaData, Protocol, RPCError, RPCResponseErrorCode};
use crate::{NetworkGlobals, PeerId};
use futures::prelude::*;
use futures::Stream;
use hashmap_delay::HashSetDelay;
use libp2p::identify::IdentifyInfo;
use slog::{crit, debug, error, warn};
use smallvec::SmallVec;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::{Duration, Instant};
use types::EthSpec;

mod client;
mod peer_info;
mod peer_sync_status;
mod peerdb;

pub use peer_info::{PeerConnectionStatus::*, PeerInfo};
pub use peer_sync_status::{PeerSyncStatus, SyncInfo};
/// The minimum reputation before a peer is disconnected.
// Most likely this needs tweaking.
const MIN_REP_BEFORE_BAN: Rep = 10;
/// The time in seconds between re-status's peers.
const STATUS_INTERVAL: u64 = 300;
/// The time in seconds between PING events. We do not send a ping if the other peer as PING'd us within
/// this time frame (Seconds)
const PING_INTERVAL: u64 = 30;

/// The main struct that handles peer's reputation and connection status.
pub struct PeerManager<TSpec: EthSpec> {
    /// Storage of network globals to access the `PeerDB`.
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

/// A collection of actions a peer can perform which will adjust its reputation.
/// Each variant has an associated reputation change.
// To easily assess the behaviour of reputation changes the number of variants should stay low, and
// somewhat generic.
pub enum PeerAction {
    /// We should not communicate more with this peer.
    /// This action will cause the peer to get banned.
    Fatal,
    /// An error occurred with this peer but it is not necessarily malicious.
    /// We have high tolerance for this actions: several occurrences are needed for a peer to get
    /// kicked.
    /// NOTE: ~15 occurrences will get the peer banned
    HighToleranceError,
    /// An error occurred with this peer but it is not necessarily malicious.
    /// We have high tolerance for this actions: several occurrences are needed for a peer to get
    /// kicked.
    /// NOTE: ~10 occurrences will get the peer banned
    MidToleranceError,
    /// This peer's action is not malicious but will not be tolerated. A few occurrences will cause
    /// the peer to get kicked.
    /// NOTE: ~5 occurrences will get the peer banned
    LowToleranceError,
    /// Received an expected message.
    _ValidMessage,
}

impl PeerAction {
    fn rep_change(&self) -> RepChange {
        match self {
            PeerAction::Fatal => RepChange::worst(),
            PeerAction::LowToleranceError => RepChange::bad(60),
            PeerAction::MidToleranceError => RepChange::bad(25),
            PeerAction::HighToleranceError => RepChange::bad(15),
            PeerAction::_ValidMessage => RepChange::good(20),
        }
    }
}

/// The events that the `PeerManager` outputs (requests).
pub enum PeerManagerEvent {
    /// Sends a STATUS to a peer.
    Status(PeerId),
    /// Sends a PING to a peer.
    Ping(PeerId),
    /// Request METADATA from a peer.
    MetaData(PeerId),
    /// The peer should be disconnected.
    _DisconnectPeer(PeerId),
    /// The peer should be disconnected and banned.
    _BanPeer(PeerId),
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
    // TODO: Update last seen
    pub fn ping_request(&mut self, peer_id: &PeerId, seq: u64) {
        if let Some(peer_info) = self.network_globals.peers.read().peer_info(peer_id) {
            // received a ping
            // reset the to-ping timer for this peer
            debug!(self.log, "Received a ping request"; "peer_id" => peer_id.to_string(), "seq_no" => seq);
            self.ping_peers.insert(peer_id.clone());

            // if the sequence number is unknown send update the meta data of the peer.
            if let Some(meta_data) = &peer_info.meta_data {
                if meta_data.seq_number < seq {
                    debug!(self.log, "Requesting new metadata from peer";
                        "peer_id" => peer_id.to_string(), "known_seq_no" => meta_data.seq_number, "ping_seq_no" => seq);
                    self.events
                        .push(PeerManagerEvent::MetaData(peer_id.clone()));
                }
            } else {
                // if we don't know the meta-data, request it
                debug!(self.log, "Requesting first metadata from peer";
                    "peer_id" => peer_id.to_string());
                self.events
                    .push(PeerManagerEvent::MetaData(peer_id.clone()));
            }
        } else {
            crit!(self.log, "Received a PING from an unknown peer";
                "peer_id" => peer_id.to_string());
        }
    }

    /// A PONG has been returned from a peer.
    // TODO: Update last seen
    pub fn pong_response(&mut self, peer_id: &PeerId, seq: u64) {
        if let Some(peer_info) = self.network_globals.peers.read().peer_info(peer_id) {
            // received a pong

            // if the sequence number is unknown send update the meta data of the peer.
            if let Some(meta_data) = &peer_info.meta_data {
                if meta_data.seq_number < seq {
                    debug!(self.log, "Requesting new metadata from peer";
                        "peer_id" => peer_id.to_string(), "known_seq_no" => meta_data.seq_number, "pong_seq_no" => seq);
                    self.events
                        .push(PeerManagerEvent::MetaData(peer_id.clone()));
                }
            } else {
                // if we don't know the meta-data, request it
                debug!(self.log, "Requesting first metadata from peer";
                    "peer_id" => peer_id.to_string());
                self.events
                    .push(PeerManagerEvent::MetaData(peer_id.clone()));
            }
        } else {
            crit!(self.log, "Received a PONG from an unknown peer"; "peer_id" => peer_id.to_string());
        }
    }

    /// Received a metadata response from a peer.
    // TODO: Update last seen
    pub fn meta_data_response(&mut self, peer_id: &PeerId, meta_data: MetaData<TSpec>) {
        if let Some(peer_info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            if let Some(known_meta_data) = &peer_info.meta_data {
                if known_meta_data.seq_number < meta_data.seq_number {
                    debug!(self.log, "Updating peer's metadata";
                        "peer_id" => peer_id.to_string(), "known_seq_no" => known_meta_data.seq_number, "new_seq_no" => meta_data.seq_number);
                    peer_info.meta_data = Some(meta_data);
                } else {
                    // TODO: isn't this malicious/random behaviour? What happens if the seq_number
                    // is the same but the contents differ?
                    warn!(self.log, "Received old metadata";
                        "peer_id" => peer_id.to_string(), "known_seq_no" => known_meta_data.seq_number, "new_seq_no" => meta_data.seq_number);
                }
            } else {
                // we have no meta-data for this peer, update
                debug!(self.log, "Obtained peer's metadata";
                    "peer_id" => peer_id.to_string(), "new_seq_no" => meta_data.seq_number);
                peer_info.meta_data = Some(meta_data);
            }
        } else {
            crit!(self.log, "Received METADATA from an unknown peer";
                "peer_id" => peer_id.to_string());
        }
    }

    /// A STATUS message has been received from a peer. This resets the status timer.
    pub fn peer_statusd(&mut self, peer_id: &PeerId) {
        self.status_peers.insert(peer_id.clone());
    }

    /// Updates the state of the peer as disconnected.
    pub fn notify_disconnect(&mut self, peer_id: &PeerId) {
        self.update_reputations();
        {
            let mut peerdb = self.network_globals.peers.write();
            peerdb.disconnect(peer_id);
        }

        // remove the ping and status timer for the peer
        self.ping_peers.remove(peer_id);
        self.status_peers.remove(peer_id);
        metrics::inc_counter(&metrics::PEER_DISCONNECT_EVENT_COUNT);
        metrics::set_gauge(
            &metrics::PEERS_CONNECTED,
            self.network_globals.connected_peers() as i64,
        );
    }

    /// Sets a peer as connected as long as their reputation allows it
    /// Informs if the peer was accepted
    pub fn connect_ingoing(&mut self, peer_id: &PeerId) -> bool {
        self.connect_peer(peer_id, false)
    }

    /// Sets a peer as connected as long as their reputation allows it
    /// Informs if the peer was accepted
    pub fn connect_outgoing(&mut self, peer_id: &PeerId) -> bool {
        self.connect_peer(peer_id, true)
    }

    /// Reports a peer for some action.
    ///
    /// If the peer doesn't exist, log a warning and insert defaults.
    pub fn report_peer(&mut self, peer_id: &PeerId, action: PeerAction) {
        self.update_reputations();
        self.network_globals
            .peers
            .write()
            .add_reputation(peer_id, action.rep_change());
        self.update_reputations();
    }

    /// Updates `PeerInfo` with `identify` information.
    pub fn identify(&mut self, peer_id: &PeerId, info: &IdentifyInfo) {
        if let Some(peer_info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            peer_info.client = client::Client::from_identify_info(info);
            peer_info.listening_addresses = info.listen_addrs.clone();
        } else {
            crit!(self.log, "Received an Identify response from an unknown peer"; "peer_id" => peer_id.to_string());
        }
    }

    pub fn handle_rpc_error(&mut self, peer_id: &PeerId, protocol: Protocol, err: &RPCError) {
        debug!(self.log, "RPCError"; "protocol" => protocol.to_string(), "err" => err.to_string());

        // Map this error to a `PeerAction` (if any)
        let peer_action = match err {
            RPCError::IncompleteStream => {
                // They closed early, this could mean poor connection
                PeerAction::MidToleranceError
            }
            RPCError::InternalError(_reason) => {
                // Our fault. Do nothing
                return;
            }
            RPCError::InvalidData => {
                // Peer is not complying with the protocol. This is considered a malicious action
                PeerAction::Fatal
            }
            RPCError::IoError(_e) => {
                // this could their fault or ours, so we tolerate this
                PeerAction::HighToleranceError
            }
            RPCError::ErrorResponse(code) => match code {
                RPCResponseErrorCode::Unknown => PeerAction::HighToleranceError,
                RPCResponseErrorCode::ServerError => PeerAction::MidToleranceError,
                RPCResponseErrorCode::InvalidRequest => PeerAction::LowToleranceError,
            },
            RPCError::SSZDecodeError(_) => PeerAction::Fatal,
            RPCError::UnsupportedProtocol => {
                // Not supporting a protocol shouldn't be considered a malicious action, but
                // it is an action that in some cases will make the peer unfit to continue
                // communicating.
                // TODO: To avoid punishing a peer repeatedly for not supporting a protocol, this
                // information could be stored and used to prevent sending requests for the given
                // protocol to this peer. Similarly, to avoid blacklisting a peer for a protocol
                // forever, if stored this information should expire.
                match protocol {
                    Protocol::Ping => PeerAction::Fatal,
                    Protocol::BlocksByRange => return,
                    Protocol::BlocksByRoot => return,
                    Protocol::Goodbye => return,
                    Protocol::MetaData => PeerAction::LowToleranceError,
                    Protocol::Status => PeerAction::LowToleranceError,
                }
            }
            RPCError::StreamTimeout => match protocol {
                Protocol::Ping => PeerAction::LowToleranceError,
                Protocol::BlocksByRange => PeerAction::MidToleranceError,
                Protocol::BlocksByRoot => PeerAction::MidToleranceError,
                Protocol::Goodbye => return,
                Protocol::MetaData => return,
                Protocol::Status => return,
            },
            RPCError::NegotiationTimeout => PeerAction::HighToleranceError,
        };

        self.report_peer(peer_id, peer_action);
    }

    /* Internal functions */

    /// Registers a peer as connected. The `ingoing` parameter determines if the peer is being
    /// dialed or connecting to us.
    ///
    /// This is called by `connect_ingoing` and `connect_outgoing`.
    ///
    /// This informs if the peer was accepted in to the db or not.
    // TODO: Drop peers if over max_peer limit
    fn connect_peer(&mut self, peer_id: &PeerId, outgoing: bool) -> bool {
        // TODO: remove after timed updates
        self.update_reputations();

        {
            let mut peerdb = self.network_globals.peers.write();
            if peerdb.connection_status(peer_id).map(|c| c.is_banned()) == Some(true) {
                // don't connect if the peer is banned
                return false;
            }

            if outgoing {
                peerdb.connect_outgoing(peer_id);
            } else {
                peerdb.connect_ingoing(peer_id);
            }
        }

        // start a ping and status timer for the peer
        self.ping_peers.insert(peer_id.clone());
        self.status_peers.insert(peer_id.clone());

        // increment prometheus metrics
        metrics::inc_counter(&metrics::PEER_CONNECT_EVENT_COUNT);
        metrics::set_gauge(
            &metrics::PEERS_CONNECTED,
            self.network_globals.connected_peers() as i64,
        );

        true
    }

    /// Notifies the peer manager that this peer is being dialed.
    pub fn _dialing_peer(&mut self, peer_id: &PeerId) {
        self.network_globals.peers.write().dialing_peer(peer_id);
    }

    /// Updates the reputation of known peers according to their connection
    /// status and the time that has passed.
    ///
    /// **Disconnected peers** get a 1rep hit every hour they stay disconnected.
    /// **Banned peers** get a 1rep gain for every hour to slowly allow them back again.
    ///
    /// A banned(disconnected) peer that gets its rep above(below) MIN_REP_BEFORE_BAN is
    /// now considered a disconnected(banned) peer.
    fn update_reputations(&mut self) {
        // avoid locking the peerdb too often
        // TODO: call this on a timer
        if self.last_updated.elapsed().as_secs() < 30 {
            return;
        }

        let now = Instant::now();

        // Check for peers that get banned, unbanned and that should be disconnected
        let mut ban_queue = Vec::new();
        let mut unban_queue = Vec::new();

        /* Check how long have peers been in this state and update their reputations if needed */
        let mut pdb = self.network_globals.peers.write();

        for (id, info) in pdb.peers_mut() {
            // Update reputations
            match info.connection_status {
                Connected { .. } => {
                    // Connected peers gain reputation by sending useful messages
                }
                Disconnected { since } | Banned { since } => {
                    // For disconnected peers, lower their reputation by 1 for every hour they
                    // stay disconnected. This helps us slowly forget disconnected peers.
                    // In the same way, slowly allow banned peers back again.
                    let dc_hours = now
                        .checked_duration_since(since)
                        .unwrap_or_else(|| Duration::from_secs(0))
                        .as_secs()
                        / 3600;
                    let last_dc_hours = self
                        .last_updated
                        .checked_duration_since(since)
                        .unwrap_or_else(|| Duration::from_secs(0))
                        .as_secs()
                        / 3600;
                    if dc_hours > last_dc_hours {
                        // this should be 1 most of the time
                        let rep_dif = (dc_hours - last_dc_hours)
                            .try_into()
                            .unwrap_or(Rep::max_value());

                        info.reputation = if info.connection_status.is_banned() {
                            info.reputation.saturating_add(rep_dif)
                        } else {
                            info.reputation.saturating_sub(rep_dif)
                        };
                    }
                }
                Dialing { since } => {
                    // A peer shouldn't be dialing for more than 2 minutes
                    if since.elapsed().as_secs() > 120 {
                        warn!(self.log,"Peer has been dialing for too long"; "peer_id" => id.to_string());
                        // TODO: decide how to handle this
                    }
                }
            }
            // Check if the peer gets banned or unbanned and if it should be disconnected
            if info.reputation < MIN_REP_BEFORE_BAN && !info.connection_status.is_banned() {
                // This peer gets banned. Check if we should request disconnection
                ban_queue.push(id.clone());
            } else if info.reputation >= MIN_REP_BEFORE_BAN && info.connection_status.is_banned() {
                // This peer gets unbanned
                unban_queue.push(id.clone());
            }
        }

        for id in ban_queue {
            pdb.ban(&id);

            self.events.push(PeerManagerEvent::_BanPeer(id.clone()));
        }

        for id in unban_queue {
            pdb.disconnect(&id);
        }

        self.last_updated = Instant::now();
    }
}

impl<TSpec: EthSpec> Stream for PeerManager<TSpec> {
    type Item = PeerManagerEvent;
    type Error = ();

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        // poll the timeouts for pings and status'
        // TODO: Remove task notifies and temporary vecs for stable futures
        // These exist to handle a bug in delayqueue
        let mut peers_to_add = Vec::new();
        while let Async::Ready(Some(peer_id)) = self.ping_peers.poll().map_err(|e| {
            error!(self.log, "Failed to check for peers to ping"; "error" => e.to_string());
        })? {
            debug!(self.log, "Pinging peer"; "peer_id" => peer_id.to_string());
            // add the ping timer back
            peers_to_add.push(peer_id.clone());
            self.events.push(PeerManagerEvent::Ping(peer_id));
        }

        if !peers_to_add.is_empty() {
            futures::task::current().notify();
        }
        while let Some(peer) = peers_to_add.pop() {
            self.ping_peers.insert(peer);
        }

        while let Async::Ready(Some(peer_id)) = self.status_peers.poll().map_err(|e| {
            error!(self.log, "Failed to check for peers to status"; "error" => e.to_string());
        })? {
            debug!(self.log, "Sending Status to peer"; "peer_id" => peer_id.to_string());
            // add the status timer back
            peers_to_add.push(peer_id.clone());
            self.events.push(PeerManagerEvent::Status(peer_id));
        }

        if !peers_to_add.is_empty() {
            futures::task::current().notify();
        }
        while let Some(peer) = peers_to_add.pop() {
            self.status_peers.insert(peer);
        }

        if !self.events.is_empty() {
            return Ok(Async::Ready(Some(self.events.remove(0))));
        } else {
            self.events.shrink_to_fit();
        }

        Ok(Async::NotReady)
    }
}
