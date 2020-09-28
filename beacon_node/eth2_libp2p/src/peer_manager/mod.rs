//! Implementation of a Lighthouse's peer management system.

pub use self::peerdb::*;
use crate::discovery::{subnet_predicate, Discovery, DiscoveryEvent, TARGET_SUBNET_PEERS};
use crate::rpc::{GoodbyeReason, MetaData, Protocol, RPCError, RPCResponseErrorCode};
use crate::{error, metrics};
use crate::{EnrExt, NetworkConfig, NetworkGlobals, PeerId, SubnetDiscovery};
use futures::prelude::*;
use futures::Stream;
use hashset_delay::HashSetDelay;
use libp2p::core::multiaddr::Protocol as MProtocol;
use libp2p::identify::IdentifyInfo;
use slog::{crit, debug, error};
use smallvec::SmallVec;
use std::{
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use types::{EthSpec, SubnetId};

pub use libp2p::core::{identity::Keypair, Multiaddr};

pub mod client;
mod peer_info;
mod peer_sync_status;
mod peerdb;
pub(crate) mod score;

pub use peer_info::{PeerConnectionStatus::*, PeerInfo};
pub use peer_sync_status::{PeerSyncStatus, SyncInfo};
use score::{PeerAction, ScoreState};
use std::collections::HashMap;
/// The time in seconds between re-status's peers.
const STATUS_INTERVAL: u64 = 300;
/// The time in seconds between PING events. We do not send a ping if the other peer as PING'd us within
/// this time frame (Seconds)
const PING_INTERVAL: u64 = 30;

/// The heartbeat performs regular updates such as updating reputations and performing discovery
/// requests. This defines the interval in seconds.
const HEARTBEAT_INTERVAL: u64 = 30;

/// A fraction of `PeerManager::target_peers` that we allow to connect to us in excess of
/// `PeerManager::target_peers`. For clarity, if `PeerManager::target_peers` is 50 and
/// PEER_EXCESS_FACTOR = 0.1 we allow 10% more nodes, i.e 55.
const PEER_EXCESS_FACTOR: f32 = 0.1;

/// The main struct that handles peer's reputation and connection status.
pub struct PeerManager<TSpec: EthSpec> {
    /// Storage of network globals to access the `PeerDB`.
    network_globals: Arc<NetworkGlobals<TSpec>>,
    /// A queue of events that the `PeerManager` is waiting to produce.
    events: SmallVec<[PeerManagerEvent; 16]>,
    /// A collection of peers awaiting to be Ping'd.
    ping_peers: HashSetDelay<PeerId>,
    /// A collection of peers awaiting to be Status'd.
    status_peers: HashSetDelay<PeerId>,
    /// The target number of peers we would like to connect to.
    target_peers: usize,
    /// The maximum number of peers we allow (exceptions for subnet peers)
    max_peers: usize,
    /// The discovery service.
    discovery: Discovery<TSpec>,
    /// The heartbeat interval to perform routine maintenance.
    heartbeat: tokio::time::Interval,
    /// The logger associated with the `PeerManager`.
    log: slog::Logger,
}

/// The events that the `PeerManager` outputs (requests).
pub enum PeerManagerEvent {
    /// Dial a PeerId.
    Dial(PeerId),
    /// Inform libp2p that our external socket addr has been updated.
    SocketUpdated(Multiaddr),
    /// Sends a STATUS to a peer.
    Status(PeerId),
    /// Sends a PING to a peer.
    Ping(PeerId),
    /// Request METADATA from a peer.
    MetaData(PeerId),
    /// The peer should be disconnected.
    DisconnectPeer(PeerId, GoodbyeReason),
}

impl<TSpec: EthSpec> PeerManager<TSpec> {
    // NOTE: Must be run inside a tokio executor.
    pub async fn new(
        local_key: &Keypair,
        config: &NetworkConfig,
        network_globals: Arc<NetworkGlobals<TSpec>>,
        log: &slog::Logger,
    ) -> error::Result<Self> {
        // start the discovery service
        let mut discovery = Discovery::new(local_key, config, network_globals.clone(), log).await?;

        // start searching for peers
        discovery.discover_peers();

        let heartbeat = tokio::time::interval(tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL));

        Ok(PeerManager {
            network_globals,
            events: SmallVec::new(),
            ping_peers: HashSetDelay::new(Duration::from_secs(PING_INTERVAL)),
            status_peers: HashSetDelay::new(Duration::from_secs(STATUS_INTERVAL)),
            target_peers: config.target_peers,
            max_peers: (config.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR)).ceil() as usize,
            discovery,
            heartbeat,
            log: log.clone(),
        })
    }

    /* Public accessible functions */

    /// Attempts to connect to a peer.
    ///
    /// Returns true if the peer was accepted into the database.
    pub fn dial_peer(&mut self, peer_id: &PeerId) -> bool {
        self.events.push(PeerManagerEvent::Dial(peer_id.clone()));
        self.connect_peer(peer_id, ConnectingType::Dialing)
    }

    /// The application layer wants to disconnect from a peer for a particular reason.
    ///
    /// All instant disconnections are fatal and we ban the associated peer.
    ///
    /// This will send a goodbye and disconnect the peer if it is connected or dialing.
    pub fn goodbye_peer(&mut self, peer_id: &PeerId, reason: GoodbyeReason) {
        // get the peer info
        if let Some(info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            debug!(self.log, "Sending goodbye to peer"; "peer_id" => peer_id.to_string(), "reason" => reason.to_string(), "score" => info.score().to_string());
            // Goodbye's are fatal
            info.apply_peer_action_to_score(PeerAction::Fatal);
            if info.connection_status.is_connected_or_dialing() {
                self.events
                    .push(PeerManagerEvent::DisconnectPeer(peer_id.clone(), reason));
            }
        }
    }

    /// Reports a peer for some action.
    ///
    /// If the peer doesn't exist, log a warning and insert defaults.
    pub fn report_peer(&mut self, peer_id: &PeerId, action: PeerAction) {
        // TODO: Remove duplicate code  - This is duplicated in the update_peer_scores()
        // function.

        // Variables to update the PeerDb if required.
        let mut ban_peer = None;
        let mut unban_peer = None;

        if let Some(info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            let previous_state = info.score_state();
            info.apply_peer_action_to_score(action);
            if previous_state != info.score_state() {
                match info.score_state() {
                    ScoreState::Banned => {
                        debug!(self.log, "Peer has been banned"; "peer_id" => peer_id.to_string(), "score" => info.score().to_string());
                        ban_peer = Some(peer_id.clone());
                        if info.connection_status.is_connected_or_dialing() {
                            self.events.push(PeerManagerEvent::DisconnectPeer(
                                peer_id.clone(),
                                GoodbyeReason::BadScore,
                            ));
                        }
                    }
                    ScoreState::Disconnected => {
                        debug!(self.log, "Peer transitioned to disconnect state"; "peer_id" => peer_id.to_string(), "score" => info.score().to_string(), "past_state" => previous_state.to_string());
                        // disconnect the peer if it's currently connected or dialing
                        unban_peer = Some(peer_id.clone());
                        if info.connection_status.is_connected_or_dialing() {
                            self.events.push(PeerManagerEvent::DisconnectPeer(
                                peer_id.clone(),
                                GoodbyeReason::BadScore,
                            ));
                        }
                        // TODO: Update the peer manager to inform that the peer is disconnecting.
                    }
                    ScoreState::Healthy => {
                        debug!(self.log, "Peer transitioned to healthy state"; "peer_id" => peer_id.to_string(), "score" => info.score().to_string(), "past_state" => previous_state.to_string());
                        // unban the peer if it was previously banned.
                        unban_peer = Some(peer_id.clone());
                    }
                }
            } else {
                debug!(self.log, "Peer score adjusted"; "peer_id" => peer_id.to_string(), "score" => info.score().to_string());
            }
        }

        // Update the PeerDB state.
        if let Some(peer_id) = ban_peer.take() {
            self.ban_peer(&peer_id);
        } else if let Some(peer_id) = unban_peer.take() {
            self.unban_peer(&peer_id);
        }
    }

    /* Discovery Requests */

    /// Provides a reference to the underlying discovery service.
    pub fn discovery(&self) -> &Discovery<TSpec> {
        &self.discovery
    }

    /// Provides a mutable reference to the underlying discovery service.
    pub fn discovery_mut(&mut self) -> &mut Discovery<TSpec> {
        &mut self.discovery
    }

    /// A request to find peers on a given subnet.
    pub fn discover_subnet_peers(&mut self, subnets_to_discover: Vec<SubnetDiscovery>) {
        let filtered: Vec<SubnetDiscovery> = subnets_to_discover
            .into_iter()
            .filter(|s| {
                // Extend min_ttl of connected peers on required subnets
                if let Some(min_ttl) = s.min_ttl {
                    self.network_globals
                        .peers
                        .write()
                        .extend_peers_on_subnet(s.subnet_id, min_ttl);
                }
                // Already have target number of peers, no need for subnet discovery
                let peers_on_subnet = self
                    .network_globals
                    .peers
                    .read()
                    .peers_on_subnet(s.subnet_id)
                    .count();
                if peers_on_subnet >= TARGET_SUBNET_PEERS {
                    debug!(
                        self.log,
                        "Discovery query ignored";
                        "subnet_id" => format!("{:?}",s.subnet_id),
                        "reason" => "Already connected to desired peers",
                        "connected_peers_on_subnet" => peers_on_subnet,
                        "target_subnet_peers" => TARGET_SUBNET_PEERS,
                    );
                    false
                // Queue an outgoing connection request to the cached peers that are on `s.subnet_id`.
                // If we connect to the cached peers before the discovery query starts, then we potentially
                // save a costly discovery query.
                } else {
                    self.dial_cached_enrs_in_subnet(s.subnet_id);
                    true
                }
            })
            .collect();

        // request the subnet query from discovery
        self.discovery.discover_subnet_peers(filtered);
    }

    /// A STATUS message has been received from a peer. This resets the status timer.
    pub fn peer_statusd(&mut self, peer_id: &PeerId) {
        self.status_peers.insert(peer_id.clone());
    }

    /* Notifications from the Swarm */

    /// Updates the state of the peer as disconnected.
    ///
    /// This is also called when dialing a peer fails.
    pub fn notify_disconnect(&mut self, peer_id: &PeerId) {
        // Decrement the PEERS_PER_CLIENT metric
        if let Some(kind) = self
            .network_globals
            .peers
            .read()
            .peer_info(peer_id)
            .and_then(|peer_info| {
                if let Connected { .. } = peer_info.connection_status {
                    Some(peer_info.client.kind.clone())
                } else {
                    None
                }
            })
        {
            if let Some(v) =
                metrics::get_int_gauge(&metrics::PEERS_PER_CLIENT, &[&kind.to_string()])
            {
                v.dec()
            };
        }

        self.network_globals.peers.write().disconnect(peer_id);

        // remove the ping and status timer for the peer
        self.ping_peers.remove(peer_id);
        self.status_peers.remove(peer_id);
        metrics::inc_counter(&metrics::PEER_DISCONNECT_EVENT_COUNT);
        metrics::set_gauge(
            &metrics::PEERS_CONNECTED,
            self.network_globals.connected_peers() as i64,
        );
    }

    /// A dial attempt has failed.
    ///
    /// NOTE: It can be the case that we are dialing a peer and during the dialing process the peer
    /// connects and the dial attempt later fails. To handle this, we only update the peer_db if
    /// the peer is not already connected.
    pub fn notify_dial_failure(&mut self, peer_id: &PeerId) {
        if !self.network_globals.peers.read().is_connected(peer_id) {
            self.notify_disconnect(peer_id);
        }
    }

    /// Sets a peer as connected as long as their reputation allows it
    /// Informs if the peer was accepted
    pub fn connect_ingoing(&mut self, peer_id: &PeerId, multiaddr: Multiaddr) -> bool {
        self.connect_peer(peer_id, ConnectingType::IngoingConnected { multiaddr })
    }

    /// Sets a peer as connected as long as their reputation allows it
    /// Informs if the peer was accepted
    pub fn connect_outgoing(&mut self, peer_id: &PeerId, multiaddr: Multiaddr) -> bool {
        self.connect_peer(peer_id, ConnectingType::OutgoingConnected { multiaddr })
    }

    /// Updates the database informing that a peer is being disconnected.
    pub fn _disconnecting_peer(&mut self, _peer_id: &PeerId) -> bool {
        // TODO: implement
        // This informs the database that we are in the process of disconnecting the
        // peer. Currently this state only exists for a short period of time before we force the
        // disconnection.
        true
    }

    /// Reports if a peer is banned or not.
    ///
    /// This is used to determine if we should accept incoming connections.
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        self.network_globals.peers.read().is_banned(peer_id)
    }

    /// Reports whether the peer limit is reached in which case we stop allowing new incoming
    /// connections.
    pub fn peer_limit_reached(&self) -> bool {
        self.network_globals.connected_or_dialing_peers() >= self.max_peers
    }

    /// Updates `PeerInfo` with `identify` information.
    pub fn identify(&mut self, peer_id: &PeerId, info: &IdentifyInfo) {
        if let Some(peer_info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            let previous_kind = peer_info.client.kind.clone();
            peer_info.client = client::Client::from_identify_info(info);
            peer_info.listening_addresses = info.listen_addrs.clone();

            if previous_kind != peer_info.client.kind {
                // update the peer client kind metric
                if let Some(v) = metrics::get_int_gauge(
                    &metrics::PEERS_PER_CLIENT,
                    &[&peer_info.client.kind.to_string()],
                ) {
                    v.inc()
                };
                if let Some(v) = metrics::get_int_gauge(
                    &metrics::PEERS_PER_CLIENT,
                    &[&previous_kind.to_string()],
                ) {
                    v.dec()
                };
            }
        } else {
            crit!(self.log, "Received an Identify response from an unknown peer"; "peer_id" => peer_id.to_string());
        }
    }

    /// An error has occured in the RPC.
    ///
    /// This adjusts a peer's score based on the error.
    pub fn handle_rpc_error(&mut self, peer_id: &PeerId, protocol: Protocol, err: &RPCError) {
        let client = self.network_globals.client(peer_id);
        let score = self.network_globals.peers.read().score(peer_id);
        debug!(self.log, "RPC Error"; "protocol" => protocol.to_string(), "err" => err.to_string(), "client" => client.to_string(), "peer_id" => peer_id.to_string(), "score" => score.to_string());

        // Map this error to a `PeerAction` (if any)
        let peer_action = match err {
            RPCError::IncompleteStream => {
                // They closed early, this could mean poor connection
                PeerAction::MidToleranceError
            }
            RPCError::InternalError(_) | RPCError::HandlerRejected => {
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
            RPCError::ErrorResponse(code, _) => match code {
                RPCResponseErrorCode::Unknown => PeerAction::HighToleranceError,
                RPCResponseErrorCode::ServerError => PeerAction::MidToleranceError,
                RPCResponseErrorCode::InvalidRequest => PeerAction::LowToleranceError,
                RPCResponseErrorCode::RateLimited => PeerAction::LowToleranceError,
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
            RPCError::RateLimited => match protocol {
                Protocol::Ping => PeerAction::MidToleranceError,
                Protocol::BlocksByRange => PeerAction::HighToleranceError,
                Protocol::BlocksByRoot => PeerAction::HighToleranceError,
                Protocol::Goodbye => PeerAction::LowToleranceError,
                Protocol::MetaData => PeerAction::LowToleranceError,
                Protocol::Status => PeerAction::LowToleranceError,
            },
        };

        self.report_peer(peer_id, peer_action);
    }

    /// A ping request has been received.
    // NOTE: The behaviour responds with a PONG automatically
    // TODO: Update last seen
    pub fn ping_request(&mut self, peer_id: &PeerId, seq: u64) {
        if let Some(peer_info) = self.network_globals.peers.read().peer_info(peer_id) {
            // received a ping
            // reset the to-ping timer for this peer
            debug!(self.log, "Received a ping request"; "peer_id" => peer_id.to_string(), "seq_no" => seq);
            self.ping_peers.insert(peer_id.clone());

            // if the sequence number is unknown send an update the meta data of the peer.
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
                    debug!(self.log, "Received old metadata";
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

    // Handles the libp2p request to obtain multiaddrs for peer_id's in order to dial them.
    pub fn addresses_of_peer(&mut self, peer_id: &PeerId) -> Vec<Multiaddr> {
        if let Some(enr) = self.discovery.enr_of_peer(peer_id) {
            // ENR's may have multiple Multiaddrs. The multi-addr associated with the UDP
            // port is removed, which is assumed to be associated with the discv5 protocol (and
            // therefore irrelevant for other libp2p components).
            let mut out_list = enr.multiaddr();
            out_list.retain(|addr| {
                addr.iter()
                    .find(|v| match v {
                        MProtocol::Udp(_) => true,
                        _ => false,
                    })
                    .is_none()
            });

            out_list
        } else {
            // PeerId is not known
            Vec::new()
        }
    }

    /* Internal functions */

    // The underlying discovery server has updated our external IP address. We send this up to
    // notify libp2p.
    fn socket_updated(&mut self, socket: SocketAddr) {
        // Build a multiaddr to report to libp2p
        let mut multiaddr = Multiaddr::from(socket.ip());
        // NOTE: This doesn't actually track the external TCP port. More sophisticated NAT handling
        // should handle this.
        multiaddr.push(MProtocol::Tcp(self.network_globals.listen_port_tcp()));
        self.events.push(PeerManagerEvent::SocketUpdated(multiaddr));
    }

    /// Dial cached enrs in discovery service that are in the given `subnet_id` and aren't
    /// in Connected, Dialing or Banned state.
    fn dial_cached_enrs_in_subnet(&mut self, subnet_id: SubnetId) {
        let predicate = subnet_predicate::<TSpec>(vec![subnet_id], &self.log);
        let peers_to_dial: Vec<PeerId> = self
            .discovery()
            .cached_enrs()
            .filter_map(|(peer_id, enr)| {
                let peers = self.network_globals.peers.read();
                if predicate(enr)
                    && !peers.is_connected_or_dialing(peer_id)
                    && !peers.is_banned(peer_id)
                {
                    Some(peer_id.clone())
                } else {
                    None
                }
            })
            .collect();
        for peer in &peers_to_dial {
            self.dial_peer(peer);
        }
    }

    /// Peers that have been returned by discovery requests are dialed here if they are suitable.
    ///
    /// NOTE: By dialing `PeerId`s and not multiaddrs, libp2p requests the multiaddr associated
    /// with a new `PeerId` which involves a discovery routing table lookup. We could dial the
    /// multiaddr here, however this could relate to duplicate PeerId's etc. If the lookup
    /// proves resource constraining, we should switch to multiaddr dialling here.
    fn peers_discovered(&mut self, results: HashMap<PeerId, Option<Instant>>) {
        let mut to_dial_peers = Vec::new();

        let connected_or_dialing = self.network_globals.connected_or_dialing_peers();
        for (peer_id, min_ttl) in results {
            // we attempt a connection if this peer is a subnet peer or if the max peer count
            // is not yet filled (including dialling peers)
            if (min_ttl.is_some() || connected_or_dialing + to_dial_peers.len() < self.max_peers)
                && !self
                    .network_globals
                    .peers
                    .read()
                    .is_connected_or_dialing(&peer_id)
                && !self
                    .network_globals
                    .peers
                    .read()
                    .is_banned_or_disconnected(&peer_id)
            {
                // TODO: Update output
                // This should be updated with the peer dialing. In fact created once the peer is
                // dialed
                if let Some(min_ttl) = min_ttl {
                    self.network_globals
                        .peers
                        .write()
                        .update_min_ttl(&peer_id, min_ttl);
                }
                to_dial_peers.push(peer_id);
            }
        }
        for peer_id in to_dial_peers {
            debug!(self.log, "Dialing discovered peer"; "peer_id"=> peer_id.to_string());
            self.dial_peer(&peer_id);
        }
    }

    /// Registers a peer as connected. The `ingoing` parameter determines if the peer is being
    /// dialed or connecting to us.
    ///
    /// This is called by `connect_ingoing` and `connect_outgoing`.
    ///
    /// Informs if the peer was accepted in to the db or not.
    fn connect_peer(&mut self, peer_id: &PeerId, connection: ConnectingType) -> bool {
        {
            let mut peerdb = self.network_globals.peers.write();
            if peerdb.connection_status(peer_id).map(|c| c.is_banned()) == Some(true) {
                // don't connect if the peer is banned
                slog::crit!(self.log, "Connection has been allowed to a banned peer"; "peer_id" => peer_id.to_string());
            }

            match connection {
                ConnectingType::Dialing => {
                    peerdb.dialing_peer(peer_id);
                    return true;
                }
                ConnectingType::IngoingConnected { multiaddr } => {
                    peerdb.connect_outgoing(peer_id, multiaddr)
                }
                ConnectingType::OutgoingConnected { multiaddr } => {
                    peerdb.connect_ingoing(peer_id, multiaddr)
                }
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

        // Increment the PEERS_PER_CLIENT metric
        if let Some(kind) = self
            .network_globals
            .peers
            .read()
            .peer_info(peer_id)
            .map(|peer_info| peer_info.client.kind.clone())
        {
            if let Some(v) =
                metrics::get_int_gauge(&metrics::PEERS_PER_CLIENT, &[&kind.to_string()])
            {
                v.inc()
            };
        }

        true
    }

    /// Updates the scores of known peers according to their connection
    /// status and the time that has passed.
    /// NOTE: This is experimental and will likely be adjusted
    fn update_peer_scores(&mut self) {
        /* Check how long have peers been in this state and update their reputations if needed */

        let mut to_ban_peers = Vec::new();
        let mut to_unban_peers = Vec::new();

        for (peer_id, info) in self.network_globals.peers.write().peers_mut() {
            let previous_state = info.score_state();
            // Update scores
            info.score_update();

            /* TODO: Implement logic about connection lifetimes
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
                        ._last_updated
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
                Unknown => {} //TODO: Handle this case
            }
            // Check if the peer gets banned or unbanned and if it should be disconnected
            if info.reputation < _MIN_REP_BEFORE_BAN && !info.connection_status.is_banned() {
                // This peer gets banned. Check if we should request disconnection
                ban_queue.push(id.clone());
            } else if info.reputation >= _MIN_REP_BEFORE_BAN && info.connection_status.is_banned() {
                // This peer gets unbanned
                unban_queue.push(id.clone());
            }
            */

            // handle score transitions
            if previous_state != info.score_state() {
                match info.score_state() {
                    ScoreState::Banned => {
                        debug!(self.log, "Peer has been banned"; "peer_id" => peer_id.to_string(), "score" => info.score().to_string());
                        to_ban_peers.push(peer_id.clone());
                        if info.connection_status.is_connected_or_dialing() {
                            self.events.push(PeerManagerEvent::DisconnectPeer(
                                peer_id.clone(),
                                GoodbyeReason::BadScore,
                            ));
                        }
                    }
                    ScoreState::Disconnected => {
                        debug!(self.log, "Peer transitioned to disconnect state"; "peer_id" => peer_id.to_string(), "score" => info.score().to_string(), "past_state" => previous_state.to_string());
                        // disconnect the peer if it's currently connected or dialing
                        to_unban_peers.push(peer_id.clone());
                        if info.connection_status.is_connected_or_dialing() {
                            self.events.push(PeerManagerEvent::DisconnectPeer(
                                peer_id.clone(),
                                GoodbyeReason::BadScore,
                            ));
                        }
                        // TODO: Update peer manager to report that it's disconnecting.
                    }
                    ScoreState::Healthy => {
                        debug!(self.log, "Peer transitioned to healthy state"; "peer_id" => peer_id.to_string(), "score" => info.score().to_string(), "past_state" => previous_state.to_string());
                        // unban the peer if it was previously banned.
                        to_unban_peers.push(peer_id.clone());
                    }
                }
            }
        }
        // process banning peers
        for peer_id in to_ban_peers {
            self.ban_peer(&peer_id);
        }
        // process unbanning peers
        for peer_id in to_unban_peers {
            self.unban_peer(&peer_id);
        }
    }

    /// Bans a peer.
    ///
    /// Records updates the peers connection status and updates the peer db as well as blocks the
    /// peer from participating in discovery and removes them from the routing table.
    fn ban_peer(&mut self, peer_id: &PeerId) {
        let mut peer_db = self.network_globals.peers.write();
        peer_db.ban(peer_id);
        let banned_ip_addresses = peer_db
            .peer_info(peer_id)
            .map(|info| {
                info.seen_addresses
                    .iter()
                    .filter(|ip| peer_db.is_ip_banned(ip))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        self.discovery.ban_peer(&peer_id, banned_ip_addresses);
    }

    /// Unbans a peer.
    ///
    /// Records updates the peers connection status and updates the peer db as well as removes
    /// previous bans from discovery.
    fn unban_peer(&mut self, peer_id: &PeerId) {
        let mut peer_db = self.network_globals.peers.write();
        peer_db.unban(&peer_id);

        let seen_ip_addresses = peer_db
            .peer_info(peer_id)
            .map(|info| info.seen_addresses.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        self.discovery.unban_peer(&peer_id, seen_ip_addresses);
    }

    /// The Peer manager's heartbeat maintains the peer count and maintains peer reputations.
    ///
    /// It will request discovery queries if the peer count has not reached the desired number of
    /// peers.
    ///
    /// NOTE: Discovery will only add a new query if one isn't already queued.
    fn heartbeat(&mut self) {
        // TODO: Provide a back-off time for discovery queries. I.e Queue many initially, then only
        // perform discoveries over a larger fixed interval. Perhaps one every 6 heartbeats. This
        // is achievable with a leaky bucket
        let peer_count = self.network_globals.connected_or_dialing_peers();
        if peer_count < self.target_peers {
            // If we need more peers, queue a discovery lookup.
            debug!(self.log, "Starting a new peer discovery query"; "connected_peers" => peer_count, "target_peers" => self.target_peers);
            self.discovery.discover_peers();
        }

        // Updates peer's scores.
        self.update_peer_scores();

        let connected_peer_count = self.network_globals.connected_peers();
        if connected_peer_count > self.target_peers {
            //remove excess peers with the worst scores, but keep subnet peers
            for (peer_id, _) in self
                .network_globals
                .peers
                .read()
                .worst_connected_peers()
                .iter()
                .filter(|(_, info)| !info.has_future_duty())
                .take(connected_peer_count - self.target_peers)
                //we only need to disconnect peers with healthy scores, since the others got already
                //disconnected in update_peer_scores
                .filter(|(_, info)| info.score_state() == ScoreState::Healthy)
            {
                self.events.push(PeerManagerEvent::DisconnectPeer(
                    (*peer_id).clone(),
                    GoodbyeReason::TooManyPeers,
                ));
            }
        }
    }
}

impl<TSpec: EthSpec> Stream for PeerManager<TSpec> {
    type Item = PeerManagerEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // perform the heartbeat when necessary
        while let Poll::Ready(Some(_)) = self.heartbeat.poll_next_unpin(cx) {
            self.heartbeat();
        }

        // handle any discovery events
        while let Poll::Ready(event) = self.discovery.poll(cx) {
            match event {
                DiscoveryEvent::SocketUpdated(socket_addr) => self.socket_updated(socket_addr),
                DiscoveryEvent::QueryResult(results) => self.peers_discovered(results),
            }
        }

        // poll the timeouts for pings and status'
        loop {
            match self.ping_peers.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(peer_id))) => {
                    self.ping_peers.insert(peer_id.clone());
                    self.events.push(PeerManagerEvent::Ping(peer_id));
                }
                Poll::Ready(Some(Err(e))) => {
                    error!(self.log, "Failed to check for peers to ping"; "error" => e.to_string())
                }
                Poll::Ready(None) | Poll::Pending => break,
            }
        }

        // We don't want to update peers during syncing, since this may result in a new chain being
        // synced which leads to inefficient re-downloads of blocks.
        if !self.network_globals.is_syncing() {
            loop {
                match self.status_peers.poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok(peer_id))) => {
                        self.status_peers.insert(peer_id.clone());
                        self.events.push(PeerManagerEvent::Status(peer_id))
                    }
                    Poll::Ready(Some(Err(e))) => {
                        error!(self.log, "Failed to check for peers to ping"; "error" => e.to_string())
                    }
                    Poll::Ready(None) | Poll::Pending => break,
                }
            }
        }

        if !self.events.is_empty() {
            return Poll::Ready(Some(self.events.remove(0)));
        } else {
            self.events.shrink_to_fit();
        }

        Poll::Pending
    }
}

enum ConnectingType {
    /// We are in the process of dialing this peer.
    Dialing,
    /// A peer has dialed us.
    IngoingConnected {
        // The multiaddr the peer connected to us on.
        multiaddr: Multiaddr,
    },
    /// We have successfully dialed a peer.
    OutgoingConnected {
        /// The multiaddr we dialed to reach the peer.
        multiaddr: Multiaddr,
    },
}
