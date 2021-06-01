//! Implementation of a Lighthouse's peer management system.

pub use self::peerdb::*;
use crate::discovery::{subnet_predicate, Discovery, DiscoveryEvent, TARGET_SUBNET_PEERS};
use crate::rpc::{GoodbyeReason, MetaData, Protocol, RPCError, RPCResponseErrorCode};
use crate::types::SyncState;
use crate::{error, metrics, Gossipsub};
use crate::{EnrExt, NetworkConfig, NetworkGlobals, PeerId, SubnetDiscovery};
use futures::prelude::*;
use futures::Stream;
use hashset_delay::HashSetDelay;
use libp2p::core::multiaddr::Protocol as MProtocol;
use libp2p::identify::IdentifyInfo;
use slog::{crit, debug, error, trace, warn};
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
#[allow(clippy::mutable_key_type)] // PeerId in hashmaps are no longer permitted by clippy
mod peerdb;
pub(crate) mod score;

pub use peer_info::{ConnectionDirection, PeerConnectionStatus, PeerConnectionStatus::*, PeerInfo};
pub use peer_sync_status::{PeerSyncStatus, SyncInfo};
use score::{PeerAction, ReportSource, ScoreState};
use std::cmp::Ordering;
use std::collections::HashMap;

/// The time in seconds between re-status's peers.
const STATUS_INTERVAL: u64 = 300;
/// The time in seconds between PING events. We do not send a ping if the other peer has PING'd us
/// within this time frame (Seconds)
/// This is asymmetric to avoid simultaneous pings.
/// The interval for outbound connections.
const PING_INTERVAL_OUTBOUND: u64 = 15;
/// The interval for inbound connections.
const PING_INTERVAL_INBOUND: u64 = 20;

/// The heartbeat performs regular updates such as updating reputations and performing discovery
/// requests. This defines the interval in seconds.
const HEARTBEAT_INTERVAL: u64 = 30;

/// A fraction of `PeerManager::target_peers` that we allow to connect to us in excess of
/// `PeerManager::target_peers`. For clarity, if `PeerManager::target_peers` is 50 and
/// PEER_EXCESS_FACTOR = 0.1 we allow 10% more nodes, i.e 55.
const PEER_EXCESS_FACTOR: f32 = 0.1;

/// Relative factor of peers that are allowed to have a negative gossipsub score without penalizing
/// them in lighthouse.
const ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR: f32 = 0.1;

/// A fraction of `PeerManager::target_peers` that need to be outbound-only connections.
const MIN_OUTBOUND_ONLY_FACTOR: f32 = 0.1;

/// The main struct that handles peer's reputation and connection status.
pub struct PeerManager<TSpec: EthSpec> {
    /// Storage of network globals to access the `PeerDB`.
    network_globals: Arc<NetworkGlobals<TSpec>>,
    /// A queue of events that the `PeerManager` is waiting to produce.
    events: SmallVec<[PeerManagerEvent; 16]>,
    /// A collection of inbound-connected peers awaiting to be Ping'd.
    inbound_ping_peers: HashSetDelay<PeerId>,
    /// A collection of outbound-connected peers awaiting to be Ping'd.
    outbound_ping_peers: HashSetDelay<PeerId>,
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
            inbound_ping_peers: HashSetDelay::new(Duration::from_secs(PING_INTERVAL_INBOUND)),
            outbound_ping_peers: HashSetDelay::new(Duration::from_secs(PING_INTERVAL_OUTBOUND)),
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
        self.events.push(PeerManagerEvent::Dial(*peer_id));
        self.connect_peer(peer_id, ConnectingType::Dialing)
    }

    /// The application layer wants to disconnect from a peer for a particular reason.
    ///
    /// All instant disconnections are fatal and we ban the associated peer.
    ///
    /// This will send a goodbye and disconnect the peer if it is connected or dialing.
    pub fn goodbye_peer(&mut self, peer_id: &PeerId, reason: GoodbyeReason, source: ReportSource) {
        // get the peer info
        if let Some(info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            debug!(self.log, "Sending goodbye to peer"; "peer_id" => %peer_id, "reason" => %reason, "score" => %info.score());
            if matches!(reason, GoodbyeReason::IrrelevantNetwork) {
                info.sync_status.update(PeerSyncStatus::IrrelevantPeer);
            }

            // Goodbye's are fatal
            info.apply_peer_action_to_score(PeerAction::Fatal);
            metrics::inc_counter_vec(
                &metrics::PEER_ACTION_EVENTS_PER_CLIENT,
                &[
                    info.client.kind.as_ref(),
                    PeerAction::Fatal.as_ref(),
                    source.into(),
                ],
            );
        }

        // Update the peerdb and peer state accordingly
        if self
            .network_globals
            .peers
            .write()
            .disconnect_and_ban(peer_id)
        {
            // update the state of the peer.
            self.events
                .push(PeerManagerEvent::DisconnectPeer(*peer_id, reason));
        }
    }

    /// Reports a peer for some action.
    ///
    /// If the peer doesn't exist, log a warning and insert defaults.
    pub fn report_peer(&mut self, peer_id: &PeerId, action: PeerAction, source: ReportSource) {
        // Helper function to avoid any potential deadlocks.
        let mut to_ban_peers = Vec::with_capacity(1);
        let mut to_unban_peers = Vec::with_capacity(1);

        {
            let mut peer_db = self.network_globals.peers.write();
            if let Some(info) = peer_db.peer_info_mut(peer_id) {
                let previous_state = info.score_state();
                info.apply_peer_action_to_score(action);
                metrics::inc_counter_vec(
                    &metrics::PEER_ACTION_EVENTS_PER_CLIENT,
                    &[info.client.kind.as_ref(), action.as_ref(), source.into()],
                );

                Self::handle_score_transitions(
                    previous_state,
                    peer_id,
                    info,
                    &mut to_ban_peers,
                    &mut to_unban_peers,
                    &mut self.events,
                    &self.log,
                );
                if previous_state == info.score_state() {
                    debug!(self.log, "Peer score adjusted"; "peer_id" => %peer_id, "score" => %info.score());
                }
            }
        } // end write lock

        self.ban_and_unban_peers(to_ban_peers, to_unban_peers);
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
        // If discovery is not started or disabled, ignore the request
        if !self.discovery.started {
            return;
        }

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
                    .good_peers_on_subnet(s.subnet_id)
                    .count();
                if peers_on_subnet >= TARGET_SUBNET_PEERS {
                    trace!(
                        self.log,
                        "Discovery query ignored";
                        "subnet_id" => ?s.subnet_id,
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
        if !filtered.is_empty() {
            self.discovery.discover_subnet_peers(filtered);
        }
    }

    /// A STATUS message has been received from a peer. This resets the status timer.
    pub fn peer_statusd(&mut self, peer_id: &PeerId) {
        self.status_peers.insert(*peer_id);
    }

    /// Adds a gossipsub subscription to a peer in the peerdb.
    pub fn add_subscription(&self, peer_id: &PeerId, subnet_id: SubnetId) {
        if let Some(info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            info.subnets.insert(subnet_id);
        }
    }

    /// Removes a gossipsub subscription to a peer in the peerdb.
    pub fn remove_subscription(&self, peer_id: &PeerId, subnet_id: SubnetId) {
        if let Some(info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            info.subnets.remove(&subnet_id);
        }
    }

    /// Removes all gossipsub subscriptions to a peer in the peerdb.
    pub fn remove_all_subscriptions(&self, peer_id: &PeerId) {
        if let Some(info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            info.subnets = Default::default();
        }
    }

    /* Notifications from the Swarm */

    /// Updates the state of the peer as disconnected.
    ///
    /// This is also called when dialing a peer fails.
    pub fn notify_disconnect(&mut self, peer_id: &PeerId) {
        self.network_globals
            .peers
            .write()
            .notify_disconnect(peer_id);

        // remove the ping and status timer for the peer
        self.inbound_ping_peers.remove(peer_id);
        self.outbound_ping_peers.remove(peer_id);
        self.status_peers.remove(peer_id);
    }

    /// A dial attempt has failed.
    ///
    /// NOTE: It can be the case that we are dialing a peer and during the dialing process the peer
    /// connects and the dial attempt later fails. To handle this, we only update the peer_db if
    /// the peer is not already connected.
    pub fn notify_dial_failure(&mut self, peer_id: &PeerId) {
        if !self.network_globals.peers.read().is_connected(peer_id) {
            self.notify_disconnect(peer_id);
            // set peer as disconnected in discovery DHT
            debug!(self.log, "Marking peer disconnected in DHT"; "peer_id" => %peer_id);
            self.discovery.disconnect_peer(peer_id);
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

    /// Reports if a peer is banned or not.
    ///
    /// This is used to determine if we should accept incoming connections.
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        self.network_globals.peers.read().is_banned(peer_id)
    }

    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.network_globals.peers.read().is_connected(peer_id)
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

    /// An error has occurred in the RPC.
    ///
    /// This adjusts a peer's score based on the error.
    pub fn handle_rpc_error(
        &mut self,
        peer_id: &PeerId,
        protocol: Protocol,
        err: &RPCError,
        direction: ConnectionDirection,
    ) {
        let client = self.network_globals.client(peer_id);
        let score = self.network_globals.peers.read().score(peer_id);
        debug!(self.log, "RPC Error"; "protocol" => %protocol, "err" => %err, "client" => %client,
            "peer_id" => %peer_id, "score" => %score, "direction" => ?direction);
        metrics::inc_counter_vec(
            &metrics::TOTAL_RPC_ERRORS_PER_CLIENT,
            &[
                client.kind.as_ref(),
                err.as_static_str(),
                direction.as_ref(),
            ],
        );

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
                RPCResponseErrorCode::ResourceUnavailable => {
                    // NOTE: This error only makes sense for the `BlocksByRange` and `BlocksByRoot`
                    // protocols. For the time being, there is no reason why a peer should send
                    // this error.
                    PeerAction::Fatal
                }
                RPCResponseErrorCode::ServerError => PeerAction::MidToleranceError,
                RPCResponseErrorCode::InvalidRequest => PeerAction::LowToleranceError,
                RPCResponseErrorCode::RateLimited => match protocol {
                    Protocol::Ping => PeerAction::MidToleranceError,
                    Protocol::BlocksByRange => PeerAction::MidToleranceError,
                    Protocol::BlocksByRoot => PeerAction::MidToleranceError,
                    Protocol::Goodbye => PeerAction::LowToleranceError,
                    Protocol::MetaData => PeerAction::LowToleranceError,
                    Protocol::Status => PeerAction::LowToleranceError,
                },
            },
            RPCError::SSZDecodeError(_) => PeerAction::Fatal,
            RPCError::UnsupportedProtocol => {
                // Not supporting a protocol shouldn't be considered a malicious action, but
                // it is an action that in some cases will make the peer unfit to continue
                // communicating.

                match protocol {
                    Protocol::Ping => PeerAction::Fatal,
                    Protocol::BlocksByRange => return,
                    Protocol::BlocksByRoot => return,
                    Protocol::Goodbye => return,
                    Protocol::MetaData => PeerAction::LowToleranceError,
                    Protocol::Status => PeerAction::LowToleranceError,
                }
            }
            RPCError::StreamTimeout => match direction {
                ConnectionDirection::Incoming => {
                    // we timed out
                    warn!(self.log, "Timed out to a peer's request. Likely too many resources, reduce peer count");
                    return;
                }
                ConnectionDirection::Outgoing => match protocol {
                    Protocol::Ping => PeerAction::LowToleranceError,
                    Protocol::BlocksByRange => PeerAction::MidToleranceError,
                    Protocol::BlocksByRoot => PeerAction::MidToleranceError,
                    Protocol::Goodbye => return,
                    Protocol::MetaData => return,
                    Protocol::Status => return,
                },
            },
            RPCError::NegotiationTimeout => PeerAction::LowToleranceError,
        };

        self.report_peer(peer_id, peer_action, ReportSource::RPC);
    }

    /// A ping request has been received.
    // NOTE: The behaviour responds with a PONG automatically
    pub fn ping_request(&mut self, peer_id: &PeerId, seq: u64) {
        if let Some(peer_info) = self.network_globals.peers.read().peer_info(peer_id) {
            // received a ping
            // reset the to-ping timer for this peer
            debug!(self.log, "Received a ping request"; "peer_id" => %peer_id, "seq_no" => seq);
            match peer_info.connection_direction {
                Some(ConnectionDirection::Incoming) => {
                    self.inbound_ping_peers.insert(*peer_id);
                }
                Some(ConnectionDirection::Outgoing) => {
                    self.outbound_ping_peers.insert(*peer_id);
                }
                None => {
                    warn!(self.log, "Received a ping from a peer with an unknown connection direction"; "peer_id" => %peer_id);
                }
            }

            // if the sequence number is unknown send an update the meta data of the peer.
            if let Some(meta_data) = &peer_info.meta_data {
                if meta_data.seq_number < seq {
                    debug!(self.log, "Requesting new metadata from peer";
                        "peer_id" => %peer_id, "known_seq_no" => meta_data.seq_number, "ping_seq_no" => seq);
                    self.events.push(PeerManagerEvent::MetaData(*peer_id));
                }
            } else {
                // if we don't know the meta-data, request it
                debug!(self.log, "Requesting first metadata from peer";
                    "peer_id" => %peer_id);
                self.events.push(PeerManagerEvent::MetaData(*peer_id));
            }
        } else {
            crit!(self.log, "Received a PING from an unknown peer";
                "peer_id" => %peer_id);
        }
    }

    /// A PONG has been returned from a peer.
    pub fn pong_response(&mut self, peer_id: &PeerId, seq: u64) {
        if let Some(peer_info) = self.network_globals.peers.read().peer_info(peer_id) {
            // received a pong

            // if the sequence number is unknown send update the meta data of the peer.
            if let Some(meta_data) = &peer_info.meta_data {
                if meta_data.seq_number < seq {
                    debug!(self.log, "Requesting new metadata from peer";
                        "peer_id" => %peer_id, "known_seq_no" => meta_data.seq_number, "pong_seq_no" => seq);
                    self.events.push(PeerManagerEvent::MetaData(*peer_id));
                }
            } else {
                // if we don't know the meta-data, request it
                debug!(self.log, "Requesting first metadata from peer";
                    "peer_id" => %peer_id);
                self.events.push(PeerManagerEvent::MetaData(*peer_id));
            }
        } else {
            crit!(self.log, "Received a PONG from an unknown peer"; "peer_id" => %peer_id);
        }
    }

    /// Received a metadata response from a peer.
    pub fn meta_data_response(&mut self, peer_id: &PeerId, meta_data: MetaData<TSpec>) {
        if let Some(peer_info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            if let Some(known_meta_data) = &peer_info.meta_data {
                if known_meta_data.seq_number < meta_data.seq_number {
                    debug!(self.log, "Updating peer's metadata";
                        "peer_id" => %peer_id, "known_seq_no" => known_meta_data.seq_number, "new_seq_no" => meta_data.seq_number);
                    peer_info.meta_data = Some(meta_data);
                } else {
                    debug!(self.log, "Received old metadata";
                        "peer_id" => %peer_id, "known_seq_no" => known_meta_data.seq_number, "new_seq_no" => meta_data.seq_number);
                    // Updating metadata even in this case to prevent storing
                    // incorrect  `metadata.attnets` for a peer
                    peer_info.meta_data = Some(meta_data);
                }
            } else {
                // we have no meta-data for this peer, update
                debug!(self.log, "Obtained peer's metadata";
                    "peer_id" => %peer_id, "new_seq_no" => meta_data.seq_number);
                peer_info.meta_data = Some(meta_data);
            }
        } else {
            crit!(self.log, "Received METADATA from an unknown peer";
                "peer_id" => %peer_id);
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
                    .find(|v| matches!(v, MProtocol::Udp(_)))
                    .is_none()
            });

            out_list
        } else {
            // PeerId is not known
            Vec::new()
        }
    }

    pub(crate) fn update_gossipsub_scores(&mut self, gossipsub: &Gossipsub) {
        let mut to_ban_peers = Vec::new();
        let mut to_unban_peers = Vec::new();

        {
            //collect peers with scores
            let mut guard = self.network_globals.peers.write();
            let mut peers: Vec<_> = guard
                .peers_mut()
                .filter_map(|(peer_id, info)| {
                    gossipsub
                        .peer_score(peer_id)
                        .map(|score| (peer_id, info, score))
                })
                .collect();

            // sort descending by score
            peers.sort_unstable_by(|(.., s1), (.., s2)| {
                s2.partial_cmp(s1).unwrap_or(Ordering::Equal)
            });

            let mut to_ignore_negative_peers =
                (self.target_peers as f32 * ALLOWED_NEGATIVE_GOSSIPSUB_FACTOR).ceil() as usize;

            for (peer_id, info, score) in peers {
                let previous_state = info.score_state();
                info.update_gossipsub_score(
                    score,
                    if score < 0.0 && to_ignore_negative_peers > 0 {
                        to_ignore_negative_peers -= 1;
                        // We ignore the negative score for the best negative peers so that their
                        // gossipsub score can recover without getting disconnected.
                        true
                    } else {
                        false
                    },
                );

                Self::handle_score_transitions(
                    previous_state,
                    peer_id,
                    info,
                    &mut to_ban_peers,
                    &mut to_unban_peers,
                    &mut self.events,
                    &self.log,
                );
            }
        } // end write lock

        self.ban_and_unban_peers(to_ban_peers, to_unban_peers);
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
                if predicate(enr) && peers.should_dial(peer_id) {
                    Some(*peer_id)
                } else {
                    None
                }
            })
            .collect();
        for peer_id in &peers_to_dial {
            debug!(self.log, "Dialing cached ENR peer"; "peer_id" => %peer_id);
            self.dial_peer(peer_id);
        }
    }

    /// Peers that have been returned by discovery requests are dialed here if they are suitable.
    ///
    /// NOTE: By dialing `PeerId`s and not multiaddrs, libp2p requests the multiaddr associated
    /// with a new `PeerId` which involves a discovery routing table lookup. We could dial the
    /// multiaddr here, however this could relate to duplicate PeerId's etc. If the lookup
    /// proves resource constraining, we should switch to multiaddr dialling here.
    #[allow(clippy::mutable_key_type)]
    fn peers_discovered(&mut self, results: HashMap<PeerId, Option<Instant>>) {
        let mut to_dial_peers = Vec::new();

        let connected_or_dialing = self.network_globals.connected_or_dialing_peers();
        for (peer_id, min_ttl) in results {
            // we attempt a connection if this peer is a subnet peer or if the max peer count
            // is not yet filled (including dialing peers)
            if (min_ttl.is_some() || connected_or_dialing + to_dial_peers.len() < self.max_peers)
                && self.network_globals.peers.read().should_dial(&peer_id)
            {
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
            debug!(self.log, "Dialing discovered peer"; "peer_id" => %peer_id);
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
            if peerdb.is_banned(&peer_id) {
                // don't connect if the peer is banned
                slog::crit!(self.log, "Connection has been allowed to a banned peer"; "peer_id" => %peer_id);
            }

            let enr = self.discovery.enr_of_peer(peer_id);

            match connection {
                ConnectingType::Dialing => {
                    peerdb.dialing_peer(peer_id, enr);
                    return true;
                }
                ConnectingType::IngoingConnected { multiaddr } => {
                    peerdb.connect_ingoing(peer_id, multiaddr, enr);
                    // start a timer to ping inbound peers.
                    self.inbound_ping_peers.insert(*peer_id);
                }
                ConnectingType::OutgoingConnected { multiaddr } => {
                    peerdb.connect_outgoing(peer_id, multiaddr, enr);
                    // start a timer for to ping outbound peers.
                    self.outbound_ping_peers.insert(*peer_id);
                }
            }
        }

        // start a ping and status timer for the peer
        self.status_peers.insert(*peer_id);

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

    fn handle_score_transitions(
        previous_state: ScoreState,
        peer_id: &PeerId,
        info: &mut PeerInfo<TSpec>,
        to_ban_peers: &mut Vec<PeerId>,
        to_unban_peers: &mut Vec<PeerId>,
        events: &mut SmallVec<[PeerManagerEvent; 16]>,
        log: &slog::Logger,
    ) {
        if previous_state != info.score_state() {
            match info.score_state() {
                ScoreState::Banned => {
                    debug!(log, "Peer has been banned"; "peer_id" => %peer_id, "score" => %info.score());
                    to_ban_peers.push(*peer_id);
                }
                ScoreState::Disconnected => {
                    debug!(log, "Peer transitioned to disconnect state"; "peer_id" => %peer_id, "score" => %info.score(), "past_state" => %previous_state);
                    // disconnect the peer if it's currently connected or dialing
                    if info.is_connected_or_dialing() {
                        // Change the state to inform that we are disconnecting the peer.
                        info.disconnecting(false);
                        events.push(PeerManagerEvent::DisconnectPeer(
                            *peer_id,
                            GoodbyeReason::BadScore,
                        ));
                    } else if info.is_banned() {
                        to_unban_peers.push(*peer_id);
                    }
                }
                ScoreState::Healthy => {
                    debug!(log, "Peer transitioned to healthy state"; "peer_id" => %peer_id, "score" => %info.score(), "past_state" => %previous_state);
                    // unban the peer if it was previously banned.
                    if info.is_banned() {
                        to_unban_peers.push(*peer_id);
                    }
                }
            }
        }
    }

    fn ban_and_unban_peers(&mut self, to_ban_peers: Vec<PeerId>, to_unban_peers: Vec<PeerId>) {
        // process banning peers
        for peer_id in to_ban_peers {
            self.ban_peer(&peer_id);
        }
        // process unbanning peers
        for peer_id in to_unban_peers {
            if let Err(e) = self.unban_peer(&peer_id) {
                error!(self.log, "{}", e; "peer_id" => %peer_id);
            }
        }
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

            Self::handle_score_transitions(
                previous_state,
                peer_id,
                info,
                &mut to_ban_peers,
                &mut to_unban_peers,
                &mut self.events,
                &self.log,
            );
        }
        self.ban_and_unban_peers(to_ban_peers, to_unban_peers);
    }

    /// Bans a peer.
    ///
    /// Records updates the peers connection status and updates the peer db as well as blocks the
    /// peer from participating in discovery and removes them from the routing table.
    fn ban_peer(&mut self, peer_id: &PeerId) {
        {
            // write lock scope
            let mut peer_db = self.network_globals.peers.write();

            if peer_db.disconnect_and_ban(peer_id) {
                // The peer was currently connected, so we start a disconnection.
                self.events.push(PeerManagerEvent::DisconnectPeer(
                    *peer_id,
                    GoodbyeReason::BadScore,
                ));
            }
        } // end write lock

        // take a read lock
        let peer_db = self.network_globals.peers.read();

        let banned_ip_addresses = peer_db
            .peer_info(peer_id)
            .map(|info| {
                info.seen_addresses()
                    .filter(|ip| peer_db.is_ip_banned(ip))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();

        self.discovery.ban_peer(&peer_id, banned_ip_addresses);
    }

    /// Unbans a peer.
    ///
    /// Records updates the peers connection status and updates the peer db as well as removes
    /// previous bans from discovery.
    fn unban_peer(&mut self, peer_id: &PeerId) -> Result<(), &'static str> {
        let mut peer_db = self.network_globals.peers.write();
        peer_db.unban(&peer_id)?;

        let seen_ip_addresses = peer_db
            .peer_info(peer_id)
            .map(|info| info.seen_addresses().collect::<Vec<_>>())
            .unwrap_or_default();

        self.discovery.unban_peer(&peer_id, seen_ip_addresses);
        Ok(())
    }

    /// The Peer manager's heartbeat maintains the peer count and maintains peer reputations.
    ///
    /// It will request discovery queries if the peer count has not reached the desired number of
    /// overall peers, as well as the desired number of outbound-only peers.
    ///
    /// NOTE: Discovery will only add a new query if one isn't already queued.
    fn heartbeat(&mut self) {
        let peer_count = self.network_globals.connected_or_dialing_peers();
        let mut outbound_only_peer_count = self.network_globals.connected_outbound_only_peers();
        let min_outbound_only_target =
            (self.target_peers as f32 * MIN_OUTBOUND_ONLY_FACTOR).ceil() as usize;

        if peer_count < self.target_peers || outbound_only_peer_count < min_outbound_only_target {
            // If we need more peers, queue a discovery lookup.
            if self.discovery.started {
                debug!(self.log, "Starting a new peer discovery query"; "connected_peers" => peer_count, "target_peers" => self.target_peers);
                self.discovery.discover_peers();
            }
        }

        // Updates peer's scores.
        self.update_peer_scores();

        // Keep a list of peers we are disconnecting
        let mut disconnecting_peers = Vec::new();

        let connected_peer_count = self.network_globals.connected_peers();
        if connected_peer_count > self.target_peers {
            // Remove excess peers with the worst scores, but keep subnet peers.
            // Must also ensure that the outbound-only peer count does not go below the minimum threshold.
            outbound_only_peer_count = self.network_globals.connected_outbound_only_peers();
            let mut n_outbound_removed = 0;
            for (peer_id, info) in self
                .network_globals
                .peers
                .read()
                .worst_connected_peers()
                .iter()
                .filter(|(_, info)| !info.has_future_duty())
            {
                if disconnecting_peers.len() == connected_peer_count - self.target_peers {
                    break;
                }
                if info.is_outbound_only() {
                    if min_outbound_only_target < outbound_only_peer_count - n_outbound_removed {
                        n_outbound_removed += 1;
                    } else {
                        continue;
                    }
                }
                disconnecting_peers.push(**peer_id);
            }
        }

        let mut peer_db = self.network_globals.peers.write();
        for peer_id in disconnecting_peers {
            peer_db.notify_disconnecting(&peer_id);
            self.events.push(PeerManagerEvent::DisconnectPeer(
                peer_id,
                GoodbyeReason::TooManyPeers,
            ));
        }
    }
}

impl<TSpec: EthSpec> Stream for PeerManager<TSpec> {
    type Item = PeerManagerEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // perform the heartbeat when necessary
        while self.heartbeat.poll_tick(cx).is_ready() {
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
            match self.inbound_ping_peers.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(peer_id))) => {
                    self.inbound_ping_peers.insert(peer_id);
                    self.events.push(PeerManagerEvent::Ping(peer_id));
                }
                Poll::Ready(Some(Err(e))) => {
                    error!(self.log, "Failed to check for inbound peers to ping"; "error" => e.to_string())
                }
                Poll::Ready(None) | Poll::Pending => break,
            }
        }

        loop {
            match self.outbound_ping_peers.poll_next_unpin(cx) {
                Poll::Ready(Some(Ok(peer_id))) => {
                    self.outbound_ping_peers.insert(peer_id);
                    self.events.push(PeerManagerEvent::Ping(peer_id));
                }
                Poll::Ready(Some(Err(e))) => {
                    error!(self.log, "Failed to check for outbound peers to ping"; "error" => e.to_string())
                }
                Poll::Ready(None) | Poll::Pending => break,
            }
        }

        if !matches!(
            self.network_globals.sync_state(),
            SyncState::SyncingFinalized { .. } | SyncState::SyncingHead { .. }
        ) {
            loop {
                match self.status_peers.poll_next_unpin(cx) {
                    Poll::Ready(Some(Ok(peer_id))) => {
                        self.status_peers.insert(peer_id);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::enr::build_enr;
    use crate::discovery::enr_ext::CombinedKeyExt;
    use crate::rpc::methods::MetaData;
    use crate::Enr;
    use discv5::enr::CombinedKey;
    use slog::{o, Drain};
    use std::net::UdpSocket;
    use types::{EnrForkId, MinimalEthSpec};

    type E = MinimalEthSpec;

    pub fn unused_port() -> u16 {
        let socket = UdpSocket::bind("127.0.0.1:0").expect("should create udp socket");
        let local_addr = socket.local_addr().expect("should read udp socket");
        local_addr.port()
    }

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

    async fn build_peer_manager(target: usize) -> PeerManager<E> {
        let keypair = libp2p::identity::Keypair::generate_secp256k1();
        let config = NetworkConfig {
            discovery_port: unused_port(),
            target_peers: target,
            ..Default::default()
        };
        let enr_key: CombinedKey = CombinedKey::from_libp2p(&keypair).unwrap();
        let enr: Enr = build_enr::<E>(&enr_key, &config, EnrForkId::default()).unwrap();
        let log = build_log(slog::Level::Debug, false);
        let globals = NetworkGlobals::new(
            enr,
            9000,
            9000,
            MetaData {
                seq_number: 0,
                attnets: Default::default(),
            },
            vec![],
            &log,
        );
        PeerManager::new(&keypair, &config, Arc::new(globals), &log)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_peer_manager_disconnects_correctly_during_heartbeat() {
        let mut peer_manager = build_peer_manager(3).await;

        // Create 5 peers to connect to.
        // 2 will be outbound-only, and have the lowest score.
        let peer0 = PeerId::random();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let outbound_only_peer1 = PeerId::random();
        let outbound_only_peer2 = PeerId::random();

        peer_manager.connect_ingoing(&peer0, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager.connect_ingoing(&peer1, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager.connect_ingoing(&peer2, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager.connect_outgoing(&outbound_only_peer1, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager.connect_outgoing(&outbound_only_peer2, "/ip4/0.0.0.0".parse().unwrap());

        // Set the outbound-only peers to have the lowest score.
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&outbound_only_peer1)
            .unwrap()
            .add_to_score(-1.0);

        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&outbound_only_peer2)
            .unwrap()
            .add_to_score(-2.0);

        // Check initial connected peers.
        assert_eq!(peer_manager.network_globals.connected_or_dialing_peers(), 5);

        peer_manager.heartbeat();

        // Check that we disconnected from two peers.
        // Check that one outbound-only peer was removed because it had the worst score
        // and that we did not disconnect the other outbound peer due to the minimum outbound quota.
        assert_eq!(peer_manager.network_globals.connected_or_dialing_peers(), 3);
        assert!(peer_manager
            .network_globals
            .peers
            .read()
            .is_connected(&outbound_only_peer1));
        assert!(!peer_manager
            .network_globals
            .peers
            .read()
            .is_connected(&outbound_only_peer2));

        peer_manager.heartbeat();

        // Check that if we are at target number of peers, we do not disconnect any.
        assert_eq!(peer_manager.network_globals.connected_or_dialing_peers(), 3);
    }

    #[tokio::test]
    async fn test_peer_manager_not_enough_outbound_peers_no_panic_during_heartbeat() {
        let mut peer_manager = build_peer_manager(20).await;

        // Connect to 20 ingoing-only peers.
        for _i in 0..19 {
            let peer = PeerId::random();
            peer_manager.connect_ingoing(&peer, "/ip4/0.0.0.0".parse().unwrap());
        }

        // Connect an outbound-only peer.
        // Give it the lowest score so that it is evaluated first in the disconnect list iterator.
        let outbound_only_peer = PeerId::random();
        peer_manager.connect_ingoing(&outbound_only_peer, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(outbound_only_peer))
            .unwrap()
            .add_to_score(-1.0);
        // After heartbeat, we will have removed one peer.
        // Having less outbound-only peers than minimum won't cause panic when the outbound-only peer is being considered for disconnection.
        peer_manager.heartbeat();
        assert_eq!(
            peer_manager.network_globals.connected_or_dialing_peers(),
            20
        );
    }

    #[tokio::test]
    async fn test_peer_manager_removes_unhealthy_peers_during_heartbeat() {
        let mut peer_manager = build_peer_manager(3).await;

        // Create 3 peers to connect to.
        let peer0 = PeerId::random();
        let inbound_only_peer1 = PeerId::random();
        let outbound_only_peer1 = PeerId::random();

        peer_manager.connect_ingoing(&peer0, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager.connect_outgoing(&peer0, "/ip4/0.0.0.0".parse().unwrap());

        // Connect to two peers that are on the threshold of being disconnected.
        peer_manager.connect_ingoing(&inbound_only_peer1, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager.connect_outgoing(&outbound_only_peer1, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(inbound_only_peer1))
            .unwrap()
            .add_to_score(-19.9);
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(outbound_only_peer1))
            .unwrap()
            .add_to_score(-19.9);
        // Update the gossipsub scores to induce connection downgrade
        // during the heartbeat, update_peer_scores will downgrade the score from -19.9 to at least -20, this will then trigger a disconnection.
        // If we changed the peer scores to -20 before the heartbeat, update_peer_scores will mark the previous score status as disconnected,
        // then handle_state_transitions will not change the connection status to disconnected because the score state has not changed.
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(inbound_only_peer1))
            .unwrap()
            .set_gossipsub_score(-85.0);
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(outbound_only_peer1))
            .unwrap()
            .set_gossipsub_score(-85.0);

        peer_manager.heartbeat();

        assert_eq!(peer_manager.network_globals.connected_or_dialing_peers(), 1);
    }

    #[tokio::test]
    async fn test_peer_manager_remove_unhealthy_peers_brings_peers_below_target() {
        let mut peer_manager = build_peer_manager(3).await;

        // Create 4 peers to connect to.
        // One pair will be unhealthy inbound only and outbound only peers.
        let peer0 = PeerId::random();
        let peer1 = PeerId::random();
        let inbound_only_peer1 = PeerId::random();
        let outbound_only_peer1 = PeerId::random();

        peer_manager.connect_ingoing(&peer0, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager.connect_ingoing(&peer1, "/ip4/0.0.0.0".parse().unwrap());

        // Connect to two peers that are on the threshold of being disconnected.
        peer_manager.connect_ingoing(&inbound_only_peer1, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager.connect_outgoing(&outbound_only_peer1, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(inbound_only_peer1))
            .unwrap()
            .add_to_score(-19.9);
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(outbound_only_peer1))
            .unwrap()
            .add_to_score(-19.9);
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(inbound_only_peer1))
            .unwrap()
            .set_gossipsub_score(-85.0);
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(outbound_only_peer1))
            .unwrap()
            .set_gossipsub_score(-85.0);
        peer_manager.heartbeat();
        // Tests that when we are over the target peer limit, after disconnecting two unhealthy peers,
        // the loop to check for disconnecting peers will stop because we have removed enough peers (only needed to remove 1 to reach target).
        assert_eq!(peer_manager.network_globals.connected_or_dialing_peers(), 2);
    }

    #[tokio::test]
    async fn test_peer_manager_removes_enough_peers_when_one_is_unhealthy() {
        let mut peer_manager = build_peer_manager(3).await;

        // Create 5 peers to connect to.
        // One will be unhealthy inbound only and outbound only peers.
        let peer0 = PeerId::random();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let inbound_only_peer1 = PeerId::random();
        let outbound_only_peer1 = PeerId::random();

        peer_manager.connect_ingoing(&peer0, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager.connect_ingoing(&peer1, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager.connect_ingoing(&peer2, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager.connect_outgoing(&outbound_only_peer1, "/ip4/0.0.0.0".parse().unwrap());
        // Have one peer be on the verge of disconnection.
        peer_manager.connect_ingoing(&inbound_only_peer1, "/ip4/0.0.0.0".parse().unwrap());
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(inbound_only_peer1))
            .unwrap()
            .add_to_score(-19.9);
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(inbound_only_peer1))
            .unwrap()
            .set_gossipsub_score(-85.0);

        peer_manager.heartbeat();
        // Tests that when we are over the target peer limit, after disconnecting an unhealthy peer,
        // the number of connected peers updates and we will not remove too many peers.
        assert_eq!(peer_manager.network_globals.connected_or_dialing_peers(), 3);
    }
}
