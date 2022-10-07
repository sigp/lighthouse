//! Implementation of Lighthouse's peer management system.

use crate::rpc::{GoodbyeReason, MetaData, Protocol, RPCError, RPCResponseErrorCode};
use crate::service::TARGET_SUBNET_PEERS;
use crate::{error, metrics, Gossipsub};
use crate::{NetworkGlobals, PeerId};
use crate::{Subnet, SubnetDiscovery};
use delay_map::HashSetDelay;
use discv5::Enr;
use libp2p::identify::IdentifyInfo;
use peerdb::{client::ClientKind, BanOperation, BanResult, ScoreUpdateResult};
use rand::seq::SliceRandom;
use slog::{debug, error, trace, warn};
use smallvec::SmallVec;
use std::collections::VecDeque;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use strum::IntoEnumIterator;
use types::{EthSpec, SyncSubnetId};

pub use libp2p::core::{identity::Keypair, Multiaddr};

#[allow(clippy::mutable_key_type)] // PeerId in hashmaps are no longer permitted by clippy
pub mod peerdb;

pub use peerdb::peer_info::{
    ConnectionDirection, PeerConnectionStatus, PeerConnectionStatus::*, PeerInfo,
};
use peerdb::score::{PeerAction, ReportSource};
pub use peerdb::sync_status::{SyncInfo, SyncStatus};
use std::collections::{hash_map::Entry, HashMap};
use std::net::IpAddr;
pub mod config;
mod network_behaviour;

/// The heartbeat performs regular updates such as updating reputations and performing discovery
/// requests. This defines the interval in seconds.
const HEARTBEAT_INTERVAL: u64 = 30;

/// This is used in the pruning logic. We avoid pruning peers on sync-committees if doing so would
/// lower our peer count below this number. Instead we favour a non-uniform distribution of subnet
/// peers.
pub const MIN_SYNC_COMMITTEE_PEERS: u64 = 2;
/// A fraction of `PeerManager::target_peers` that we allow to connect to us in excess of
/// `PeerManager::target_peers`. For clarity, if `PeerManager::target_peers` is 50 and
/// PEER_EXCESS_FACTOR = 0.1 we allow 10% more nodes, i.e 55.
pub const PEER_EXCESS_FACTOR: f32 = 0.1;
/// A fraction of `PeerManager::target_peers` that we want to be outbound-only connections.
pub const TARGET_OUTBOUND_ONLY_FACTOR: f32 = 0.3;
/// A fraction of `PeerManager::target_peers` that if we get below, we start a discovery query to
/// reach our target. MIN_OUTBOUND_ONLY_FACTOR must be < TARGET_OUTBOUND_ONLY_FACTOR.
pub const MIN_OUTBOUND_ONLY_FACTOR: f32 = 0.2;
/// The fraction of extra peers beyond the PEER_EXCESS_FACTOR that we allow us to dial for when
/// requiring subnet peers. More specifically, if our target peer limit is 50, and our excess peer
/// limit is 55, and we are at 55 peers, the following parameter provisions a few more slots of
/// dialing priority peers we need for validator duties.
pub const PRIORITY_PEER_EXCESS: f32 = 0.2;

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
    /// Peers queued to be dialed.
    peers_to_dial: VecDeque<(PeerId, Option<Enr>)>,
    /// A collection of sync committee subnets that we need to stay subscribed to.
    /// Sync committee subnets are longer term (256 epochs). Hence, we need to re-run
    /// discovery queries for subnet peers if we disconnect from existing sync
    /// committee subnet peers.
    sync_committee_subnets: HashMap<SyncSubnetId, Instant>,
    /// The heartbeat interval to perform routine maintenance.
    heartbeat: tokio::time::Interval,
    /// Keeps track of whether the discovery service is enabled or not.
    discovery_enabled: bool,
    /// Keeps track if the current instance is reporting metrics or not.
    metrics_enabled: bool,
    /// The logger associated with the `PeerManager`.
    log: slog::Logger,
}

/// The events that the `PeerManager` outputs (requests).
#[derive(Debug)]
pub enum PeerManagerEvent {
    /// A peer has dialed us.
    PeerConnectedIncoming(PeerId),
    /// A peer has been dialed.
    PeerConnectedOutgoing(PeerId),
    /// A peer has disconnected.
    PeerDisconnected(PeerId),
    /// Sends a STATUS to a peer.
    Status(PeerId),
    /// Sends a PING to a peer.
    Ping(PeerId),
    /// Request METADATA from a peer.
    MetaData(PeerId),
    /// The peer should be disconnected.
    DisconnectPeer(PeerId, GoodbyeReason),
    /// Inform the behaviour to ban this peer and associated ip addresses.
    Banned(PeerId, Vec<IpAddr>),
    /// The peer should be unbanned with the associated ip addresses.
    UnBanned(PeerId, Vec<IpAddr>),
    /// Request the behaviour to discover more peers and the amount of peers to discover.
    DiscoverPeers(usize),
    /// Request the behaviour to discover peers on subnets.
    DiscoverSubnetPeers(Vec<SubnetDiscovery>),
}

impl<TSpec: EthSpec> PeerManager<TSpec> {
    // NOTE: Must be run inside a tokio executor.
    pub fn new(
        cfg: config::Config,
        network_globals: Arc<NetworkGlobals<TSpec>>,
        log: &slog::Logger,
    ) -> error::Result<Self> {
        let config::Config {
            discovery_enabled,
            metrics_enabled,
            target_peer_count,
            status_interval,
            ping_interval_inbound,
            ping_interval_outbound,
        } = cfg;

        // Set up the peer manager heartbeat interval
        let heartbeat = tokio::time::interval(tokio::time::Duration::from_secs(HEARTBEAT_INTERVAL));

        Ok(PeerManager {
            network_globals,
            events: SmallVec::new(),
            peers_to_dial: Default::default(),
            inbound_ping_peers: HashSetDelay::new(Duration::from_secs(ping_interval_inbound)),
            outbound_ping_peers: HashSetDelay::new(Duration::from_secs(ping_interval_outbound)),
            status_peers: HashSetDelay::new(Duration::from_secs(status_interval)),
            target_peers: target_peer_count,
            sync_committee_subnets: Default::default(),
            heartbeat,
            discovery_enabled,
            metrics_enabled,
            log: log.clone(),
        })
    }

    /* Public accessible functions */

    /// The application layer wants to disconnect from a peer for a particular reason.
    ///
    /// All instant disconnections are fatal and we ban the associated peer.
    ///
    /// This will send a goodbye and disconnect the peer if it is connected or dialing.
    pub fn goodbye_peer(&mut self, peer_id: &PeerId, reason: GoodbyeReason, source: ReportSource) {
        // Update the sync status if required
        if let Some(info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            debug!(self.log, "Sending goodbye to peer"; "peer_id" => %peer_id, "reason" => %reason, "score" => %info.score());
            if matches!(reason, GoodbyeReason::IrrelevantNetwork) {
                info.update_sync_status(SyncStatus::IrrelevantPeer);
            }
        }

        self.report_peer(
            peer_id,
            PeerAction::Fatal,
            source,
            Some(reason),
            "goodbye_peer",
        );
    }

    /// Reports a peer for some action.
    ///
    /// If the peer doesn't exist, log a warning and insert defaults.
    pub fn report_peer(
        &mut self,
        peer_id: &PeerId,
        action: PeerAction,
        source: ReportSource,
        reason: Option<GoodbyeReason>,
        msg: &'static str,
    ) {
        let action = self
            .network_globals
            .peers
            .write()
            .report_peer(peer_id, action, source, msg);
        self.handle_score_action(peer_id, action, reason);
    }

    /// Upon adjusting a Peer's score, there are times the peer manager must pass messages up to
    /// libp2p. This function handles the conditional logic associated with each score update
    /// result.
    fn handle_score_action(
        &mut self,
        peer_id: &PeerId,
        action: ScoreUpdateResult,
        reason: Option<GoodbyeReason>,
    ) {
        match action {
            ScoreUpdateResult::Ban(ban_operation) => {
                // The peer has been banned and we need to handle the banning operation
                // NOTE: When we ban a peer, its IP address can be banned. We do not recursively search
                // through all our connected peers banning all other peers that are using this IP address.
                // If these peers are behaving fine, we permit their current connections. However, if any new
                // nodes or current nodes try to reconnect on a banned IP, they will be instantly banned
                // and disconnected.
                self.handle_ban_operation(peer_id, ban_operation, reason);
            }
            ScoreUpdateResult::Disconnect => {
                // The peer has transitioned to a disconnect state and has been marked as such in
                // the peer db. We must inform libp2p to disconnect this peer.
                self.inbound_ping_peers.remove(peer_id);
                self.outbound_ping_peers.remove(peer_id);
                self.events.push(PeerManagerEvent::DisconnectPeer(
                    *peer_id,
                    GoodbyeReason::BadScore,
                ));
            }
            ScoreUpdateResult::NoAction => {
                // The report had no effect on the peer and there is nothing to do.
            }
            ScoreUpdateResult::Unbanned(unbanned_ips) => {
                // Inform the Swarm to unban the peer
                self.events
                    .push(PeerManagerEvent::UnBanned(*peer_id, unbanned_ips));
            }
        }
    }

    /// If a peer is being banned, this handles the banning operation.
    fn handle_ban_operation(
        &mut self,
        peer_id: &PeerId,
        ban_operation: BanOperation,
        reason: Option<GoodbyeReason>,
    ) {
        match ban_operation {
            BanOperation::DisconnectThePeer => {
                // The peer was currently connected, so we start a disconnection.
                // Once the peer has disconnected, its connection state will transition to a
                // banned state.
                self.events.push(PeerManagerEvent::DisconnectPeer(
                    *peer_id,
                    reason.unwrap_or(GoodbyeReason::BadScore),
                ));
            }
            BanOperation::PeerDisconnecting => {
                // The peer is currently being disconnected and will be banned once the
                // disconnection completes.
            }
            BanOperation::ReadyToBan(banned_ips) => {
                // The peer is not currently connected, we can safely ban it at the swarm
                // level.
                // Inform the Swarm to ban the peer
                self.events
                    .push(PeerManagerEvent::Banned(*peer_id, banned_ips));
            }
        }
    }

    /// Peers that have been returned by discovery requests that are suitable for dialing are
    /// returned here.
    ///
    /// NOTE: By dialing `PeerId`s and not multiaddrs, libp2p requests the multiaddr associated
    /// with a new `PeerId` which involves a discovery routing table lookup. We could dial the
    /// multiaddr here, however this could relate to duplicate PeerId's etc. If the lookup
    /// proves resource constraining, we should switch to multiaddr dialling here.
    #[allow(clippy::mutable_key_type)]
    pub fn peers_discovered(&mut self, results: HashMap<PeerId, Option<Instant>>) -> Vec<PeerId> {
        let mut to_dial_peers = Vec::new();

        let connected_or_dialing = self.network_globals.connected_or_dialing_peers();
        for (peer_id, min_ttl) in results {
            // There are two conditions in deciding whether to dial this peer.
            // 1. If we are less than our max connections. Discovery queries are executed to reach
            //    our target peers, so its fine to dial up to our max peers (which will get pruned
            //    in the next heartbeat down to our target).
            // 2. If the peer is one our validators require for a specific subnet, then it is
            //    considered a priority. We have pre-allocated some extra priority slots for these
            //    peers as specified by PRIORITY_PEER_EXCESS. Therefore we dial these peers, even
            //    if we are already at our max_peer limit.
            if (min_ttl.is_some()
                && connected_or_dialing + to_dial_peers.len() < self.max_priority_peers()
                || connected_or_dialing + to_dial_peers.len() < self.max_peers())
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

        // Queue another discovery if we need to
        self.maintain_peer_count(to_dial_peers.len());

        to_dial_peers
    }

    /// A STATUS message has been received from a peer. This resets the status timer.
    pub fn peer_statusd(&mut self, peer_id: &PeerId) {
        self.status_peers.insert(*peer_id);
    }

    /// Insert the sync subnet into list of long lived sync committee subnets that we need to
    /// maintain adequate number of peers for.
    pub fn add_sync_subnet(&mut self, subnet_id: SyncSubnetId, min_ttl: Instant) {
        match self.sync_committee_subnets.entry(subnet_id) {
            Entry::Vacant(_) => {
                self.sync_committee_subnets.insert(subnet_id, min_ttl);
            }
            Entry::Occupied(old) => {
                if *old.get() < min_ttl {
                    self.sync_committee_subnets.insert(subnet_id, min_ttl);
                }
            }
        }
    }

    /// The maximum number of peers we allow to connect to us. This is `target_peers` * (1 +
    /// PEER_EXCESS_FACTOR)
    fn max_peers(&self) -> usize {
        (self.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR)).ceil() as usize
    }

    /// The maximum number of peers we allow when dialing a priority peer (i.e a peer that is
    /// subscribed to subnets that our validator requires. This is `target_peers` * (1 +
    /// PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS)
    fn max_priority_peers(&self) -> usize {
        (self.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS)).ceil()
            as usize
    }

    /// The minimum number of outbound peers that we reach before we start another discovery query.
    fn min_outbound_only_peers(&self) -> usize {
        (self.target_peers as f32 * MIN_OUTBOUND_ONLY_FACTOR).ceil() as usize
    }

    /// The minimum number of outbound peers that we reach before we start another discovery query.
    fn target_outbound_peers(&self) -> usize {
        (self.target_peers as f32 * TARGET_OUTBOUND_ONLY_FACTOR).ceil() as usize
    }

    /// The maximum number of peers that are connected or dialing before we refuse to do another
    /// discovery search for more outbound peers. We can use up to half the priority peer excess allocation.
    fn max_outbound_dialing_peers(&self) -> usize {
        (self.target_peers as f32 * (1.0 + PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS / 2.0)).ceil()
            as usize
    }

    /* Notifications from the Swarm */

    // A peer is being dialed.
    pub fn dial_peer(&mut self, peer_id: &PeerId, enr: Option<Enr>) {
        self.peers_to_dial.push_back((*peer_id, enr));
    }

    /// Reports if a peer is banned or not.
    ///
    /// This is used to determine if we should accept incoming connections.
    pub fn ban_status(&self, peer_id: &PeerId) -> BanResult {
        self.network_globals.peers.read().ban_status(peer_id)
    }

    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.network_globals.peers.read().is_connected(peer_id)
    }

    /// Reports whether the peer limit is reached in which case we stop allowing new incoming
    /// connections.
    pub fn peer_limit_reached(&self, count_dialing: bool) -> bool {
        if count_dialing {
            // This is an incoming connection so limit by the standard max peers
            self.network_globals.connected_or_dialing_peers() >= self.max_peers()
        } else {
            // We dialed this peer, allow up to max_outbound_dialing_peers
            self.network_globals.connected_peers() >= self.max_outbound_dialing_peers()
        }
    }

    /// Updates `PeerInfo` with `identify` information.
    pub fn identify(&mut self, peer_id: &PeerId, info: &IdentifyInfo) {
        if let Some(peer_info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            let previous_kind = peer_info.client().kind;
            let previous_listening_addresses =
                peer_info.set_listening_addresses(info.listen_addrs.clone());
            peer_info.set_client(peerdb::client::Client::from_identify_info(info));

            if previous_kind != peer_info.client().kind
                || *peer_info.listening_addresses() != previous_listening_addresses
            {
                debug!(self.log, "Identified Peer"; "peer" => %peer_id,
                    "protocol_version" => &info.protocol_version,
                    "agent_version" => &info.agent_version,
                    "listening_ addresses" => ?info.listen_addrs,
                    "observed_address" => ?info.observed_addr,
                    "protocols" => ?info.protocols
                );

                // update the peer client kind metric if the peer is connected
                if matches!(
                    peer_info.connection_status(),
                    PeerConnectionStatus::Connected { .. }
                        | PeerConnectionStatus::Disconnecting { .. }
                ) {
                    metrics::inc_gauge_vec(
                        &metrics::PEERS_PER_CLIENT,
                        &[peer_info.client().kind.as_ref()],
                    );
                    metrics::dec_gauge_vec(&metrics::PEERS_PER_CLIENT, &[previous_kind.as_ref()]);
                }
            }
        } else {
            error!(self.log, "Received an Identify response from an unknown peer"; "peer_id" => peer_id.to_string());
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
            RPCError::InternalError(e) => {
                debug!(self.log, "Internal RPC Error"; "error" => %e, "peer_id" => %peer_id);
                return;
            }
            RPCError::HandlerRejected => PeerAction::Fatal,
            RPCError::InvalidData(_) => {
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
                    // protocols.
                    //
                    // If we are syncing, there is no point keeping these peers around and
                    // continually failing to request blocks. We instantly ban them and hope that
                    // by the time the ban lifts, the peers will have completed their backfill
                    // sync.
                    //
                    // TODO: Potentially a more graceful way of handling such peers, would be to
                    // implement a new sync type which tracks these peers and prevents the sync
                    // algorithms from requesting blocks from them (at least for a set period of
                    // time, multiple failures would then lead to a ban).

                    match direction {
                        // If the blocks request was initiated by us, then we have no use of this
                        // peer and so we ban it.
                        ConnectionDirection::Outgoing => PeerAction::Fatal,
                        // If the blocks request was initiated by the peer, then we let the peer decide if
                        // it wants to continue talking to us, we do not ban the peer.
                        ConnectionDirection::Incoming => return,
                    }
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
                    // There was a timeout responding to a peer.
                    debug!(self.log, "Timed out responding to RPC Request"; "peer_id" => %peer_id);
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
            RPCError::Disconnected => return, // No penalty for a graceful disconnection
        };

        self.report_peer(
            peer_id,
            peer_action,
            ReportSource::RPC,
            None,
            "handle_rpc_error",
        );
    }

    /// A ping request has been received.
    // NOTE: The behaviour responds with a PONG automatically
    pub fn ping_request(&mut self, peer_id: &PeerId, seq: u64) {
        if let Some(peer_info) = self.network_globals.peers.read().peer_info(peer_id) {
            // received a ping
            // reset the to-ping timer for this peer
            trace!(self.log, "Received a ping request"; "peer_id" => %peer_id, "seq_no" => seq);
            match peer_info.connection_direction() {
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
            if let Some(meta_data) = &peer_info.meta_data() {
                if *meta_data.seq_number() < seq {
                    trace!(self.log, "Requesting new metadata from peer";
                        "peer_id" => %peer_id, "known_seq_no" => meta_data.seq_number(), "ping_seq_no" => seq);
                    self.events.push(PeerManagerEvent::MetaData(*peer_id));
                }
            } else {
                // if we don't know the meta-data, request it
                debug!(self.log, "Requesting first metadata from peer";
                    "peer_id" => %peer_id);
                self.events.push(PeerManagerEvent::MetaData(*peer_id));
            }
        } else {
            error!(self.log, "Received a PING from an unknown peer";
                "peer_id" => %peer_id);
        }
    }

    /// A PONG has been returned from a peer.
    pub fn pong_response(&mut self, peer_id: &PeerId, seq: u64) {
        if let Some(peer_info) = self.network_globals.peers.read().peer_info(peer_id) {
            // received a pong

            // if the sequence number is unknown send update the meta data of the peer.
            if let Some(meta_data) = &peer_info.meta_data() {
                if *meta_data.seq_number() < seq {
                    trace!(self.log, "Requesting new metadata from peer";
                        "peer_id" => %peer_id, "known_seq_no" => meta_data.seq_number(), "pong_seq_no" => seq);
                    self.events.push(PeerManagerEvent::MetaData(*peer_id));
                }
            } else {
                // if we don't know the meta-data, request it
                trace!(self.log, "Requesting first metadata from peer";
                    "peer_id" => %peer_id);
                self.events.push(PeerManagerEvent::MetaData(*peer_id));
            }
        } else {
            error!(self.log, "Received a PONG from an unknown peer"; "peer_id" => %peer_id);
        }
    }

    /// Received a metadata response from a peer.
    pub fn meta_data_response(&mut self, peer_id: &PeerId, meta_data: MetaData<TSpec>) {
        if let Some(peer_info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            if let Some(known_meta_data) = &peer_info.meta_data() {
                if *known_meta_data.seq_number() < *meta_data.seq_number() {
                    trace!(self.log, "Updating peer's metadata";
                        "peer_id" => %peer_id, "known_seq_no" => known_meta_data.seq_number(), "new_seq_no" => meta_data.seq_number());
                } else {
                    trace!(self.log, "Received old metadata";
                        "peer_id" => %peer_id, "known_seq_no" => known_meta_data.seq_number(), "new_seq_no" => meta_data.seq_number());
                    // Updating metadata even in this case to prevent storing
                    // incorrect  `attnets/syncnets` for a peer
                }
            } else {
                // we have no meta-data for this peer, update
                debug!(self.log, "Obtained peer's metadata";
                    "peer_id" => %peer_id, "new_seq_no" => meta_data.seq_number());
            }
            peer_info.set_meta_data(meta_data);
        } else {
            error!(self.log, "Received METADATA from an unknown peer";
                "peer_id" => %peer_id);
        }
    }

    /// Updates the gossipsub scores for all known peers in gossipsub.
    pub(crate) fn update_gossipsub_scores(&mut self, gossipsub: &Gossipsub) {
        let actions = self
            .network_globals
            .peers
            .write()
            .update_gossipsub_scores(self.target_peers, gossipsub);

        for (peer_id, score_action) in actions {
            self.handle_score_action(&peer_id, score_action, None);
        }
    }

    // This function updates metrics for all connected peers.
    fn update_connected_peer_metrics(&self) {
        // Do nothing if we don't have metrics enabled.
        if !self.metrics_enabled {
            return;
        }

        let mut connected_peer_count = 0;
        let mut inbound_connected_peers = 0;
        let mut outbound_connected_peers = 0;
        let mut clients_per_peer = HashMap::new();

        for (_peer, peer_info) in self.network_globals.peers.read().connected_peers() {
            connected_peer_count += 1;
            if let PeerConnectionStatus::Connected { n_in, .. } = peer_info.connection_status() {
                if *n_in > 0 {
                    inbound_connected_peers += 1;
                } else {
                    outbound_connected_peers += 1;
                }
            }
            *clients_per_peer
                .entry(peer_info.client().kind.to_string())
                .or_default() += 1;
        }

        metrics::set_gauge(&metrics::PEERS_CONNECTED, connected_peer_count);
        metrics::set_gauge(&metrics::NETWORK_INBOUND_PEERS, inbound_connected_peers);
        metrics::set_gauge(&metrics::NETWORK_OUTBOUND_PEERS, outbound_connected_peers);

        for client_kind in ClientKind::iter() {
            let value = clients_per_peer.get(&client_kind.to_string()).unwrap_or(&0);
            metrics::set_gauge_vec(
                &metrics::PEERS_PER_CLIENT,
                &[client_kind.as_ref()],
                *value as i64,
            );
        }
    }

    /* Internal functions */

    /// Sets a peer as connected as long as their reputation allows it
    /// Informs if the peer was accepted
    fn inject_connect_ingoing(
        &mut self,
        peer_id: &PeerId,
        multiaddr: Multiaddr,
        enr: Option<Enr>,
    ) -> bool {
        self.inject_peer_connection(peer_id, ConnectingType::IngoingConnected { multiaddr }, enr)
    }

    /// Sets a peer as connected as long as their reputation allows it
    /// Informs if the peer was accepted
    fn inject_connect_outgoing(
        &mut self,
        peer_id: &PeerId,
        multiaddr: Multiaddr,
        enr: Option<Enr>,
    ) -> bool {
        self.inject_peer_connection(
            peer_id,
            ConnectingType::OutgoingConnected { multiaddr },
            enr,
        )
    }

    /// Updates the state of the peer as disconnected.
    ///
    /// This is also called when dialing a peer fails.
    fn inject_disconnect(&mut self, peer_id: &PeerId) {
        let (ban_operation, purged_peers) = self
            .network_globals
            .peers
            .write()
            .inject_disconnect(peer_id);

        if let Some(ban_operation) = ban_operation {
            // The peer was awaiting a ban, continue to ban the peer.
            self.handle_ban_operation(peer_id, ban_operation, None);
        }

        // Remove the ping and status timer for the peer
        self.inbound_ping_peers.remove(peer_id);
        self.outbound_ping_peers.remove(peer_id);
        self.status_peers.remove(peer_id);
        self.events.extend(
            purged_peers
                .into_iter()
                .map(|(peer_id, unbanned_ips)| PeerManagerEvent::UnBanned(peer_id, unbanned_ips)),
        );
    }

    /// Registers a peer as connected. The `ingoing` parameter determines if the peer is being
    /// dialed or connecting to us.
    ///
    /// This is called by `connect_ingoing` and `connect_outgoing`.
    ///
    /// Informs if the peer was accepted in to the db or not.
    fn inject_peer_connection(
        &mut self,
        peer_id: &PeerId,
        connection: ConnectingType,
        enr: Option<Enr>,
    ) -> bool {
        {
            let mut peerdb = self.network_globals.peers.write();
            if !matches!(peerdb.ban_status(peer_id), BanResult::NotBanned) {
                // don't connect if the peer is banned
                error!(self.log, "Connection has been allowed to a banned peer"; "peer_id" => %peer_id);
            }

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

        let connected_peers = self.network_globals.connected_peers() as i64;

        // increment prometheus metrics
        metrics::inc_counter(&metrics::PEER_CONNECT_EVENT_COUNT);
        metrics::set_gauge(&metrics::PEERS_CONNECTED, connected_peers);

        true
    }

    // Gracefully disconnects a peer without banning them.
    fn disconnect_peer(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        self.events
            .push(PeerManagerEvent::DisconnectPeer(peer_id, reason));
        self.network_globals
            .peers
            .write()
            .notify_disconnecting(&peer_id, false);
    }

    /// Run discovery query for additional sync committee peers if we fall below `TARGET_PEERS`.
    fn maintain_sync_committee_peers(&mut self) {
        // Remove expired entries
        self.sync_committee_subnets
            .retain(|_, v| *v > Instant::now());

        let subnets_to_discover: Vec<SubnetDiscovery> = self
            .sync_committee_subnets
            .iter()
            .filter_map(|(k, v)| {
                if self
                    .network_globals
                    .peers
                    .read()
                    .good_peers_on_subnet(Subnet::SyncCommittee(*k))
                    .count()
                    < TARGET_SUBNET_PEERS
                {
                    Some(SubnetDiscovery {
                        subnet: Subnet::SyncCommittee(*k),
                        min_ttl: Some(*v),
                    })
                } else {
                    None
                }
            })
            .collect();

        // request the subnet query from discovery
        if !subnets_to_discover.is_empty() {
            debug!(
                self.log,
                "Making subnet queries for maintaining sync committee peers";
                "subnets" => ?subnets_to_discover.iter().map(|s| s.subnet).collect::<Vec<_>>()
            );
            self.events
                .push(PeerManagerEvent::DiscoverSubnetPeers(subnets_to_discover));
        }
    }

    /// This function checks the status of our current peers and optionally requests a discovery
    /// query if we need to find more peers to maintain the current number of peers
    fn maintain_peer_count(&mut self, dialing_peers: usize) {
        // Check if we need to do a discovery lookup
        if self.discovery_enabled {
            let peer_count = self.network_globals.connected_or_dialing_peers();
            let outbound_only_peer_count = self.network_globals.connected_outbound_only_peers();
            let wanted_peers = if peer_count < self.target_peers.saturating_sub(dialing_peers) {
                // We need more peers in general.
                // Note: The maximum discovery query is bounded by `Discovery`.
                self.target_peers.saturating_sub(dialing_peers) - peer_count
            } else if outbound_only_peer_count < self.min_outbound_only_peers()
                && peer_count < self.max_outbound_dialing_peers()
            {
                self.max_outbound_dialing_peers()
                    .saturating_sub(dialing_peers)
                    - peer_count
            } else {
                0
            };

            if wanted_peers != 0 {
                // We need more peers, re-queue a discovery lookup.
                debug!(self.log, "Starting a new peer discovery query"; "connected" => peer_count, "target" => self.target_peers, "outbound" => outbound_only_peer_count, "wanted" => wanted_peers);
                self.events
                    .push(PeerManagerEvent::DiscoverPeers(wanted_peers));
            }
        }
    }

    /// Remove excess peers back down to our target values.
    /// This prioritises peers with a good score and uniform distribution of peers across
    /// subnets.
    ///
    /// The logic for the peer pruning is as follows:
    ///
    /// Global rules:
    /// - Always maintain peers we need for a validator duty.
    /// - Do not prune outbound peers to exceed our outbound target.
    /// - Do not prune more peers than our target peer count.
    /// - If we have an option to remove a number of peers, remove ones that have the least
    ///     long-lived subnets.
    /// - When pruning peers based on subnet count. If multiple peers can be chosen, choose a peer
    ///     that is not subscribed to a long-lived sync committee subnet.
    /// - When pruning peers based on subnet count, do not prune a peer that would lower us below the
    ///     MIN_SYNC_COMMITTEE_PEERS peer count. To keep it simple, we favour a minimum number of sync-committee-peers over
    ///     uniformity subnet peers. NOTE: We could apply more sophisticated logic, but the code is
    ///     simpler and easier to maintain if we take this approach. If we are pruning subnet peers
    ///     below the MIN_SYNC_COMMITTEE_PEERS and maintaining the sync committee peers, this should be
    ///     fine as subnet peers are more likely to be found than sync-committee-peers. Also, we're
    ///     in a bit of trouble anyway if we have so few peers on subnets. The
    ///     MIN_SYNC_COMMITTEE_PEERS
    ///     number should be set low as an absolute lower bound to maintain peers on the sync
    ///     committees.
    ///
    /// Prune peers in the following order:
    /// 1. Remove worst scoring peers
    /// 2. Remove peers that are not subscribed to a subnet (they have less value)
    /// 3. Remove peers that we have many on any particular subnet
    /// 4. Randomly remove peers if all the above are satisfied
    ///
    fn prune_excess_peers(&mut self) {
        // The current number of connected peers.
        let connected_peer_count = self.network_globals.connected_peers();
        if connected_peer_count <= self.target_peers {
            // No need to prune peers
            return;
        }

        // Keep a list of peers we are pruning.
        let mut peers_to_prune = std::collections::HashSet::new();
        let connected_outbound_peer_count = self.network_globals.connected_outbound_only_peers();

        // Keep track of the number of outbound peers we are pruning.
        let mut outbound_peers_pruned = 0;

        macro_rules! prune_peers {
            ($filter: expr) => {
                for (peer_id, info) in self
                    .network_globals
                    .peers
                    .read()
                    .worst_connected_peers()
                    .iter()
                    .filter(|(_, info)| !info.has_future_duty() && $filter(*info))
                {
                    if peers_to_prune.len()
                        >= connected_peer_count.saturating_sub(self.target_peers)
                    {
                        // We have found all the peers we need to drop, end.
                        break;
                    }
                    if peers_to_prune.contains(*peer_id) {
                        continue;
                    }
                    // Only remove up to the target outbound peer count.
                    if info.is_outbound_only() {
                        if self.target_outbound_peers() + outbound_peers_pruned
                            < connected_outbound_peer_count
                        {
                            outbound_peers_pruned += 1;
                        } else {
                            continue;
                        }
                    }
                    peers_to_prune.insert(**peer_id);
                }
            };
        }

        // 1. Look through peers that have the worst score (ignoring non-penalized scored peers).
        prune_peers!(|info: &PeerInfo<TSpec>| { info.score().score() < 0.0 });

        // 2. Attempt to remove peers that are not subscribed to a subnet, if we still need to
        //    prune more.
        if peers_to_prune.len() < connected_peer_count.saturating_sub(self.target_peers) {
            prune_peers!(|info: &PeerInfo<TSpec>| { !info.has_long_lived_subnet() });
        }

        // 3. and 4. Remove peers that are too grouped on any given subnet. If all subnets are
        //    uniformly distributed, remove random peers.
        if peers_to_prune.len() < connected_peer_count.saturating_sub(self.target_peers) {
            // Of our connected peers, build a map from subnet_id -> Vec<(PeerId, PeerInfo)>
            let mut subnet_to_peer: HashMap<Subnet, Vec<(PeerId, PeerInfo<TSpec>)>> =
                HashMap::new();
            // These variables are used to track if a peer is in a long-lived sync-committee as we
            // may wish to retain this peer over others when pruning.
            let mut sync_committee_peer_count: HashMap<SyncSubnetId, u64> = HashMap::new();
            let mut peer_to_sync_committee: HashMap<
                PeerId,
                std::collections::HashSet<SyncSubnetId>,
            > = HashMap::new();

            for (peer_id, info) in self.network_globals.peers.read().connected_peers() {
                // Ignore peers we are already pruning
                if peers_to_prune.contains(peer_id) {
                    continue;
                }

                // Count based on long-lived subnets not short-lived subnets
                // NOTE: There are only 4 sync committees. These are likely to be denser than the
                // subnets, so our priority here to make the subnet peer count uniform, ignoring
                // the dense sync committees.
                for subnet in info.long_lived_subnets() {
                    match subnet {
                        Subnet::Attestation(_) => {
                            subnet_to_peer
                                .entry(subnet)
                                .or_insert_with(Vec::new)
                                .push((*peer_id, info.clone()));
                        }
                        Subnet::SyncCommittee(id) => {
                            *sync_committee_peer_count.entry(id).or_default() += 1;
                            peer_to_sync_committee
                                .entry(*peer_id)
                                .or_default()
                                .insert(id);
                        }
                    }
                }
            }

            // Add to the peers to prune mapping
            while peers_to_prune.len() < connected_peer_count.saturating_sub(self.target_peers) {
                if let Some((_, peers_on_subnet)) = subnet_to_peer
                    .iter_mut()
                    .max_by_key(|(_, peers)| peers.len())
                {
                    // and the subnet still contains peers
                    if !peers_on_subnet.is_empty() {
                        // Order the peers by the number of subnets they are long-lived
                        // subscribed too, shuffle equal peers.
                        peers_on_subnet.shuffle(&mut rand::thread_rng());
                        peers_on_subnet.sort_by_key(|(_, info)| info.long_lived_subnet_count());

                        // Try and find a candidate peer to remove from the subnet.
                        // We ignore peers that would put us below our target outbound peers
                        // and we currently ignore peers that would put us below our
                        // sync-committee threshold, if we can avoid it.

                        let mut removed_peer_index = None;
                        for (index, (candidate_peer, info)) in peers_on_subnet.iter().enumerate() {
                            // Ensure we don't remove too many outbound peers
                            if info.is_outbound_only()
                                && self.target_outbound_peers()
                                    >= connected_outbound_peer_count
                                        .saturating_sub(outbound_peers_pruned)
                            {
                                // Restart the main loop with the outbound peer removed from
                                // the list. This will lower the peers per subnet count and
                                // potentially a new subnet may be chosen to remove peers. This
                                // can occur recursively until we have no peers left to choose
                                // from.
                                continue;
                            }

                            // Check the sync committee
                            if let Some(subnets) = peer_to_sync_committee.get(candidate_peer) {
                                // The peer is subscribed to some long-lived sync-committees
                                // Of all the subnets this peer is subscribed too, the minimum
                                // peer count of all of them is min_subnet_count
                                if let Some(min_subnet_count) = subnets
                                    .iter()
                                    .filter_map(|v| sync_committee_peer_count.get(v).copied())
                                    .min()
                                {
                                    // If the minimum count is our target or lower, we
                                    // shouldn't remove this peer, because it drops us lower
                                    // than our target
                                    if min_subnet_count <= MIN_SYNC_COMMITTEE_PEERS {
                                        // Do not drop this peer in this pruning interval
                                        continue;
                                    }
                                }
                            }

                            if info.is_outbound_only() {
                                outbound_peers_pruned += 1;
                            }
                            // This peer is suitable to be pruned
                            removed_peer_index = Some(index);
                            break;
                        }

                        // If we have successfully found a candidate peer to prune, prune it,
                        // otherwise all peers on this subnet should not be removed due to our
                        // outbound limit or min_subnet_count. In this case, we remove all
                        // peers from the pruning logic and try another subnet.
                        if let Some(index) = removed_peer_index {
                            let (candidate_peer, _) = peers_on_subnet.remove(index);
                            // Remove pruned peers from other subnet counts
                            for subnet_peers in subnet_to_peer.values_mut() {
                                subnet_peers.retain(|(peer_id, _)| peer_id != &candidate_peer);
                            }
                            // Remove pruned peers from all sync-committee counts
                            if let Some(known_sync_committes) =
                                peer_to_sync_committee.get(&candidate_peer)
                            {
                                for sync_committee in known_sync_committes {
                                    if let Some(sync_committee_count) =
                                        sync_committee_peer_count.get_mut(sync_committee)
                                    {
                                        *sync_committee_count =
                                            sync_committee_count.saturating_sub(1);
                                    }
                                }
                            }
                            peers_to_prune.insert(candidate_peer);
                        } else {
                            peers_on_subnet.clear();
                        }
                        continue;
                    }
                }
                // If there are no peers left to prune exit.
                break;
            }
        }

        // Disconnect the pruned peers.
        for peer_id in peers_to_prune {
            self.disconnect_peer(peer_id, GoodbyeReason::TooManyPeers);
        }
    }

    /// The Peer manager's heartbeat maintains the peer count and maintains peer reputations.
    ///
    /// It will request discovery queries if the peer count has not reached the desired number of
    /// overall peers, as well as the desired number of outbound-only peers.
    ///
    /// NOTE: Discovery will only add a new query if one isn't already queued.
    fn heartbeat(&mut self) {
        // Optionally run a discovery query if we need more peers.
        self.maintain_peer_count(0);

        // Cleans up the connection state of dialing peers.
        // Libp2p dials peer-ids, but sometimes the response is from another peer-id or libp2p
        // returns dial errors without a peer-id attached. This function reverts peers that have a
        // dialing status long than DIAL_TIMEOUT seconds to a disconnected status. This is important because
        // we count the number of dialing peers in our inbound connections.
        self.network_globals.peers.write().cleanup_dialing_peers();

        // Updates peer's scores and unban any peers if required.
        let actions = self.network_globals.peers.write().update_scores();
        for (peer_id, action) in actions {
            self.handle_score_action(&peer_id, action, None);
        }

        // Update peer score metrics;
        self.update_peer_score_metrics();

        // Maintain minimum count for sync committee peers.
        self.maintain_sync_committee_peers();

        // Prune any excess peers back to our target in such a way that incentivises good scores and
        // a uniform distribution of subnets.
        self.prune_excess_peers();
    }

    // Update metrics related to peer scoring.
    fn update_peer_score_metrics(&self) {
        if !self.metrics_enabled {
            return;
        }
        // reset the gauges
        let _ = metrics::PEER_SCORE_DISTRIBUTION
            .as_ref()
            .map(|gauge| gauge.reset());
        let _ = metrics::PEER_SCORE_PER_CLIENT
            .as_ref()
            .map(|gauge| gauge.reset());

        let mut avg_score_per_client: HashMap<String, (f64, usize)> = HashMap::with_capacity(5);
        {
            let peers_db_read_lock = self.network_globals.peers.read();
            let connected_peers = peers_db_read_lock.best_peers_by_status(PeerInfo::is_connected);
            let total_peers = connected_peers.len();
            for (id, (_peer, peer_info)) in connected_peers.into_iter().enumerate() {
                // First quartile
                if id == 0 {
                    metrics::set_gauge_vec(
                        &metrics::PEER_SCORE_DISTRIBUTION,
                        &["1st"],
                        peer_info.score().score() as i64,
                    );
                } else if id == (total_peers * 3 / 4).saturating_sub(1) {
                    metrics::set_gauge_vec(
                        &metrics::PEER_SCORE_DISTRIBUTION,
                        &["3/4"],
                        peer_info.score().score() as i64,
                    );
                } else if id == (total_peers / 2).saturating_sub(1) {
                    metrics::set_gauge_vec(
                        &metrics::PEER_SCORE_DISTRIBUTION,
                        &["1/2"],
                        peer_info.score().score() as i64,
                    );
                } else if id == (total_peers / 4).saturating_sub(1) {
                    metrics::set_gauge_vec(
                        &metrics::PEER_SCORE_DISTRIBUTION,
                        &["1/4"],
                        peer_info.score().score() as i64,
                    );
                } else if id == total_peers.saturating_sub(1) {
                    metrics::set_gauge_vec(
                        &metrics::PEER_SCORE_DISTRIBUTION,
                        &["last"],
                        peer_info.score().score() as i64,
                    );
                }

                let mut score_peers: &mut (f64, usize) = avg_score_per_client
                    .entry(peer_info.client().kind.to_string())
                    .or_default();
                score_peers.0 += peer_info.score().score();
                score_peers.1 += 1;
            }
        } // read lock ended

        for (client, (score, peers)) in avg_score_per_client {
            metrics::set_float_gauge_vec(
                &metrics::PEER_SCORE_PER_CLIENT,
                &[&client.to_string()],
                score / (peers as f64),
            );
        }
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
    use slog::{o, Drain};
    use types::MainnetEthSpec as E;

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

    async fn build_peer_manager(target_peer_count: usize) -> PeerManager<E> {
        let config = config::Config {
            target_peer_count,
            discovery_enabled: false,
            ..Default::default()
        };
        let log = build_log(slog::Level::Debug, false);
        let globals = NetworkGlobals::new_test_globals(&log);
        PeerManager::new(config, Arc::new(globals), &log).unwrap()
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

        peer_manager.inject_connect_ingoing(&peer0, "/ip4/0.0.0.0".parse().unwrap(), None);
        peer_manager.inject_connect_ingoing(&peer1, "/ip4/0.0.0.0".parse().unwrap(), None);
        peer_manager.inject_connect_ingoing(&peer2, "/ip4/0.0.0.0".parse().unwrap(), None);
        peer_manager.inject_connect_outgoing(
            &outbound_only_peer1,
            "/ip4/0.0.0.0".parse().unwrap(),
            None,
        );
        peer_manager.inject_connect_outgoing(
            &outbound_only_peer2,
            "/ip4/0.0.0.0".parse().unwrap(),
            None,
        );

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
            peer_manager.inject_connect_ingoing(&peer, "/ip4/0.0.0.0".parse().unwrap(), None);
        }

        // Connect an outbound-only peer.
        // Give it the lowest score so that it is evaluated first in the disconnect list iterator.
        let outbound_only_peer = PeerId::random();
        peer_manager.inject_connect_ingoing(
            &outbound_only_peer,
            "/ip4/0.0.0.0".parse().unwrap(),
            None,
        );
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
    async fn test_peer_manager_remove_unhealthy_peers_brings_peers_below_target() {
        let mut peer_manager = build_peer_manager(3).await;

        // Create 4 peers to connect to.
        // One pair will be unhealthy inbound only and outbound only peers.
        let peer0 = PeerId::random();
        let peer1 = PeerId::random();
        let inbound_only_peer1 = PeerId::random();
        let outbound_only_peer1 = PeerId::random();

        peer_manager.inject_connect_ingoing(&peer0, "/ip4/0.0.0.0/tcp/8000".parse().unwrap(), None);
        peer_manager.inject_connect_ingoing(&peer1, "/ip4/0.0.0.0/tcp/8000".parse().unwrap(), None);

        // Connect to two peers that are on the threshold of being disconnected.
        peer_manager.inject_connect_ingoing(
            &inbound_only_peer1,
            "/ip4/0.0.0.0/tcp/8000".parse().unwrap(),
            None,
        );
        peer_manager.inject_connect_outgoing(
            &outbound_only_peer1,
            "/ip4/0.0.0.0/tcp/8000".parse().unwrap(),
            None,
        );
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(inbound_only_peer1))
            .unwrap()
            .add_to_score(-19.8);
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&(outbound_only_peer1))
            .unwrap()
            .add_to_score(-19.8);
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
        // Tests that when we are over the target peer limit, after disconnecting one unhealthy peer,
        // the loop to check for disconnecting peers will stop because we have removed enough peers (only needed to remove 1 to reach target).
        assert_eq!(peer_manager.network_globals.connected_or_dialing_peers(), 3);
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

        peer_manager.inject_connect_ingoing(&peer0, "/ip4/0.0.0.0".parse().unwrap(), None);
        peer_manager.inject_connect_ingoing(&peer1, "/ip4/0.0.0.0".parse().unwrap(), None);
        peer_manager.inject_connect_ingoing(&peer2, "/ip4/0.0.0.0".parse().unwrap(), None);
        peer_manager.inject_connect_outgoing(
            &outbound_only_peer1,
            "/ip4/0.0.0.0".parse().unwrap(),
            None,
        );
        // Have one peer be on the verge of disconnection.
        peer_manager.inject_connect_ingoing(
            &inbound_only_peer1,
            "/ip4/0.0.0.0".parse().unwrap(),
            None,
        );
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

    #[tokio::test]
    /// We want to test that the peer manager removes peers that are not subscribed to a subnet as
    /// a priority over all else.
    async fn test_peer_manager_remove_non_subnet_peers_when_all_healthy() {
        let mut peer_manager = build_peer_manager(3).await;

        // Create 5 peers to connect to.
        let peer0 = PeerId::random();
        let peer1 = PeerId::random();
        let peer2 = PeerId::random();
        let peer3 = PeerId::random();
        let peer4 = PeerId::random();

        println!("{}", peer0);
        println!("{}", peer1);
        println!("{}", peer2);
        println!("{}", peer3);
        println!("{}", peer4);

        peer_manager.inject_connect_ingoing(&peer0, "/ip4/0.0.0.0".parse().unwrap(), None);
        peer_manager.inject_connect_ingoing(&peer1, "/ip4/0.0.0.0".parse().unwrap(), None);
        peer_manager.inject_connect_ingoing(&peer2, "/ip4/0.0.0.0".parse().unwrap(), None);
        peer_manager.inject_connect_ingoing(&peer3, "/ip4/0.0.0.0".parse().unwrap(), None);
        peer_manager.inject_connect_ingoing(&peer4, "/ip4/0.0.0.0".parse().unwrap(), None);

        // Have some of the peers be on a long-lived subnet
        let mut attnets = crate::types::EnrAttestationBitfield::<E>::new();
        attnets.set(1, true).unwrap();
        let metadata = crate::rpc::MetaDataV2 {
            seq_number: 0,
            attnets,
            syncnets: Default::default(),
        };
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&peer0)
            .unwrap()
            .set_meta_data(MetaData::V2(metadata));
        peer_manager
            .network_globals
            .peers
            .write()
            .add_subscription(&peer0, Subnet::Attestation(1.into()));

        let mut attnets = crate::types::EnrAttestationBitfield::<E>::new();
        attnets.set(10, true).unwrap();
        let metadata = crate::rpc::MetaDataV2 {
            seq_number: 0,
            attnets,
            syncnets: Default::default(),
        };
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&peer2)
            .unwrap()
            .set_meta_data(MetaData::V2(metadata));
        peer_manager
            .network_globals
            .peers
            .write()
            .add_subscription(&peer2, Subnet::Attestation(10.into()));

        let mut syncnets = crate::types::EnrSyncCommitteeBitfield::<E>::new();
        syncnets.set(3, true).unwrap();
        let metadata = crate::rpc::MetaDataV2 {
            seq_number: 0,
            attnets: Default::default(),
            syncnets,
        };
        peer_manager
            .network_globals
            .peers
            .write()
            .peer_info_mut(&peer4)
            .unwrap()
            .set_meta_data(MetaData::V2(metadata));
        peer_manager
            .network_globals
            .peers
            .write()
            .add_subscription(&peer4, Subnet::SyncCommittee(3.into()));

        // Perform the heartbeat.
        peer_manager.heartbeat();
        // Tests that when we are over the target peer limit, after disconnecting an unhealthy peer,
        // the number of connected peers updates and we will not remove too many peers.
        assert_eq!(peer_manager.network_globals.connected_or_dialing_peers(), 3);

        // Check that we removed the peers that were not subscribed to any subnet
        let mut peers_should_have_removed = std::collections::HashSet::new();
        peers_should_have_removed.insert(peer1);
        peers_should_have_removed.insert(peer3);
        for (peer, _) in peer_manager
            .network_globals
            .peers
            .read()
            .peers()
            .filter(|(_, info)| {
                matches!(
                    info.connection_status(),
                    PeerConnectionStatus::Disconnecting { .. }
                )
            })
        {
            println!("{}", peer);
            assert!(peers_should_have_removed.remove(peer));
        }
        // Ensure we removed all the peers
        assert!(peers_should_have_removed.is_empty());
    }

    #[tokio::test]
    /// Test the pruning logic to remove grouped subnet peers
    async fn test_peer_manager_prune_grouped_subnet_peers() {
        let target = 9;
        let mut peer_manager = build_peer_manager(target).await;

        // Create 5 peers to connect to.
        let mut peers = Vec::new();
        for x in 0..20 {
            // Make 20 peers and group peers as:
            // id mod % 4
            // except for the last 5 peers which all go on their own subnets
            // So subnets 0-2 should have 4 peers subnet 3 should have 3 and 15-19 should have 1
            let subnet: u64 = {
                if x < 15 {
                    x % 4
                } else {
                    x
                }
            };

            let peer = PeerId::random();
            peer_manager.inject_connect_ingoing(&peer, "/ip4/0.0.0.0".parse().unwrap(), None);

            // Have some of the peers be on a long-lived subnet
            let mut attnets = crate::types::EnrAttestationBitfield::<E>::new();
            attnets.set(subnet as usize, true).unwrap();
            let metadata = crate::rpc::MetaDataV2 {
                seq_number: 0,
                attnets,
                syncnets: Default::default(),
            };
            peer_manager
                .network_globals
                .peers
                .write()
                .peer_info_mut(&peer)
                .unwrap()
                .set_meta_data(MetaData::V2(metadata));
            peer_manager
                .network_globals
                .peers
                .write()
                .add_subscription(&peer, Subnet::Attestation(subnet.into()));
            println!("{},{},{}", x, subnet, peer);
            peers.push(peer);
        }

        // Perform the heartbeat.
        peer_manager.heartbeat();

        // Tests that when we are over the target peer limit, after disconnecting an unhealthy peer,
        // the number of connected peers updates and we will not remove too many peers.
        assert_eq!(
            peer_manager.network_globals.connected_or_dialing_peers(),
            target
        );

        // Check that we removed the peers that were not subscribed to any subnet
        // Should remove peers from subnet 0-2 first. Removing 3 peers subnets 0-3 now have 3
        // peers.
        // Should then remove 8 peers each from subnets 1-4. New total: 11 peers.
        // Therefore the remaining peer set should be each on their own subnet.
        // Lets check this:

        let connected_peers: std::collections::HashSet<_> = peer_manager
            .network_globals
            .peers
            .read()
            .connected_or_dialing_peers()
            .cloned()
            .collect();

        for peer in connected_peers.iter() {
            let position = peers.iter().position(|peer_id| peer_id == peer).unwrap();
            println!("{},{}", position, peer);
        }

        println!();

        for peer in connected_peers.iter() {
            let position = peers.iter().position(|peer_id| peer_id == peer).unwrap();
            println!("{},{}", position, peer);

            if position < 15 {
                let y = position % 4;
                for x in 0..4 {
                    let alternative_index = y + 4 * x;
                    if alternative_index != position && alternative_index < 15 {
                        // Make sure a peer on the same subnet has been removed
                        println!(
                            "Check against: {}, {}",
                            alternative_index, &peers[alternative_index]
                        );
                        assert!(!connected_peers.contains(&peers[alternative_index]));
                    }
                }
            }
        }
    }

    /// Test the pruning logic to prioritise peers with the most subnets
    ///
    /// Create 6 peers.
    /// Peer0: None
    /// Peer1 : Subnet 1,2,3
    /// Peer2 : Subnet 1,2
    /// Peer3 : Subnet 3
    /// Peer4 : Subnet 1
    /// Peer5 : Subnet 2
    ///
    /// Prune 3 peers: Should be Peer0, Peer 4 and Peer 5 because (4 and 5) are both on the subnet with the
    /// most peers and have the least subscribed long-lived subnets. And peer 0 because it has no
    /// long-lived subnet.
    #[tokio::test]
    async fn test_peer_manager_prune_subnet_peers_most_subscribed() {
        let target = 3;
        let mut peer_manager = build_peer_manager(target).await;

        // Create 6 peers to connect to.
        let mut peers = Vec::new();
        for x in 0..6 {
            let peer = PeerId::random();
            peer_manager.inject_connect_ingoing(&peer, "/ip4/0.0.0.0".parse().unwrap(), None);

            // Have some of the peers be on a long-lived subnet
            let mut attnets = crate::types::EnrAttestationBitfield::<E>::new();

            match x {
                0 => {}
                1 => {
                    attnets.set(1, true).unwrap();
                    attnets.set(2, true).unwrap();
                    attnets.set(3, true).unwrap();
                }
                2 => {
                    attnets.set(1, true).unwrap();
                    attnets.set(2, true).unwrap();
                }
                3 => {
                    attnets.set(3, true).unwrap();
                }
                4 => {
                    attnets.set(1, true).unwrap();
                }
                5 => {
                    attnets.set(2, true).unwrap();
                }
                _ => unreachable!(),
            }

            let metadata = crate::rpc::MetaDataV2 {
                seq_number: 0,
                attnets,
                syncnets: Default::default(),
            };
            peer_manager
                .network_globals
                .peers
                .write()
                .peer_info_mut(&peer)
                .unwrap()
                .set_meta_data(MetaData::V2(metadata));
            let long_lived_subnets = peer_manager
                .network_globals
                .peers
                .read()
                .peer_info(&peer)
                .unwrap()
                .long_lived_subnets();
            for subnet in long_lived_subnets {
                println!("Subnet: {:?}", subnet);
                peer_manager
                    .network_globals
                    .peers
                    .write()
                    .add_subscription(&peer, subnet);
            }
            println!("{},{}", x, peer);
            peers.push(peer);
        }

        // Perform the heartbeat.
        peer_manager.heartbeat();

        // Tests that when we are over the target peer limit, after disconnecting an unhealthy peer,
        // the number of connected peers updates and we will not remove too many peers.
        assert_eq!(
            peer_manager.network_globals.connected_or_dialing_peers(),
            target
        );

        // Check that we removed peers 4 and 5
        let connected_peers: std::collections::HashSet<_> = peer_manager
            .network_globals
            .peers
            .read()
            .connected_or_dialing_peers()
            .cloned()
            .collect();

        assert!(!connected_peers.contains(&peers[0]));
        assert!(!connected_peers.contains(&peers[4]));
        assert!(!connected_peers.contains(&peers[5]));
    }

    /// Test the pruning logic to prioritise peers with the most subnets, but not at the expense of
    /// removing our few sync-committee subnets.
    ///
    /// Create 6 peers.
    /// Peer0: None
    /// Peer1 : Subnet 1,2,3,
    /// Peer2 : Subnet 1,2,
    /// Peer3 : Subnet 3
    /// Peer4 : Subnet 1,2,  Sync-committee-1
    /// Peer5 : Subnet 1,2,  Sync-committee-2
    ///
    /// Prune 3 peers: Should be Peer0, Peer1 and Peer2 because (4 and 5 are on a sync-committee)
    #[tokio::test]
    async fn test_peer_manager_prune_subnet_peers_sync_committee() {
        let target = 3;
        let mut peer_manager = build_peer_manager(target).await;

        // Create 6 peers to connect to.
        let mut peers = Vec::new();
        for x in 0..6 {
            let peer = PeerId::random();
            peer_manager.inject_connect_ingoing(&peer, "/ip4/0.0.0.0".parse().unwrap(), None);

            // Have some of the peers be on a long-lived subnet
            let mut attnets = crate::types::EnrAttestationBitfield::<E>::new();
            let mut syncnets = crate::types::EnrSyncCommitteeBitfield::<E>::new();

            match x {
                0 => {}
                1 => {
                    attnets.set(1, true).unwrap();
                    attnets.set(2, true).unwrap();
                    attnets.set(3, true).unwrap();
                }
                2 => {
                    attnets.set(1, true).unwrap();
                    attnets.set(2, true).unwrap();
                }
                3 => {
                    attnets.set(3, true).unwrap();
                }
                4 => {
                    attnets.set(1, true).unwrap();
                    attnets.set(2, true).unwrap();
                    syncnets.set(1, true).unwrap();
                }
                5 => {
                    attnets.set(1, true).unwrap();
                    attnets.set(2, true).unwrap();
                    syncnets.set(2, true).unwrap();
                }
                _ => unreachable!(),
            }

            let metadata = crate::rpc::MetaDataV2 {
                seq_number: 0,
                attnets,
                syncnets,
            };
            peer_manager
                .network_globals
                .peers
                .write()
                .peer_info_mut(&peer)
                .unwrap()
                .set_meta_data(MetaData::V2(metadata));
            let long_lived_subnets = peer_manager
                .network_globals
                .peers
                .read()
                .peer_info(&peer)
                .unwrap()
                .long_lived_subnets();
            println!("{},{}", x, peer);
            for subnet in long_lived_subnets {
                println!("Subnet: {:?}", subnet);
                peer_manager
                    .network_globals
                    .peers
                    .write()
                    .add_subscription(&peer, subnet);
            }
            peers.push(peer);
        }

        // Perform the heartbeat.
        peer_manager.heartbeat();

        // Tests that when we are over the target peer limit, after disconnecting an unhealthy peer,
        // the number of connected peers updates and we will not remove too many peers.
        assert_eq!(
            peer_manager.network_globals.connected_or_dialing_peers(),
            target
        );

        // Check that we removed peers 4 and 5
        let connected_peers: std::collections::HashSet<_> = peer_manager
            .network_globals
            .peers
            .read()
            .connected_or_dialing_peers()
            .cloned()
            .collect();

        assert!(!connected_peers.contains(&peers[0]));
        assert!(!connected_peers.contains(&peers[1]));
        assert!(!connected_peers.contains(&peers[2]));
    }

    /// This test is for reproducing the issue:
    /// https://github.com/sigp/lighthouse/pull/3236#issue-1256432659
    ///
    /// Whether the issue happens depends on `subnet_to_peer` (HashMap), since HashMap doesn't
    /// guarantee a particular order of iteration. So we repeat the test case to try to reproduce
    /// the issue.
    #[tokio::test]
    async fn test_peer_manager_prune_based_on_subnet_count_repeat() {
        for _ in 0..100 {
            test_peer_manager_prune_based_on_subnet_count().await;
        }
    }

    /// Test the pruning logic to prioritize peers with the most subnets. This test specifies
    /// the connection direction for the peers.
    /// Either Peer 4 or 5 is expected to be removed in this test case.
    ///
    /// Create 8 peers.
    /// Peer0 (out) : Subnet 1, Sync-committee-1
    /// Peer1 (out) : Subnet 1, Sync-committee-1
    /// Peer2 (out) : Subnet 2, Sync-committee-2
    /// Peer3 (out) : Subnet 2, Sync-committee-2
    /// Peer4 (out) : Subnet 3
    /// Peer5 (out) : Subnet 3
    /// Peer6 (in) : Subnet 4
    /// Peer7 (in) : Subnet 5
    async fn test_peer_manager_prune_based_on_subnet_count() {
        let target = 7;
        let mut peer_manager = build_peer_manager(target).await;

        // Create 8 peers to connect to.
        let mut peers = Vec::new();
        for x in 0..8 {
            let peer = PeerId::random();

            // Have some of the peers be on a long-lived subnet
            let mut attnets = crate::types::EnrAttestationBitfield::<E>::new();
            let mut syncnets = crate::types::EnrSyncCommitteeBitfield::<E>::new();

            match x {
                0 => {
                    peer_manager.inject_connect_outgoing(
                        &peer,
                        "/ip4/0.0.0.0".parse().unwrap(),
                        None,
                    );
                    attnets.set(1, true).unwrap();
                    syncnets.set(1, true).unwrap();
                }
                1 => {
                    peer_manager.inject_connect_outgoing(
                        &peer,
                        "/ip4/0.0.0.0".parse().unwrap(),
                        None,
                    );
                    attnets.set(1, true).unwrap();
                    syncnets.set(1, true).unwrap();
                }
                2 => {
                    peer_manager.inject_connect_outgoing(
                        &peer,
                        "/ip4/0.0.0.0".parse().unwrap(),
                        None,
                    );
                    attnets.set(2, true).unwrap();
                    syncnets.set(2, true).unwrap();
                }
                3 => {
                    peer_manager.inject_connect_outgoing(
                        &peer,
                        "/ip4/0.0.0.0".parse().unwrap(),
                        None,
                    );
                    attnets.set(2, true).unwrap();
                    syncnets.set(2, true).unwrap();
                }
                4 => {
                    peer_manager.inject_connect_outgoing(
                        &peer,
                        "/ip4/0.0.0.0".parse().unwrap(),
                        None,
                    );
                    attnets.set(3, true).unwrap();
                }
                5 => {
                    peer_manager.inject_connect_outgoing(
                        &peer,
                        "/ip4/0.0.0.0".parse().unwrap(),
                        None,
                    );
                    attnets.set(3, true).unwrap();
                }
                6 => {
                    peer_manager.inject_connect_ingoing(
                        &peer,
                        "/ip4/0.0.0.0".parse().unwrap(),
                        None,
                    );
                    attnets.set(4, true).unwrap();
                }
                7 => {
                    peer_manager.inject_connect_ingoing(
                        &peer,
                        "/ip4/0.0.0.0".parse().unwrap(),
                        None,
                    );
                    attnets.set(5, true).unwrap();
                }
                _ => unreachable!(),
            }

            let metadata = crate::rpc::MetaDataV2 {
                seq_number: 0,
                attnets,
                syncnets,
            };
            peer_manager
                .network_globals
                .peers
                .write()
                .peer_info_mut(&peer)
                .unwrap()
                .set_meta_data(MetaData::V2(metadata));
            let long_lived_subnets = peer_manager
                .network_globals
                .peers
                .read()
                .peer_info(&peer)
                .unwrap()
                .long_lived_subnets();
            println!("{},{}", x, peer);
            for subnet in long_lived_subnets {
                println!("Subnet: {:?}", subnet);
                peer_manager
                    .network_globals
                    .peers
                    .write()
                    .add_subscription(&peer, subnet);
            }
            peers.push(peer);
        }

        // Perform the heartbeat.
        peer_manager.heartbeat();

        // Tests that when we are over the target peer limit, after disconnecting an unhealthy peer,
        // the number of connected peers updates and we will not remove too many peers.
        assert_eq!(
            peer_manager.network_globals.connected_or_dialing_peers(),
            target
        );

        let connected_peers: std::collections::HashSet<_> = peer_manager
            .network_globals
            .peers
            .read()
            .connected_or_dialing_peers()
            .cloned()
            .collect();

        // Either peer 4 or 5 should be removed.
        // Check that we keep 6 and 7 peers, which we have few on a particular subnet.
        assert!(connected_peers.contains(&peers[6]));
        assert!(connected_peers.contains(&peers[7]));
    }

    // Test properties PeerManager should have using randomly generated input.
    #[cfg(test)]
    mod property_based_tests {
        use crate::peer_manager::config::DEFAULT_TARGET_PEERS;
        use crate::peer_manager::tests::build_peer_manager;
        use crate::rpc::MetaData;
        use libp2p::PeerId;
        use quickcheck::{Arbitrary, Gen, TestResult};
        use quickcheck_macros::quickcheck;
        use tokio::runtime::Runtime;
        use types::Unsigned;
        use types::{EthSpec, MainnetEthSpec as E};

        #[derive(Clone, Debug)]
        struct PeerCondition {
            outgoing: bool,
            attestation_net_bitfield: Vec<bool>,
            sync_committee_net_bitfield: Vec<bool>,
            score: f64,
            gossipsub_score: f64,
        }

        impl Arbitrary for PeerCondition {
            fn arbitrary<G: Gen>(g: &mut G) -> Self {
                let attestation_net_bitfield = {
                    let len = <E as EthSpec>::SubnetBitfieldLength::to_usize();
                    let mut bitfield = Vec::with_capacity(len);
                    for _ in 0..len {
                        bitfield.push(bool::arbitrary(g));
                    }
                    bitfield
                };

                let sync_committee_net_bitfield = {
                    let len = <E as EthSpec>::SyncCommitteeSubnetCount::to_usize();
                    let mut bitfield = Vec::with_capacity(len);
                    for _ in 0..len {
                        bitfield.push(bool::arbitrary(g));
                    }
                    bitfield
                };

                PeerCondition {
                    outgoing: bool::arbitrary(g),
                    attestation_net_bitfield,
                    sync_committee_net_bitfield,
                    score: f64::arbitrary(g),
                    gossipsub_score: f64::arbitrary(g),
                }
            }
        }

        #[quickcheck]
        fn prune_excess_peers(peer_conditions: Vec<PeerCondition>) -> TestResult {
            let target_peer_count = DEFAULT_TARGET_PEERS;
            if peer_conditions.len() < target_peer_count {
                return TestResult::discard();
            }
            let rt = Runtime::new().unwrap();

            rt.block_on(async move {
                let mut peer_manager = build_peer_manager(target_peer_count).await;

                // Create peers based on the randomly generated conditions.
                for condition in &peer_conditions {
                    let peer = PeerId::random();
                    let mut attnets = crate::types::EnrAttestationBitfield::<E>::new();
                    let mut syncnets = crate::types::EnrSyncCommitteeBitfield::<E>::new();

                    if condition.outgoing {
                        peer_manager.inject_connect_outgoing(
                            &peer,
                            "/ip4/0.0.0.0".parse().unwrap(),
                            None,
                        );
                    } else {
                        peer_manager.inject_connect_ingoing(
                            &peer,
                            "/ip4/0.0.0.0".parse().unwrap(),
                            None,
                        );
                    }

                    for (i, value) in condition.attestation_net_bitfield.iter().enumerate() {
                        attnets.set(i, *value).unwrap();
                    }

                    for (i, value) in condition.sync_committee_net_bitfield.iter().enumerate() {
                        syncnets.set(i, *value).unwrap();
                    }

                    let metadata = crate::rpc::MetaDataV2 {
                        seq_number: 0,
                        attnets,
                        syncnets,
                    };

                    let mut peer_db = peer_manager.network_globals.peers.write();
                    let peer_info = peer_db.peer_info_mut(&peer).unwrap();
                    peer_info.set_meta_data(MetaData::V2(metadata));
                    peer_info.set_gossipsub_score(condition.gossipsub_score);
                    peer_info.add_to_score(condition.score);

                    for subnet in peer_info.long_lived_subnets() {
                        peer_db.add_subscription(&peer, subnet);
                    }
                }

                // Perform the heartbeat.
                peer_manager.heartbeat();

                TestResult::from_bool(
                    peer_manager.network_globals.connected_or_dialing_peers()
                        == target_peer_count.min(peer_conditions.len()),
                )
            })
        }
    }
}
