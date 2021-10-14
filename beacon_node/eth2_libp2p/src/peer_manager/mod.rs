//! Implementation of Lighthouse's peer management system.
//! The PeerManager manages scoring of peers with respect to their behaviour in different
//! protocols, mainly the RPC and Gossipsub. Based on certain conditions, including peers' scores
//! the PeerManager will also disconnect, ban, and request searching or dialing peers. Additionally
//! it manages the intervals at which peers mut be ping'd and status'd to stay healthy.
// TODO(@me): I'm trying to understand what is the peer manager at this point. It does a lot of
// stuff wrt to all behaviours/protocols it seems. TODO: Remove/improve this

use crate::discovery::TARGET_SUBNET_PEERS;
use crate::rpc::{GoodbyeReason, MetaData, Protocol, RPCError, RPCResponseErrorCode};
use crate::types::Subnet;
use crate::types::{Owner, ReadOnly, SyncState};
use crate::PeerId;
use crate::SubnetDiscovery;
use crate::{error, metrics, Gossipsub};
use discv5::Enr;
use futures::prelude::*;
use futures::Stream;
use hashset_delay::HashSetDelay;
use libp2p::core::ConnectedPoint;
use libp2p::identify::IdentifyInfo;
use peerdb::{BanOperation, BanResult, ScoreUpdateResult};
use slog::{debug, error, warn};
use smallvec::SmallVec;
use std::{
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use types::{EthSpec, SyncSubnetId};

pub use libp2p::core::{identity::Keypair, Multiaddr};

#[allow(clippy::mutable_key_type)] // PeerId in hashmaps are no longer permitted by clippy
pub mod peerdb;
pub use peerdb::PeerDB;

pub use peerdb::peer_info::{
    ConnectionDirection, PeerConnectionStatus, PeerConnectionStatus::*, PeerInfo,
};
use peerdb::score::{PeerAction, ReportSource};
pub use peerdb::sync_status::{SyncInfo, SyncStatus};
use std::collections::{hash_map::Entry, HashMap};
use std::net::IpAddr;
pub mod config;

/// The main struct that handles peer's reputation and connection status.
pub struct PeerManager<TSpec: EthSpec> {
    peer_db: Owner<PeerDB<TSpec>>,
    /// Syncing state of the node.
    // TODO: This means the PeerManager has also write access to this. Same strategy could apply to
    // the sync state, being sync who provides a read only access struct to it.
    sync_state: ReadOnly<SyncState>,
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
    /// A collection of sync committee subnets that we need to stay subscribed to.
    /// Sync committee subnets are longer term (256 epochs). Hence, we need to re-run
    /// discovery queries for subnet peers if we disconnect from existing sync
    /// committee subnet peers.
    sync_committee_subnets: HashMap<SyncSubnetId, Instant>,
    /// The heartbeat interval to perform routine maintenance.
    heartbeat: tokio::time::Interval,
    /// Keeps track of whether the discovery service is enabled or not.
    discovery_enabled: bool,
    /// The logger associated with the `PeerManager`.
    log: slog::Logger,
}

/// The events that the `PeerManager` outputs (requests).
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
    /// Request the behaviour to discover more peers.
    DiscoverPeers,
    /// Request the behaviour to discover peers on subnets.
    DiscoverSubnetPeers(Vec<SubnetDiscovery>),
}

impl<TSpec: EthSpec> PeerManager<TSpec> {
    // NOTE: Must be run inside a tokio executor.
    pub async fn new(
        cfg: config::Config,
        sync_state: ReadOnly<SyncState>,
        log: &slog::Logger,
    ) -> error::Result<Self> {
        // Set up the peer manager heartbeat interval
        let heartbeat =
            tokio::time::interval(tokio::time::Duration::from_secs(config::HEARTBEAT_INTERVAL));
        let config::Config {
            discovery_enabled,
            target_peer_count,
            status_interval,
            ping_interval_inbound,
            ping_interval_outbound,
            trusted_peers,
        } = cfg;

        Ok(PeerManager {
            peer_db: Owner::new(PeerDB::new(trusted_peers, log)),
            sync_state,
            events: SmallVec::new(),
            inbound_ping_peers: HashSetDelay::new(Duration::from_secs(ping_interval_inbound)),
            outbound_ping_peers: HashSetDelay::new(Duration::from_secs(ping_interval_outbound)),
            status_peers: HashSetDelay::new(Duration::from_secs(status_interval)),
            target_peers: target_peer_count,
            sync_committee_subnets: Default::default(),
            heartbeat,
            discovery_enabled,
            log: log.clone(),
        })
    }

    pub fn peer_db_access(&self) -> ReadOnly<PeerDB<TSpec>> {
        self.peer_db.read_access()
    }

    /* Public accessible functions */

    /// The application layer wants to disconnect from a peer for a particular reason.
    ///
    /// All instant disconnections are fatal and we ban the associated peer.
    ///
    /// This will send a goodbye and disconnect the peer if it is connected or dialing.
    pub fn goodbye_peer(&mut self, peer_id: &PeerId, reason: GoodbyeReason, source: ReportSource) {
        // get the peer info
        if let Some(info) = self.peer_db.write().peer_info_mut(peer_id) {
            debug!(self.log, "Sending goodbye to peer"; "peer_id" => %peer_id, "reason" => %reason, "score" => %info.score());
            if matches!(reason, GoodbyeReason::IrrelevantNetwork) {
                info.update_sync_status(SyncStatus::IrrelevantPeer);
            }
        }

        self.report_peer(peer_id, PeerAction::Fatal, source, Some(reason));
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
    ) {
        let action = self.peer_db.write().report_peer(peer_id, action, source);
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

        let connected_or_dialing = self.peer_db.read().connected_or_dialing_peer_count();
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
                && self.peer_db.read().should_dial(&peer_id)
            {
                // This should be updated with the peer dialing. In fact created once the peer is
                // dialed
                if let Some(min_ttl) = min_ttl {
                    self.peer_db.write().update_min_ttl(&peer_id, min_ttl);
                }
                to_dial_peers.push(peer_id);
            }
        }

        // Queue another discovery if we need to
        let peer_count = self.peer_db.read().connected_or_dialing_peer_count();
        let outbound_only_peer_count = self.peer_db.read().connected_outbound_only_peer_count();
        let min_outbound_only_target =
            (self.target_peers as f32 * config::MIN_OUTBOUND_ONLY_FACTOR).ceil() as usize;

        if self.discovery_enabled
            && (peer_count < self.target_peers.saturating_sub(to_dial_peers.len())
                || outbound_only_peer_count < min_outbound_only_target)
        {
            // We need more peers, re-queue a discovery lookup.
            debug!(self.log, "Starting a new peer discovery query"; "connected_peers" => peer_count, "target_peers" => self.target_peers);
            self.events.push(PeerManagerEvent::DiscoverPeers);
        }

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
        (self.target_peers as f32 * (1.0 + config::PEER_EXCESS_FACTOR)).ceil() as usize
    }

    /// The maximum number of peers we allow when dialing a priority peer (i.e a peer that is
    /// subscribed to subnets that our validator requires. This is `target_peers` * (1 +
    /// PEER_EXCESS_FACTOR + PRIORITY_PEER_EXCESS)
    fn max_priority_peers(&self) -> usize {
        (self.target_peers as f32
            * (1.0 + config::PEER_EXCESS_FACTOR + config::PRIORITY_PEER_EXCESS))
            .ceil() as usize
    }

    /* Notifications from the Swarm */

    // A peer is being dialed.
    pub fn inject_dialing(&mut self, peer_id: &PeerId, enr: Option<Enr>) {
        self.inject_peer_connection(peer_id, ConnectingType::Dialing, enr);
    }

    pub fn inject_connection_established(
        &mut self,
        peer_id: PeerId,
        endpoint: ConnectedPoint,
        num_established: std::num::NonZeroU32,
        enr: Option<Enr>,
    ) {
        // Log the connection
        match &endpoint {
            ConnectedPoint::Listener { .. } => {
                debug!(self.log, "Connection established"; "peer_id" => %peer_id, "connection" => "Incoming", "connections" => %num_established);
            }
            ConnectedPoint::Dialer { .. } => {
                debug!(self.log, "Connection established"; "peer_id" => %peer_id, "connection" => "Outgoing", "connections" => %num_established);
            }
        }

        // Check to make sure the peer is not supposed to be banned
        match self.ban_status(&peer_id) {
            BanResult::BadScore => {
                // This is a faulty state
                error!(self.log, "Connected to a banned peer, re-banning"; "peer_id" => %peer_id);
                // Reban the peer
                self.goodbye_peer(&peer_id, GoodbyeReason::Banned, ReportSource::PeerManager);
                return;
            }
            BanResult::BannedIp(ip_addr) => {
                // A good peer has connected to us via a banned IP address. We ban the peer and
                // prevent future connections.
                debug!(self.log, "Peer connected via banned IP. Banning"; "peer_id" => %peer_id, "banned_ip" => %ip_addr);
                self.goodbye_peer(&peer_id, GoodbyeReason::BannedIP, ReportSource::PeerManager);
                return;
            }
            BanResult::NotBanned => {}
        }

        // Check the connection limits
        if self.peer_limit_reached()
            && self
                .peer_db
                .read()
                .peer_info(&peer_id)
                .map_or(true, |peer| !peer.has_future_duty())
        {
            // Gracefully disconnect the peer.
            self.disconnect_peer(peer_id, GoodbyeReason::TooManyPeers);
            return;
        }

        // Register the newly connected peer (regardless if we are about to disconnect them).
        // NOTE: We don't register peers that we are disconnecting immediately. The network service
        // does not need to know about these peers.
        match endpoint {
            ConnectedPoint::Listener { send_back_addr, .. } => {
                self.inject_connect_ingoing(&peer_id, send_back_addr, enr);
                if num_established == std::num::NonZeroU32::new(1).expect("valid") {
                    self.events
                        .push(PeerManagerEvent::PeerConnectedIncoming(peer_id));
                }
            }
            ConnectedPoint::Dialer { address } => {
                self.inject_connect_outgoing(&peer_id, address, enr);
                if num_established == std::num::NonZeroU32::new(1).expect("valid") {
                    self.events
                        .push(PeerManagerEvent::PeerConnectedOutgoing(peer_id));
                }
            }
        }

        let connected_peers = self.peer_db.read().connected_peer_count() as i64;

        // increment prometheus metrics
        metrics::inc_counter(&metrics::PEER_CONNECT_EVENT_COUNT);
        metrics::set_gauge(&metrics::PEERS_CONNECTED, connected_peers);
        metrics::set_gauge(&metrics::PEERS_CONNECTED_INTEROP, connected_peers);
    }

    pub fn inject_connection_closed(
        &mut self,
        peer_id: PeerId,
        _endpoint: ConnectedPoint,
        num_established: u32,
    ) {
        if num_established == 0 {
            // There are no more connections

            if self.peer_db.read().is_connected_or_disconnecting(&peer_id) {
                // We are disconnecting the peer or the peer has already been connected.
                // Both these cases, the peer has been previously registered by the peer manager and
                // potentially the application layer.
                // Inform the application.
                self.events
                    .push(PeerManagerEvent::PeerDisconnected(peer_id));
                debug!(self.log, "Peer disconnected"; "peer_id" => %peer_id);

                // Decrement the PEERS_PER_CLIENT metric
                if let Some(kind) = self
                    .peer_db
                    .read()
                    .peer_info(&peer_id)
                    .map(|info| info.client().kind.clone())
                {
                    if let Some(v) =
                        metrics::get_int_gauge(&metrics::PEERS_PER_CLIENT, &[&kind.to_string()])
                    {
                        v.dec()
                    };
                }
            }

            // NOTE: It may be the case that a rejected node, due to too many peers is disconnected
            // here and the peer manager has no knowledge of its connection. We insert it here for
            // reference so that peer manager can track this peer.
            self.inject_disconnect(&peer_id);

            let connected_peers = self.peer_db.read().connected_peer_count() as i64;

            // Update the prometheus metrics
            metrics::inc_counter(&metrics::PEER_DISCONNECT_EVENT_COUNT);
            metrics::set_gauge(&metrics::PEERS_CONNECTED, connected_peers);
            metrics::set_gauge(&metrics::PEERS_CONNECTED_INTEROP, connected_peers);
        }
    }

    /// A dial attempt has failed.
    ///
    /// NOTE: It can be the case that we are dialing a peer and during the dialing process the peer
    /// connects and the dial attempt later fails. To handle this, we only update the peer_db if
    /// the peer is not already connected.
    pub fn inject_dial_failure(&mut self, peer_id: &PeerId) {
        if !self.peer_db.read().is_connected(peer_id) {
            self.inject_disconnect(peer_id);
        }
    }

    /// Reports if a peer is banned or not.
    ///
    /// This is used to determine if we should accept incoming connections.
    pub fn ban_status(&self, peer_id: &PeerId) -> BanResult {
        self.peer_db.read().ban_status(peer_id)
    }

    pub fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.peer_db.read().is_connected(peer_id)
    }

    /// Reports whether the peer limit is reached in which case we stop allowing new incoming
    /// connections.
    pub fn peer_limit_reached(&self) -> bool {
        self.peer_db.read().connected_or_dialing_peer_count() >= self.max_peers()
    }

    /// Updates `PeerInfo` with `identify` information.
    pub fn identify(&mut self, peer_id: &PeerId, info: &IdentifyInfo) {
        if let Some(peer_info) = self.peer_db.write().peer_info_mut(peer_id) {
            let previous_kind = peer_info.client().kind.clone();
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

                // update the peer client kind metric
                if let Some(v) = metrics::get_int_gauge(
                    &metrics::PEERS_PER_CLIENT,
                    &[&peer_info.client().kind.to_string()],
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
        let client = self.peer_db.read().client(peer_id);
        let score = self.peer_db.read().score(peer_id);
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
            RPCError::Disconnected => return, // No penalty for a graceful disconnection
        };

        self.report_peer(peer_id, peer_action, ReportSource::RPC, None);
    }

    /// A ping request has been received.
    // NOTE: The behaviour responds with a PONG automatically
    pub fn ping_request(&mut self, peer_id: &PeerId, seq: u64) {
        if let Some(peer_info) = self.peer_db.read().peer_info(peer_id) {
            // received a ping
            // reset the to-ping timer for this peer
            debug!(self.log, "Received a ping request"; "peer_id" => %peer_id, "seq_no" => seq);
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
                    debug!(self.log, "Requesting new metadata from peer";
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
        if let Some(peer_info) = self.peer_db.read().peer_info(peer_id) {
            // received a pong

            // if the sequence number is unknown send update the meta data of the peer.
            if let Some(meta_data) = &peer_info.meta_data() {
                if *meta_data.seq_number() < seq {
                    debug!(self.log, "Requesting new metadata from peer";
                        "peer_id" => %peer_id, "known_seq_no" => meta_data.seq_number(), "pong_seq_no" => seq);
                    self.events.push(PeerManagerEvent::MetaData(*peer_id));
                }
            } else {
                // if we don't know the meta-data, request it
                debug!(self.log, "Requesting first metadata from peer";
                    "peer_id" => %peer_id);
                self.events.push(PeerManagerEvent::MetaData(*peer_id));
            }
        } else {
            error!(self.log, "Received a PONG from an unknown peer"; "peer_id" => %peer_id);
        }
    }

    /// Received a metadata response from a peer.
    pub fn meta_data_response(&mut self, peer_id: &PeerId, meta_data: MetaData<TSpec>) {
        if let Some(peer_info) = self.peer_db.write().peer_info_mut(peer_id) {
            if let Some(known_meta_data) = &peer_info.meta_data() {
                if *known_meta_data.seq_number() < *meta_data.seq_number() {
                    debug!(self.log, "Updating peer's metadata";
                        "peer_id" => %peer_id, "known_seq_no" => known_meta_data.seq_number(), "new_seq_no" => meta_data.seq_number());
                } else {
                    debug!(self.log, "Received old metadata";
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
            .peer_db
            .write()
            .update_gossipsub_scores(self.target_peers, gossipsub);

        for (peer_id, score_action) in actions {
            self.handle_score_action(&peer_id, score_action, None);
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
        let ban_operation = self.peer_db.write().inject_disconnect(peer_id);

        if let Some(ban_operation) = ban_operation {
            // The peer was awaiting a ban, continue to ban the peer.
            self.handle_ban_operation(peer_id, ban_operation, None);
        }

        // Remove the ping and status timer for the peer
        self.inbound_ping_peers.remove(peer_id);
        self.outbound_ping_peers.remove(peer_id);
        self.status_peers.remove(peer_id);
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
            let mut peerdb = self.peer_db.write();
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

        let connected_peers = self.peer_db.read().connected_peer_count() as i64;

        // increment prometheus metrics
        metrics::inc_counter(&metrics::PEER_CONNECT_EVENT_COUNT);
        metrics::set_gauge(&metrics::PEERS_CONNECTED, connected_peers);
        metrics::set_gauge(&metrics::PEERS_CONNECTED_INTEROP, connected_peers);

        // Increment the PEERS_PER_CLIENT metric
        if let Some(kind) = self
            .peer_db
            .read()
            .peer_info(peer_id)
            .map(|peer_info| peer_info.client().kind.clone())
        {
            if let Some(v) =
                metrics::get_int_gauge(&metrics::PEERS_PER_CLIENT, &[&kind.to_string()])
            {
                v.inc()
            };
        }

        true
    }

    // Gracefully disconnects a peer without banning them.
    fn disconnect_peer(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        self.events
            .push(PeerManagerEvent::DisconnectPeer(peer_id, reason));
        self.peer_db.write().notify_disconnecting(&peer_id, false);
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
                    .peer_db
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

    /// The Peer manager's heartbeat maintains the peer count and maintains peer reputations.
    ///
    /// It will request discovery queries if the peer count has not reached the desired number of
    /// overall peers, as well as the desired number of outbound-only peers.
    ///
    /// NOTE: Discovery will only add a new query if one isn't already queued.
    fn heartbeat(&mut self) {
        let peer_count = self.peer_db.read().connected_or_dialing_peer_count();
        let mut outbound_only_peer_count = self.peer_db.read().connected_outbound_only_peer_count();
        let min_outbound_only_target =
            (self.target_peers as f32 * config::MIN_OUTBOUND_ONLY_FACTOR).ceil() as usize;

        if self.discovery_enabled
            && (peer_count < self.target_peers
                || outbound_only_peer_count < min_outbound_only_target)
        {
            // If we need more peers, queue a discovery lookup.
            debug!(self.log, "Starting a new peer discovery query"; "connected_peers" => peer_count, "target_peers" => self.target_peers);
            self.events.push(PeerManagerEvent::DiscoverPeers);
        }

        // Updates peer's scores and unban any peers if required.
        let actions = self.peer_db.write().update_scores();
        for (peer_id, action) in actions {
            self.handle_score_action(&peer_id, action, None);
        }

        // Maintain minimum count for sync committee peers.
        self.maintain_sync_committee_peers();

        // Keep a list of peers we are disconnecting
        let mut disconnecting_peers = Vec::new();

        let connected_peer_count = self.peer_db.read().connected_peer_count();
        if connected_peer_count > self.target_peers {
            // Remove excess peers with the worst scores, but keep subnet peers.
            // Must also ensure that the outbound-only peer count does not go below the minimum threshold.
            outbound_only_peer_count = self.peer_db.read().connected_outbound_only_peer_count();
            let mut n_outbound_removed = 0;
            for (peer_id, info) in self
                .peer_db
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

        for peer_id in disconnecting_peers {
            self.disconnect_peer(peer_id, GoodbyeReason::TooManyPeers);
        }
    }

    pub(crate) fn extend_peers_on_subnet(&self, subnet: &Subnet, min_ttl: Instant) {
        self.peer_db.write().extend_peers_on_subnet(subnet, min_ttl);
    }

    pub(crate) fn add_subscription(&self, peer_id: &PeerId, subnet_id: Subnet) {
        self.peer_db.write().add_subscription(peer_id, subnet_id)
    }

    pub(crate) fn remove_subscription(&self, peer_id: &PeerId, subnet_id: &Subnet) {
        self.peer_db.write().remove_subscription(peer_id, subnet_id)
    }
}

impl<TSpec: EthSpec> Stream for PeerManager<TSpec> {
    type Item = PeerManagerEvent;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // perform the heartbeat when necessary
        while self.heartbeat.poll_tick(cx).is_ready() {
            self.heartbeat();
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
            self.sync_state.read().clone(),
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
    use slog::{o, Drain};
    use types::MinimalEthSpec;

    type E = MinimalEthSpec;

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
        let cfg = config::Config {
            target_peer_count: target,
            ..Default::default()
        };
        let log = build_log(slog::Level::Debug, false);
        let sync_state = Owner::new(SyncState::Stalled);
        PeerManager::new(cfg, sync_state.read_access(), &log)
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
            .peer_db
            .write()
            .peer_info_mut(&outbound_only_peer1)
            .unwrap()
            .add_to_score(-1.0);

        peer_manager
            .peer_db
            .write()
            .peer_info_mut(&outbound_only_peer2)
            .unwrap()
            .add_to_score(-2.0);

        // Check initial connected peers.
        assert_eq!(
            peer_manager
                .peer_db
                .read()
                .connected_or_dialing_peer_count(),
            5
        );

        peer_manager.heartbeat();

        // Check that we disconnected from two peers.
        // Check that one outbound-only peer was removed because it had the worst score
        // and that we did not disconnect the other outbound peer due to the minimum outbound quota.
        assert_eq!(
            peer_manager
                .peer_db
                .read()
                .connected_or_dialing_peer_count(),
            3
        );
        assert!(peer_manager
            .peer_db
            .read()
            .is_connected(&outbound_only_peer1));
        assert!(!peer_manager
            .peer_db
            .read()
            .is_connected(&outbound_only_peer2));

        peer_manager.heartbeat();

        // Check that if we are at target number of peers, we do not disconnect any.
        assert_eq!(
            peer_manager
                .peer_db
                .read()
                .connected_or_dialing_peer_count(),
            3
        );
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
            .peer_db
            .write()
            .peer_info_mut(&(outbound_only_peer))
            .unwrap()
            .add_to_score(-1.0);
        // After heartbeat, we will have removed one peer.
        // Having less outbound-only peers than minimum won't cause panic when the outbound-only peer is being considered for disconnection.
        peer_manager.heartbeat();
        assert_eq!(
            peer_manager
                .peer_db
                .read()
                .connected_or_dialing_peer_count(),
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
            .peer_db
            .write()
            .peer_info_mut(&(inbound_only_peer1))
            .unwrap()
            .add_to_score(-19.8);
        peer_manager
            .peer_db
            .write()
            .peer_info_mut(&(outbound_only_peer1))
            .unwrap()
            .add_to_score(-19.8);
        peer_manager
            .peer_db
            .write()
            .peer_info_mut(&(inbound_only_peer1))
            .unwrap()
            .set_gossipsub_score(-85.0);
        peer_manager
            .peer_db
            .write()
            .peer_info_mut(&(outbound_only_peer1))
            .unwrap()
            .set_gossipsub_score(-85.0);
        peer_manager.heartbeat();
        // Tests that when we are over the target peer limit, after disconnecting one unhealthy peer,
        // the loop to check for disconnecting peers will stop because we have removed enough peers (only needed to remove 1 to reach target).
        assert_eq!(
            peer_manager
                .peer_db
                .read()
                .connected_or_dialing_peer_count(),
            3
        );
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
            .peer_db
            .write()
            .peer_info_mut(&(inbound_only_peer1))
            .unwrap()
            .add_to_score(-19.9);
        peer_manager
            .peer_db
            .write()
            .peer_info_mut(&(inbound_only_peer1))
            .unwrap()
            .set_gossipsub_score(-85.0);

        peer_manager.heartbeat();
        // Tests that when we are over the target peer limit, after disconnecting an unhealthy peer,
        // the number of connected peers updates and we will not remove too many peers.
        assert_eq!(
            peer_manager
                .peer_db
                .read()
                .connected_or_dialing_peer_count(),
            3
        );
    }
}
