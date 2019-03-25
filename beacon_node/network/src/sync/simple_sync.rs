use super::import_queue::ImportQueue;
use crate::beacon_chain::BeaconChain;
use crate::message_handler::NetworkContext;
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::{RPCRequest, RPCResponse};
use eth2_libp2p::PeerId;
use slog::{debug, error, info, o, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use types::{Epoch, Hash256, Slot};

/// The number of slots that we can import blocks ahead of us, before going into full Sync mode.
const SLOT_IMPORT_TOLERANCE: u64 = 100;

/// The amount of seconds a block (or partial block) may exist in the import queue.
const QUEUE_STALE_SECS: u64 = 60;

/// Keeps track of syncing information for known connected peers.
#[derive(Clone, Copy, Debug)]
pub struct PeerSyncInfo {
    network_id: u8,
    latest_finalized_root: Hash256,
    latest_finalized_epoch: Epoch,
    best_root: Hash256,
    best_slot: Slot,
}

impl PeerSyncInfo {
    /// Returns `true` if the has a different network ID to `other`.
    fn has_different_network_id_to(&self, other: Self) -> bool {
        self.network_id != other.network_id
    }

    /// Returns `true` if the peer has a higher finalized epoch than `other`.
    fn has_higher_finalized_epoch_than(&self, other: Self) -> bool {
        self.latest_finalized_epoch > other.latest_finalized_epoch
    }

    /// Returns `true` if the peer has a higher best slot than `other`.
    fn has_higher_best_slot_than(&self, other: Self) -> bool {
        self.best_slot > other.best_slot
    }
}

/// The status of a peers view on the chain, relative to some other view of the chain (presumably
/// our view).
#[derive(PartialEq, Clone, Copy, Debug)]
pub enum PeerStatus {
    /// The peer is on a completely different chain.
    DifferentNetworkId,
    /// The peer lists a finalized epoch for which we have a different root.
    FinalizedEpochNotInChain,
    /// The peer has a higher finalized epoch.
    HigherFinalizedEpoch,
    /// The peer has a higher best slot.
    HigherBestSlot,
    /// The peer has the same or lesser view of the chain. We have nothing to request of them.
    NotInteresting,
}

impl PeerStatus {
    pub fn should_handshake(&self) -> bool {
        match self {
            PeerStatus::DifferentNetworkId => false,
            PeerStatus::FinalizedEpochNotInChain => false,
            PeerStatus::HigherFinalizedEpoch => true,
            PeerStatus::HigherBestSlot => true,
            PeerStatus::NotInteresting => true,
        }
    }
}

impl From<HelloMessage> for PeerSyncInfo {
    fn from(hello: HelloMessage) -> PeerSyncInfo {
        PeerSyncInfo {
            network_id: hello.network_id,
            latest_finalized_root: hello.latest_finalized_root,
            latest_finalized_epoch: hello.latest_finalized_epoch,
            best_root: hello.best_root,
            best_slot: hello.best_slot,
        }
    }
}

impl From<&Arc<BeaconChain>> for PeerSyncInfo {
    fn from(chain: &Arc<BeaconChain>) -> PeerSyncInfo {
        Self::from(chain.hello_message())
    }
}

/// The current syncing state.
#[derive(PartialEq)]
pub enum SyncState {
    Idle,
    Downloading,
    _Stopped,
}

/// Simple Syncing protocol.
pub struct SimpleSync {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain>,
    /// A mapping of Peers to their respective PeerSyncInfo.
    known_peers: HashMap<PeerId, PeerSyncInfo>,
    /// A queue to allow importing of blocks
    import_queue: ImportQueue,
    /// The current state of the syncing protocol.
    state: SyncState,
    /// Sync logger.
    log: slog::Logger,
}

impl SimpleSync {
    /// Instantiate a `SimpleSync` instance, with no peers and an empty queue.
    pub fn new(beacon_chain: Arc<BeaconChain>, log: &slog::Logger) -> Self {
        let sync_logger = log.new(o!("Service"=> "Sync"));

        let queue_item_stale_time = Duration::from_secs(QUEUE_STALE_SECS);

        let import_queue =
            ImportQueue::new(beacon_chain.clone(), queue_item_stale_time, log.clone());
        SimpleSync {
            chain: beacon_chain.clone(),
            known_peers: HashMap::new(),
            import_queue,
            state: SyncState::Idle,
            log: sync_logger,
        }
    }

    /// Handle a `Goodbye` message from a peer.
    ///
    /// Removes the peer from `known_peers`.
    pub fn on_goodbye(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        info!(
            self.log, "PeerGoodbye";
            "peer" => format!("{:?}", peer_id),
            "reason" => format!("{:?}", reason),
        );

        self.known_peers.remove(&peer_id);
    }

    /// Handle the connection of a new peer.
    ///
    /// Sends a `Hello` message to the peer.
    pub fn on_connect(&self, peer_id: PeerId, network: &mut NetworkContext) {
        info!(self.log, "PeerConnect"; "peer" => format!("{:?}", peer_id));

        network.send_rpc_request(peer_id, RPCRequest::Hello(self.chain.hello_message()));
    }

    /// Handle a `Hello` request.
    ///
    /// Processes the `HelloMessage` from the remote peer and sends back our `Hello`.
    pub fn on_hello_request(
        &mut self,
        peer_id: PeerId,
        hello: HelloMessage,
        network: &mut NetworkContext,
    ) {
        debug!(self.log, "HelloRequest"; "peer" => format!("{:?}", peer_id));

        // Say hello back.
        network.send_rpc_response(
            peer_id.clone(),
            RPCResponse::Hello(self.chain.hello_message()),
        );

        self.process_hello(peer_id, hello, network);
    }

    /// Process a `Hello` response from a peer.
    pub fn on_hello_response(
        &mut self,
        peer_id: PeerId,
        hello: HelloMessage,
        network: &mut NetworkContext,
    ) {
        debug!(self.log, "HelloResponse"; "peer" => format!("{:?}", peer_id));

        // Process the hello message, without sending back another hello.
        self.process_hello(peer_id, hello, network);
    }

    /// Returns a `PeerStatus` for some peer.
    fn peer_status(&self, peer: PeerSyncInfo) -> PeerStatus {
        let local = PeerSyncInfo::from(&self.chain);

        if peer.has_different_network_id_to(local) {
            return PeerStatus::DifferentNetworkId;
        }

        if local.has_higher_finalized_epoch_than(peer) {
            let peer_finalized_slot = peer
                .latest_finalized_epoch
                .start_slot(self.chain.get_spec().slots_per_epoch);

            let local_roots = self.chain.get_block_roots(peer_finalized_slot, 1, 0);

            if let Ok(local_roots) = local_roots {
                if let Some(local_root) = local_roots.get(0) {
                    if *local_root != peer.latest_finalized_root {
                        return PeerStatus::FinalizedEpochNotInChain;
                    }
                } else {
                    error!(
                        self.log,
                        "Cannot get root for peer finalized slot.";
                        "error" => "empty roots"
                    );
                }
            } else {
                error!(
                    self.log,
                    "Cannot get root for peer finalized slot.";
                    "error" => format!("{:?}", local_roots)
                );
            }
        }

        if peer.has_higher_finalized_epoch_than(local) {
            PeerStatus::HigherFinalizedEpoch
        } else if peer.has_higher_best_slot_than(local) {
            PeerStatus::HigherBestSlot
        } else {
            PeerStatus::NotInteresting
        }
    }

    /// Process a `Hello` message, requesting new blocks if appropriate.
    ///
    /// Disconnects the peer if required.
    fn process_hello(
        &mut self,
        peer_id: PeerId,
        hello: HelloMessage,
        network: &mut NetworkContext,
    ) {
        let spec = self.chain.get_spec();

        let remote = PeerSyncInfo::from(hello);
        let local = PeerSyncInfo::from(&self.chain);
        let remote_status = self.peer_status(remote);

        if remote_status.should_handshake() {
            info!(self.log, "HandshakeSuccess"; "peer" => format!("{:?}", peer_id));
            self.known_peers.insert(peer_id.clone(), remote);
        } else {
            info!(
                self.log, "HandshakeFailure";
                "peer" => format!("{:?}", peer_id),
                "reason" => "network_id"
            );
            network.disconnect(peer_id.clone(), GoodbyeReason::IrreleventNetwork);
        }

        // If required, send requests for blocks.
        match remote_status {
            PeerStatus::HigherFinalizedEpoch => {
                let start_slot = remote
                    .latest_finalized_epoch
                    .start_slot(spec.slots_per_epoch);
                let required_slots = start_slot - local.best_slot;

                self.request_block_roots(
                    peer_id,
                    BeaconBlockRootsRequest {
                        start_slot,
                        count: required_slots.into(),
                    },
                    network,
                );
            }
            PeerStatus::HigherBestSlot => {
                let required_slots = remote.best_slot - local.best_slot;

                self.request_block_roots(
                    peer_id,
                    BeaconBlockRootsRequest {
                        start_slot: local.best_slot + 1,
                        count: required_slots.into(),
                    },
                    network,
                );
            }
            PeerStatus::FinalizedEpochNotInChain => {}
            PeerStatus::DifferentNetworkId => {}
            PeerStatus::NotInteresting => {}
        }
    }

    /// Handle a `BeaconBlockRoots` request from the peer.
    pub fn on_beacon_block_roots_request(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockRootsRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockRootsRequest";
            "peer" => format!("{:?}", peer_id),
            "count" => req.count,
        );

        let roots = match self
            .chain
            .get_block_roots(req.start_slot, req.count as usize, 0)
        {
            Ok(roots) => roots,
            Err(e) => {
                // TODO: return RPC error.
                warn!(
                    self.log,
                    "RPCRequest"; "peer" => format!("{:?}", peer_id),
                    "req" => "BeaconBlockRoots",
                    "error" => format!("{:?}", e)
                );
                return;
            }
        };

        let roots = roots
            .iter()
            .enumerate()
            .map(|(i, &block_root)| BlockRootSlot {
                slot: req.start_slot + Slot::from(i),
                block_root,
            })
            .collect();

        network.send_rpc_response(
            peer_id,
            RPCResponse::BeaconBlockRoots(BeaconBlockRootsResponse { roots }),
        )
    }

    /// Handle a `BeaconBlockRoots` response from the peer.
    pub fn on_beacon_block_roots_response(
        &mut self,
        peer_id: PeerId,
        res: BeaconBlockRootsResponse,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockRootsResponse";
            "peer" => format!("{:?}", peer_id),
            "count" => res.roots.len(),
        );

        if res.roots.is_empty() {
            warn!(
                self.log,
                "Peer returned empty block roots response. PeerId: {:?}", peer_id
            );
            return;
        }

        let new_root_index = self.import_queue.first_new_root(&res.roots);

        // If a new block root is found, request it and all the headers following it.
        //
        // We make an assumption here that if we don't know a block then we don't know of all
        // it's parents. This might not be the case if syncing becomes more sophisticated.
        if let Some(i) = new_root_index {
            let new = &res.roots[i];

            self.request_block_headers(
                peer_id,
                BeaconBlockHeadersRequest {
                    start_root: new.block_root,
                    start_slot: new.slot,
                    max_headers: (res.roots.len() - i) as u64,
                    skip_slots: 0,
                },
                network,
            )
        }
    }

    /// Handle a `BeaconBlockHeaders` request from the peer.
    pub fn on_beacon_block_headers_request(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockHeadersRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockHeadersRequest";
            "peer" => format!("{:?}", peer_id),
            "count" => req.max_headers,
        );

        let headers = match self.chain.get_block_headers(
            req.start_slot,
            req.max_headers as usize,
            req.skip_slots as usize,
        ) {
            Ok(headers) => headers,
            Err(e) => {
                // TODO: return RPC error.
                warn!(
                    self.log,
                    "RPCRequest"; "peer" => format!("{:?}", peer_id),
                    "req" => "BeaconBlockHeaders",
                    "error" => format!("{:?}", e)
                );
                return;
            }
        };

        network.send_rpc_response(
            peer_id,
            RPCResponse::BeaconBlockHeaders(BeaconBlockHeadersResponse { headers }),
        )
    }

    /// Handle a `BeaconBlockHeaders` response from the peer.
    pub fn on_beacon_block_headers_response(
        &mut self,
        peer_id: PeerId,
        res: BeaconBlockHeadersResponse,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockHeadersResponse";
            "peer" => format!("{:?}", peer_id),
            "count" => res.headers.len(),
        );

        if res.headers.is_empty() {
            warn!(
                self.log,
                "Peer returned empty block headers response. PeerId: {:?}", peer_id
            );
            return;
        }

        // Enqueue the headers, obtaining a list of the roots of the headers which were newly added
        // to the queue.
        let block_roots = self
            .import_queue
            .enqueue_headers(res.headers, peer_id.clone());

        self.request_block_bodies(peer_id, BeaconBlockBodiesRequest { block_roots }, network);
    }

    /// Handle a `BeaconBlockBodies` request from the peer.
    pub fn on_beacon_block_bodies_request(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockBodiesRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockBodiesRequest";
            "peer" => format!("{:?}", peer_id),
            "count" => req.block_roots.len(),
        );

        let block_bodies = match self.chain.get_block_bodies(&req.block_roots) {
            Ok(bodies) => bodies,
            Err(e) => {
                // TODO: return RPC error.
                warn!(
                    self.log,
                    "RPCRequest"; "peer" => format!("{:?}", peer_id),
                    "req" => "BeaconBlockBodies",
                    "error" => format!("{:?}", e)
                );
                return;
            }
        };

        network.send_rpc_response(
            peer_id,
            RPCResponse::BeaconBlockBodies(BeaconBlockBodiesResponse { block_bodies }),
        )
    }

    /// Handle a `BeaconBlockBodies` response from the peer.
    pub fn on_beacon_block_bodies_response(
        &mut self,
        peer_id: PeerId,
        res: BeaconBlockBodiesResponse,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockBodiesResponse";
            "peer" => format!("{:?}", peer_id),
            "count" => res.block_bodies.len(),
        );

        self.import_queue
            .enqueue_bodies(res.block_bodies, peer_id.clone());

        // Clear out old entries
        self.import_queue.remove_stale();

        // Import blocks, if possible.
        self.process_import_queue(network);
    }

    /// Process a gossip message declaring a new block.
    pub fn on_block_gossip(
        &mut self,
        peer_id: PeerId,
        msg: BlockGossip,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockGossip";
            "peer" => format!("{:?}", peer_id),
        );
        // TODO: filter out messages that a prior to the finalized slot.
        //
        // TODO: if the block is a few more slots ahead, try to get all block roots from then until
        // now.
        //
        // Note: only requests the new block -- will fail if we don't have its parents.
        if self.import_queue.is_new_block(&msg.root.block_root) {
            self.request_block_headers(
                peer_id,
                BeaconBlockHeadersRequest {
                    start_root: msg.root.block_root,
                    start_slot: msg.root.slot,
                    max_headers: 1,
                    skip_slots: 0,
                },
                network,
            )
        }
    }

    /// Process a gossip message declaring a new attestation.
    ///
    /// Not currently implemented.
    pub fn on_attestation_gossip(
        &mut self,
        peer_id: PeerId,
        msg: AttestationGossip,
        _network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "AttestationGossip";
            "peer" => format!("{:?}", peer_id),
        );

        // Awaiting a proper operations pool before we can import attestations.
        //
        // https://github.com/sigp/lighthouse/issues/281
        match self.chain.process_attestation(msg.attestation) {
            Ok(_) => panic!("Impossible, method not implemented."),
            Err(_) => error!(self.log, "Attestation processing not implemented!"),
        }
    }

    /// Iterate through the `import_queue` and process any complete blocks.
    ///
    /// If a block is successfully processed it is removed from the queue, otherwise it remains in
    /// the queue.
    pub fn process_import_queue(&mut self, network: &mut NetworkContext) {
        let mut successful = 0;
        let mut invalid = 0;
        let mut errored = 0;

        // Loop through all of the complete blocks in the queue.
        for (block_root, block, sender) in self.import_queue.complete_blocks() {
            match self.chain.process_block(block) {
                Ok(outcome) => {
                    if outcome.is_invalid() {
                        invalid += 1;
                        warn!(
                            self.log,
                            "InvalidBlock";
                            "sender_peer_id" => format!("{:?}", sender),
                            "reason" => format!("{:?}", outcome),
                        );
                        network.disconnect(sender, GoodbyeReason::Fault);
                    }

                    // If this results to true, the item will be removed from the queue.
                    if outcome.sucessfully_processed() {
                        successful += 1;
                        self.import_queue.remove(block_root);
                    }
                }
                Err(e) => {
                    errored += 1;
                    error!(self.log, "BlockProcessingError"; "error" => format!("{:?}", e));
                }
            }
        }

        if successful > 0 {
            info!(self.log, "Imported {} blocks", successful)
        }
        if invalid > 0 {
            warn!(self.log, "Rejected {} invalid blocks", invalid)
        }
        if errored > 0 {
            warn!(self.log, "Failed to process {} blocks", errored)
        }
    }

    /// Request some `BeaconBlockRoots` from the remote peer.
    fn request_block_roots(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockRootsRequest,
        network: &mut NetworkContext,
    ) {
        // Potentially set state to sync.
        if self.state == SyncState::Idle && req.count > SLOT_IMPORT_TOLERANCE {
            debug!(self.log, "Entering downloading sync state.");
            self.state = SyncState::Downloading;
        }

        debug!(
            self.log,
            "RPCRequest(BeaconBlockRoots)";
            "count" => req.count,
            "peer" => format!("{:?}", peer_id)
        );

        // TODO: handle count > max count.
        network.send_rpc_request(peer_id.clone(), RPCRequest::BeaconBlockRoots(req));
    }

    /// Request some `BeaconBlockHeaders` from the remote peer.
    fn request_block_headers(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockHeadersRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "RPCRequest(BeaconBlockHeaders)";
            "max_headers" => req.max_headers,
            "peer" => format!("{:?}", peer_id)
        );

        network.send_rpc_request(peer_id.clone(), RPCRequest::BeaconBlockHeaders(req));
    }

    /// Request some `BeaconBlockBodies` from the remote peer.
    fn request_block_bodies(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockBodiesRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "RPCRequest(BeaconBlockBodies)";
            "count" => req.block_roots.len(),
            "peer" => format!("{:?}", peer_id)
        );

        network.send_rpc_request(peer_id.clone(), RPCRequest::BeaconBlockBodies(req));
    }

    /// Generates our current state in the form of a HELLO RPC message.
    pub fn generate_hello(&self) -> HelloMessage {
        self.chain.hello_message()
    }
}
