use super::import_queue::ImportQueue;
use crate::message_handler::NetworkContext;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome, InvalidBlock};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::{RPCRequest, RPCResponse, RequestId};
use eth2_libp2p::PeerId;
use slog::{debug, error, info, o, warn};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tree_hash::TreeHash;
use types::{Attestation, BeaconBlock, BeaconBlockHeader, Epoch, EthSpec, Hash256, Slot};

/// The number of slots that we can import blocks ahead of us, before going into full Sync mode.
const SLOT_IMPORT_TOLERANCE: u64 = 100;

/// The amount of seconds a block (or partial block) may exist in the import queue.
const QUEUE_STALE_SECS: u64 = 600;

/// If a block is more than `FUTURE_SLOT_TOLERANCE` slots ahead of our slot clock, we drop it.
/// Otherwise we queue it.
const FUTURE_SLOT_TOLERANCE: u64 = 1;

/// Keeps track of syncing information for known connected peers.
#[derive(Clone, Copy, Debug)]
pub struct PeerSyncInfo {
    network_id: u8,
    latest_finalized_root: Hash256,
    latest_finalized_epoch: Epoch,
    best_root: Hash256,
    best_slot: Slot,
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

impl<T: BeaconChainTypes> From<&Arc<BeaconChain<T>>> for PeerSyncInfo {
    fn from(chain: &Arc<BeaconChain<T>>) -> PeerSyncInfo {
        Self::from(hello_message(chain))
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
pub struct SimpleSync<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,
    /// A mapping of Peers to their respective PeerSyncInfo.
    known_peers: HashMap<PeerId, PeerSyncInfo>,
    /// A queue to allow importing of blocks
    import_queue: ImportQueue<T>,
    /// The current state of the syncing protocol.
    state: SyncState,
    /// Sync logger.
    log: slog::Logger,
}

impl<T: BeaconChainTypes> SimpleSync<T> {
    /// Instantiate a `SimpleSync` instance, with no peers and an empty queue.
    pub fn new(beacon_chain: Arc<BeaconChain<T>>, log: &slog::Logger) -> Self {
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
        info!(self.log, "PeerConnected"; "peer" => format!("{:?}", peer_id));

        network.send_rpc_request(peer_id, RPCRequest::Hello(hello_message(&self.chain)));
    }

    /// Handle a `Hello` request.
    ///
    /// Processes the `HelloMessage` from the remote peer and sends back our `Hello`.
    pub fn on_hello_request(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        hello: HelloMessage,
        network: &mut NetworkContext,
    ) {
        debug!(self.log, "HelloRequest"; "peer" => format!("{:?}", peer_id));

        // Say hello back.
        network.send_rpc_response(
            peer_id.clone(),
            request_id,
            RPCResponse::Hello(hello_message(&self.chain)),
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

    /// Process a `Hello` message, requesting new blocks if appropriate.
    ///
    /// Disconnects the peer if required.
    fn process_hello(
        &mut self,
        peer_id: PeerId,
        hello: HelloMessage,
        network: &mut NetworkContext,
    ) {
        let spec = T::EthSpec::spec();

        let remote = PeerSyncInfo::from(hello);
        let local = PeerSyncInfo::from(&self.chain);

        let network_id_mismatch = local.network_id != remote.network_id;
        let on_different_finalized_chain = (local.latest_finalized_epoch
            >= remote.latest_finalized_epoch)
            && (!self
                .chain
                .rev_iter_block_roots(local.best_slot)
                .any(|root| root == remote.latest_finalized_root));

        if network_id_mismatch || on_different_finalized_chain {
            info!(
                self.log, "HandshakeFailure";
                "peer" => format!("{:?}", peer_id),
                "reason" => "network_id"
            );
            network.disconnect(peer_id.clone(), GoodbyeReason::IrreleventNetwork);
            return;
        } else {
            info!(self.log, "HandshakeSuccess"; "peer" => format!("{:?}", peer_id));
            self.known_peers.insert(peer_id.clone(), remote);
        }

        // If we have equal or better finalized epochs and best slots, we require nothing else from
        // this peer.
        if (remote.latest_finalized_epoch <= local.latest_finalized_epoch)
            && (remote.best_slot <= local.best_slot)
        {
            return;
        }

        // If the remote has a higher finalized epoch, request all block roots from our finalized
        // epoch through to its best slot.
        if remote.latest_finalized_epoch > local.latest_finalized_epoch {
            let start_slot = local
                .latest_finalized_epoch
                .start_slot(spec.slots_per_epoch);
            let required_slots = start_slot - remote.best_slot;

            self.request_block_roots(
                peer_id,
                BeaconBlockRootsRequest {
                    start_slot,
                    count: required_slots.into(),
                },
                network,
            );
        // If the remote has a greater best slot, request the roots between our best slot and their
        // best slot.
        } else if remote.best_root > local.best_root {
            let start_slot = local
                .latest_finalized_epoch
                .start_slot(spec.slots_per_epoch);
            let required_slots = start_slot - remote.best_slot;

            self.request_block_roots(
                peer_id,
                BeaconBlockRootsRequest {
                    start_slot,
                    count: required_slots.into(),
                },
                network,
            );
        }
    }

    /// Handle a `BeaconBlockRoots` request from the peer.
    pub fn on_beacon_block_roots_request(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        req: BeaconBlockRootsRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockRootsRequest";
            "peer" => format!("{:?}", peer_id),
            "count" => req.count,
        );

        let roots = self
            .chain
            .rev_iter_block_roots(req.start_slot)
            .take(req.count as usize)
            .enumerate()
            .map(|(i, block_root)| BlockRootSlot {
                slot: req.start_slot + Slot::from(i),
                block_root,
            })
            .collect();

        network.send_rpc_response(
            peer_id,
            request_id,
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
                "Peer returned empty block roots response";
                "peer_id" => format!("{:?}", peer_id)
            );
            return;
        }

        // The wire protocol specifies that slots must be in ascending order.
        if !res.slots_are_ascending() {
            warn!(
                self.log,
                "Peer returned block roots response with bad slot ordering";
                "peer_id" => format!("{:?}", peer_id)
            );
            return;
        }

        let new_roots = self
            .import_queue
            .enqueue_block_roots(&res.roots, peer_id.clone());

        // No new roots means nothing to do.
        //
        // This check protects against future panics.
        if new_roots.is_empty() {
            return;
        }

        // Determine the first (earliest) and last (latest) `BlockRootSlot` items.
        //
        // This logic relies upon slots to be in ascending order, which is enforced earlier.
        let first = new_roots.first().expect("Non-empty list must have first");
        let last = new_roots.last().expect("Non-empty list must have last");

        // Request all headers between the earliest and latest new `BlockRootSlot` items.
        self.request_block_headers(
            peer_id,
            BeaconBlockHeadersRequest {
                start_root: first.block_root,
                start_slot: first.slot,
                max_headers: (last.slot - first.slot + 1).as_u64(),
                skip_slots: 0,
            },
            network,
        )
    }

    /// Handle a `BeaconBlockHeaders` request from the peer.
    pub fn on_beacon_block_headers_request(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        req: BeaconBlockHeadersRequest,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BlockHeadersRequest";
            "peer" => format!("{:?}", peer_id),
            "count" => req.max_headers,
        );

        let headers = get_block_headers(
            &self.chain,
            req.start_slot,
            req.max_headers as usize,
            req.skip_slots as usize,
        );

        network.send_rpc_response(
            peer_id,
            request_id,
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
        request_id: RequestId,
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
            request_id,
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
    ///
    /// Returns a `bool` which, if `true`, indicates we should forward the block to our peers.
    pub fn on_block_gossip(
        &mut self,
        peer_id: PeerId,
        block: BeaconBlock,
        network: &mut NetworkContext,
    ) -> bool {
        info!(
            self.log,
            "GossipBlockReceived";
            "peer" => format!("{:?}", peer_id),
            "block_slot" => format!("{:?}", block.slot),
        );

        // Ignore any block from a finalized slot.
        if self.slot_is_finalized(block.slot) {
            warn!(
                self.log, "IgnoredGossipBlock";
                "msg" => "new block slot is finalized.",
                "block_slot" => block.slot,
            );
            return false;
        }

        let block_root = Hash256::from_slice(&block.tree_hash_root());

        // Ignore any block that the chain already knows about.
        if self.chain_has_seen_block(&block_root) {
            // TODO: Age confirm that we shouldn't forward a block if we already know of it.
            return false;
        }

        match self.chain.process_block(block.clone()) {
            Ok(BlockProcessingOutcome::InvalidBlock(InvalidBlock::ParentUnknown)) => {
                // The block was valid and we processed it successfully.
                debug!(
                    self.log, "InvalidGossipBlock";
                    "msg" => "parent block unknown",
                    "parent_root" => format!("{}", block.previous_block_root),
                    "peer" => format!("{:?}", peer_id),
                );
                // Queue the block for later processing.
                self.import_queue
                    .enqueue_full_blocks(vec![block], peer_id.clone());
                // Send a hello to learn of the clients best slot so we can then sync the require
                // parent(s).
                network.send_rpc_request(
                    peer_id.clone(),
                    RPCRequest::Hello(hello_message(&self.chain)),
                );
                // Forward the block onto our peers.
                //
                // Note: this may need to be changed if we decide to only forward blocks if we have
                // all required info.
                true
            }
            Ok(BlockProcessingOutcome::InvalidBlock(InvalidBlock::FutureSlot {
                present_slot,
                block_slot,
            })) => {
                if block_slot - present_slot > FUTURE_SLOT_TOLERANCE {
                    // The block is too far in the future, drop it.
                    warn!(
                        self.log, "InvalidGossipBlock";
                        "msg" => "future block rejected",
                        "present_slot" => present_slot,
                        "block_slot" => block_slot,
                        "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                        "peer" => format!("{:?}", peer_id),
                    );
                    // Do not forward the block around to peers.
                    false
                } else {
                    // The block is in the future, but not too far.
                    warn!(
                        self.log, "FutureGossipBlock";
                        "msg" => "queuing future block",
                        "present_slot" => present_slot,
                        "block_slot" => block_slot,
                        "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                        "peer" => format!("{:?}", peer_id),
                    );
                    // Queue the block for later processing.
                    self.import_queue.enqueue_full_blocks(vec![block], peer_id);
                    // Forward the block around to peers.
                    true
                }
            }
            Ok(outcome) => {
                if outcome.is_invalid() {
                    // The peer has sent a block which is fundamentally invalid.
                    warn!(
                        self.log, "InvalidGossipBlock";
                        "msg" => "peer sent objectively invalid block",
                        "outcome" => format!("{:?}", outcome),
                        "peer" => format!("{:?}", peer_id),
                    );
                    // Disconnect the peer
                    network.disconnect(peer_id, GoodbyeReason::Fault);
                    // Do not forward the block to peers.
                    false
                } else if outcome.sucessfully_processed() {
                    // The block was valid and we processed it successfully.
                    info!(
                        self.log, "ValidGossipBlock";
                        "peer" => format!("{:?}", peer_id),
                    );
                    // Forward the block to peers
                    true
                } else {
                    // The block wasn't necessarily invalid but we didn't process it successfully.
                    // This condition shouldn't be reached.
                    error!(
                        self.log, "InvalidGossipBlock";
                        "msg" => "unexpected condition in processing block.",
                        "outcome" => format!("{:?}", outcome),
                    );
                    // Do not forward the block on.
                    false
                }
            }
            Err(e) => {
                // We encountered an error whilst processing the block.
                //
                // Blocks should not be able to trigger errors, instead they should be flagged as
                // invalid.
                error!(
                    self.log, "InvalidGossipBlock";
                    "msg" => "internal error in processing block.",
                    "error" => format!("{:?}", e),
                );
                // Do not forward the block to peers.
                false
            }
        }
    }

    /// Process a gossip message declaring a new attestation.
    ///
    /// Not currently implemented.
    pub fn on_attestation_gossip(
        &mut self,
        peer_id: PeerId,
        msg: Attestation,
        _network: &mut NetworkContext,
    ) {
        info!(
            self.log,
            "NewAttestationGossip";
            "peer" => format!("{:?}", peer_id),
        );

        match self.chain.process_attestation(msg) {
            Ok(()) => info!(self.log, "ImportedAttestation"),
            Err(e) => warn!(self.log, "InvalidAttestation"; "error" => format!("{:?}", e)),
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
                        break;
                    }

                    // If this results to true, the item will be removed from the queue.
                    if outcome.sucessfully_processed() {
                        successful += 1;
                        self.import_queue.remove(block_root);
                    } else {
                        debug!(
                            self.log,
                            "ProcessImportQueue";
                            "msg" => "Block not imported",
                            "outcome" => format!("{:?}", outcome),
                            "peer" => format!("{:?}", sender),
                        );
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

    /// Returns `true` if `self.chain` has not yet processed this block.
    pub fn chain_has_seen_block(&self, block_root: &Hash256) -> bool {
        !self
            .chain
            .is_new_block_root(&block_root)
            .unwrap_or_else(|_| {
                error!(self.log, "Unable to determine if block is new.");
                false
            })
    }

    /// Returns `true` if the given slot is finalized in our chain.
    fn slot_is_finalized(&self, slot: Slot) -> bool {
        slot <= hello_message(&self.chain)
            .latest_finalized_epoch
            .start_slot(T::EthSpec::spec().slots_per_epoch)
    }

    /// Generates our current state in the form of a HELLO RPC message.
    pub fn generate_hello(&self) -> HelloMessage {
        hello_message(&self.chain)
    }
}

/// Build a `HelloMessage` representing the state of the given `beacon_chain`.
fn hello_message<T: BeaconChainTypes>(beacon_chain: &BeaconChain<T>) -> HelloMessage {
    let spec = T::EthSpec::spec();
    let state = &beacon_chain.head().beacon_state;

    HelloMessage {
        network_id: spec.chain_id,
        latest_finalized_root: state.finalized_root,
        latest_finalized_epoch: state.finalized_epoch,
        best_root: beacon_chain.head().beacon_block_root,
        best_slot: state.slot,
    }
}

/// Return a list of `BeaconBlockHeader` from the given `BeaconChain`, starting at `start_slot` and
/// returning `count` headers with a gap of `skip` slots between each.
fn get_block_headers<T: BeaconChainTypes>(
    beacon_chain: &BeaconChain<T>,
    start_slot: Slot,
    count: usize,
    skip: usize,
) -> Vec<BeaconBlockHeader> {
    beacon_chain
        .rev_iter_blocks(start_slot)
        .step_by(skip + 1)
        .take(count)
        .map(|block| block.block_header())
        .collect()
}
