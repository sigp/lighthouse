use super::import_queue::{ImportQueue, PartialBeaconBlockCompletion};
use crate::message_handler::NetworkContext;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::{RPCRequest, RPCResponse, RequestId};
use eth2_libp2p::PeerId;
use slog::{debug, error, info, o, trace, warn};
use ssz::Encode;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use store::Store;
use types::{
    Attestation, BeaconBlock, BeaconBlockBody, BeaconBlockHeader, Epoch, EthSpec, Hash256, Slot,
};

/// The number of slots that we can import blocks ahead of us, before going into full Sync mode.
const SLOT_IMPORT_TOLERANCE: u64 = 100;

/// The amount of seconds a block (or partial block) may exist in the import queue.
const QUEUE_STALE_SECS: u64 = 100;

/// If a block is more than `FUTURE_SLOT_TOLERANCE` slots ahead of our slot clock, we drop it.
/// Otherwise we queue it.
const FUTURE_SLOT_TOLERANCE: u64 = 1;

const SHOULD_FORWARD_GOSSIP_BLOCK: bool = true;
const SHOULD_NOT_FORWARD_GOSSIP_BLOCK: bool = false;

/// Keeps track of syncing information for known connected peers.
#[derive(Clone, Copy, Debug)]
pub struct PeerSyncInfo {
    network_id: u8,
    chain_id: u64,
    latest_finalized_root: Hash256,
    latest_finalized_epoch: Epoch,
    best_root: Hash256,
    best_slot: Slot,
}

impl From<HelloMessage> for PeerSyncInfo {
    fn from(hello: HelloMessage) -> PeerSyncInfo {
        PeerSyncInfo {
            network_id: hello.network_id,
            chain_id: hello.chain_id,
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

    /// Handle a peer disconnect.
    ///
    /// Removes the peer from `known_peers`.
    pub fn on_disconnect(&mut self, peer_id: PeerId) {
        info!(
            self.log, "Peer Disconnected";
            "peer" => format!("{:?}", peer_id),
        );
        self.known_peers.remove(&peer_id);
    }

    /// Handle the connection of a new peer.
    ///
    /// Sends a `Hello` message to the peer.
    pub fn on_connect(&self, peer_id: PeerId, network: &mut NetworkContext<T::EthSpec>) {
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
        network: &mut NetworkContext<T::EthSpec>,
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
        network: &mut NetworkContext<T::EthSpec>,
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
        network: &mut NetworkContext<T::EthSpec>,
    ) {
        let remote = PeerSyncInfo::from(hello);
        let local = PeerSyncInfo::from(&self.chain);

        let start_slot = |epoch: Epoch| epoch.start_slot(T::EthSpec::slots_per_epoch());

        if local.network_id != remote.network_id {
            // The node is on a different network, disconnect them.
            info!(
                self.log, "HandshakeFailure";
                "peer" => format!("{:?}", peer_id),
                "reason" => "network_id"
            );

            network.disconnect(peer_id.clone(), GoodbyeReason::IrrelevantNetwork);
        } else if remote.latest_finalized_epoch <= local.latest_finalized_epoch
            && remote.latest_finalized_root != Hash256::zero()
            && local.latest_finalized_root != Hash256::zero()
            && (self.root_at_slot(start_slot(remote.latest_finalized_epoch))
                != Some(remote.latest_finalized_root))
        {
            // The remotes finalized epoch is less than or greater than ours, but the block root is
            // different to the one in our chain.
            //
            // Therefore, the node is on a different chain and we should not communicate with them.
            info!(
                self.log, "HandshakeFailure";
                "peer" => format!("{:?}", peer_id),
                "reason" => "different finalized chain"
            );
            network.disconnect(peer_id.clone(), GoodbyeReason::IrrelevantNetwork);
        } else if remote.latest_finalized_epoch < local.latest_finalized_epoch {
            // The node has a lower finalized epoch, their chain is not useful to us. There are two
            // cases where a node can have a lower finalized epoch:
            //
            // ## The node is on the same chain
            //
            // If a node is on the same chain but has a lower finalized epoch, their head must be
            // lower than ours. Therefore, we have nothing to request from them.
            //
            // ## The node is on a fork
            //
            // If a node is on a fork that has a lower finalized epoch, switching to that fork would
            // cause us to revert a finalized block. This is not permitted, therefore we have no
            // interest in their blocks.
            debug!(
                self.log,
                "NaivePeer";
                "peer" => format!("{:?}", peer_id),
                "reason" => "lower finalized epoch"
            );
        } else if self
            .chain
            .store
            .exists::<BeaconBlock<T::EthSpec>>(&remote.best_root)
            .unwrap_or_else(|_| false)
        {
            // If the node's best-block is already known to us, we have nothing to request.
            debug!(
                self.log,
                "NaivePeer";
                "peer" => format!("{:?}", peer_id),
                "reason" => "best block is known"
            );
        } else {
            // The remote node has an equal or great finalized epoch and we don't know it's head.
            //
            // Therefore, there are some blocks between the local finalized epoch and the remote
            // head that are worth downloading.
            debug!(
                self.log, "UsefulPeer";
                "peer" => format!("{:?}", peer_id),
                "local_finalized_epoch" => local.latest_finalized_epoch,
                "remote_latest_finalized_epoch" => remote.latest_finalized_epoch,
            );

            let start_slot = local
                .latest_finalized_epoch
                .start_slot(T::EthSpec::slots_per_epoch());
            let required_slots = remote.best_slot - start_slot;

            self.request_block_roots(
                peer_id,
                BeaconBlockRootsRequest {
                    start_slot,
                    count: required_slots.as_u64(),
                },
                network,
            );
        }
    }

    fn root_at_slot(&self, target_slot: Slot) -> Option<Hash256> {
        self.chain
            .rev_iter_block_roots(target_slot)
            .take(1)
            .find(|(_root, slot)| *slot == target_slot)
            .map(|(root, _slot)| root)
    }

    /// Handle a `BeaconBlockRoots` request from the peer.
    pub fn on_beacon_block_roots_request(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        req: BeaconBlockRootsRequest,
        network: &mut NetworkContext<T::EthSpec>,
    ) {
        let state = &self.chain.head().beacon_state;

        debug!(
            self.log,
            "BlockRootsRequest";
            "peer" => format!("{:?}", peer_id),
            "count" => req.count,
            "start_slot" => req.start_slot,
        );

        let mut roots: Vec<BlockRootSlot> = self
            .chain
            .rev_iter_block_roots(std::cmp::min(req.start_slot + req.count, state.slot))
            .take_while(|(_root, slot)| req.start_slot <= *slot)
            .map(|(block_root, slot)| BlockRootSlot { slot, block_root })
            .collect();

        if roots.len() as u64 != req.count {
            debug!(
                self.log,
                "BlockRootsRequest";
                "peer" => format!("{:?}", peer_id),
                "msg" => "Failed to return all requested hashes",
                "start_slot" => req.start_slot,
                "current_slot" => self.chain.present_slot(),
                "requested" => req.count,
                "returned" => roots.len(),
            );
        }

        roots.reverse();
        roots.dedup_by_key(|brs| brs.block_root);

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
        network: &mut NetworkContext<T::EthSpec>,
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
        network: &mut NetworkContext<T::EthSpec>,
    ) {
        let state = &self.chain.head().beacon_state;

        debug!(
            self.log,
            "BlockHeadersRequest";
            "peer" => format!("{:?}", peer_id),
            "count" => req.max_headers,
        );

        let count = req.max_headers;

        // Collect the block roots.
        let mut roots: Vec<Hash256> = self
            .chain
            .rev_iter_block_roots(std::cmp::min(req.start_slot + count, state.slot))
            .take_while(|(_root, slot)| req.start_slot <= *slot)
            .map(|(root, _slot)| root)
            .collect();

        roots.reverse();
        roots.dedup();

        let headers: Vec<BeaconBlockHeader> = roots
            .into_iter()
            .step_by(req.skip_slots as usize + 1)
            .filter_map(|root| {
                let block = self
                    .chain
                    .store
                    .get::<BeaconBlock<T::EthSpec>>(&root)
                    .ok()?;
                Some(block?.block_header())
            })
            .collect();

        // ssz-encode the headers
        let headers = headers.as_ssz_bytes();

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
        headers: Vec<BeaconBlockHeader>,
        network: &mut NetworkContext<T::EthSpec>,
    ) {
        debug!(
            self.log,
            "BlockHeadersResponse";
            "peer" => format!("{:?}", peer_id),
            "count" => headers.len(),
        );

        if headers.is_empty() {
            warn!(
                self.log,
                "Peer returned empty block headers response. PeerId: {:?}", peer_id
            );
            return;
        }

        // Enqueue the headers, obtaining a list of the roots of the headers which were newly added
        // to the queue.
        let block_roots = self.import_queue.enqueue_headers(headers, peer_id.clone());

        if !block_roots.is_empty() {
            self.request_block_bodies(peer_id, BeaconBlockBodiesRequest { block_roots }, network);
        }
    }

    /// Handle a `BeaconBlockBodies` request from the peer.
    pub fn on_beacon_block_bodies_request(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        req: BeaconBlockBodiesRequest,
        network: &mut NetworkContext<T::EthSpec>,
    ) {
        let block_bodies: Vec<BeaconBlockBody<_>> = req
            .block_roots
            .iter()
            .filter_map(|root| {
                if let Ok(Some(block)) = self.chain.store.get::<BeaconBlock<T::EthSpec>>(root) {
                    Some(block.body)
                } else {
                    debug!(
                        self.log,
                        "Peer requested unknown block";
                        "peer" => format!("{:?}", peer_id),
                        "request_root" => format!("{:}", root),
                    );

                    None
                }
            })
            .collect();

        debug!(
            self.log,
            "BlockBodiesRequest";
            "peer" => format!("{:?}", peer_id),
            "requested" => req.block_roots.len(),
            "returned" => block_bodies.len(),
        );

        let bytes = block_bodies.as_ssz_bytes();

        network.send_rpc_response(
            peer_id,
            request_id,
            RPCResponse::BeaconBlockBodies(BeaconBlockBodiesResponse {
                block_bodies: bytes,
                block_roots: None,
            }),
        )
    }

    /// Handle a `BeaconBlockBodies` response from the peer.
    pub fn on_beacon_block_bodies_response(
        &mut self,
        peer_id: PeerId,
        res: DecodedBeaconBlockBodiesResponse<T::EthSpec>,
        network: &mut NetworkContext<T::EthSpec>,
    ) {
        debug!(
            self.log,
            "BlockBodiesResponse";
            "peer" => format!("{:?}", peer_id),
            "count" => res.block_bodies.len(),
        );

        if !res.block_bodies.is_empty() {
            // Import all blocks to queue
            let last_root = self
                .import_queue
                .enqueue_bodies(res.block_bodies, peer_id.clone());

            // Attempt to process all received bodies by recursively processing the latest block
            if let Some(root) = last_root {
                if let Some(BlockProcessingOutcome::Processed { .. }) =
                    self.attempt_process_partial_block(peer_id, root, network, &"rpc")
                {
                    // If processing is successful remove from `import_queue`
                    self.import_queue.remove(root);
                }
            }
        }

        // Clear out old entries
        self.import_queue.remove_stale();
    }

    /// Process a gossip message declaring a new block.
    ///
    /// Attempts to apply to block to the beacon chain. May queue the block for later processing.
    ///
    /// Returns a `bool` which, if `true`, indicates we should forward the block to our peers.
    pub fn on_block_gossip(
        &mut self,
        peer_id: PeerId,
        block: BeaconBlock<T::EthSpec>,
        network: &mut NetworkContext<T::EthSpec>,
    ) -> bool {
        if let Some(outcome) =
            self.process_block(peer_id.clone(), block.clone(), network, &"gossip")
        {
            match outcome {
                BlockProcessingOutcome::Processed { .. } => SHOULD_FORWARD_GOSSIP_BLOCK,
                BlockProcessingOutcome::ParentUnknown { parent } => {
                    // Add this block to the queue
                    self.import_queue
                        .enqueue_full_blocks(vec![block.clone()], peer_id.clone());
                    debug!(
                        self.log, "RequestParentBlock";
                        "parent_root" => format!("{}", parent),
                        "parent_slot" => block.slot - 1,
                        "peer" => format!("{:?}", peer_id),
                    );

                    // Request roots between parent and start of finality from peer.
                    let start_slot = self
                        .chain
                        .head()
                        .beacon_state
                        .finalized_checkpoint
                        .epoch
                        .start_slot(T::EthSpec::slots_per_epoch());
                    self.request_block_roots(
                        peer_id,
                        BeaconBlockRootsRequest {
                            // Request blocks between `latest_finalized_slot` and the `block`
                            start_slot,
                            count: block.slot.as_u64() - start_slot.as_u64(),
                        },
                        network,
                    );

                    // Clean the stale entries from the queue.
                    self.import_queue.remove_stale();

                    SHOULD_FORWARD_GOSSIP_BLOCK
                }

                BlockProcessingOutcome::FutureSlot {
                    present_slot,
                    block_slot,
                } if present_slot + FUTURE_SLOT_TOLERANCE >= block_slot => {
                    self.import_queue
                        .enqueue_full_blocks(vec![block], peer_id.clone());

                    SHOULD_FORWARD_GOSSIP_BLOCK
                }
                // Note: known blocks are forwarded on the gossip network.
                //
                // We rely upon the lower layers (libp2p) to stop loops occurring from re-gossiped
                // blocks.
                BlockProcessingOutcome::BlockIsAlreadyKnown => SHOULD_FORWARD_GOSSIP_BLOCK,
                _ => SHOULD_NOT_FORWARD_GOSSIP_BLOCK,
            }
        } else {
            SHOULD_NOT_FORWARD_GOSSIP_BLOCK
        }
    }

    /// Process a gossip message declaring a new attestation.
    ///
    /// Not currently implemented.
    pub fn on_attestation_gossip(
        &mut self,
        _peer_id: PeerId,
        msg: Attestation<T::EthSpec>,
        _network: &mut NetworkContext<T::EthSpec>,
    ) {
        match self.chain.process_attestation(msg) {
            Ok(()) => info!(self.log, "ImportedAttestation"; "source" => "gossip"),
            Err(e) => {
                warn!(self.log, "InvalidAttestation"; "source" => "gossip", "error" => format!("{:?}", e))
            }
        }
    }

    /// Request some `BeaconBlockRoots` from the remote peer.
    fn request_block_roots(
        &mut self,
        peer_id: PeerId,
        req: BeaconBlockRootsRequest,
        network: &mut NetworkContext<T::EthSpec>,
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
        network: &mut NetworkContext<T::EthSpec>,
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
        network: &mut NetworkContext<T::EthSpec>,
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

    /// Generates our current state in the form of a HELLO RPC message.
    pub fn generate_hello(&self) -> HelloMessage {
        hello_message(&self.chain)
    }

    /// Helper function to attempt to process a partial block.
    ///
    /// If the block can be completed recursively call `process_block`
    /// else request missing parts.
    fn attempt_process_partial_block(
        &mut self,
        peer_id: PeerId,
        block_root: Hash256,
        network: &mut NetworkContext<T::EthSpec>,
        source: &str,
    ) -> Option<BlockProcessingOutcome> {
        match self.import_queue.attempt_complete_block(block_root) {
            PartialBeaconBlockCompletion::MissingBody => {
                // Unable to complete the block because the block body is missing.
                debug!(
                    self.log, "RequestParentBody";
                    "source" => source,
                    "block_root" => format!("{}", block_root),
                    "peer" => format!("{:?}", peer_id),
                );

                // Request the block body from the peer.
                self.request_block_bodies(
                    peer_id,
                    BeaconBlockBodiesRequest {
                        block_roots: vec![block_root],
                    },
                    network,
                );

                None
            }
            PartialBeaconBlockCompletion::MissingHeader(slot) => {
                // Unable to complete the block because the block header is missing.
                debug!(
                    self.log, "RequestParentHeader";
                    "source" => source,
                    "block_root" => format!("{}", block_root),
                    "peer" => format!("{:?}", peer_id),
                );

                // Request the block header from the peer.
                self.request_block_headers(
                    peer_id,
                    BeaconBlockHeadersRequest {
                        start_root: block_root,
                        start_slot: slot,
                        max_headers: 1,
                        skip_slots: 0,
                    },
                    network,
                );

                None
            }
            PartialBeaconBlockCompletion::MissingRoot => {
                // The `block_root` is not known to the queue.
                debug!(
                    self.log, "MissingParentRoot";
                    "source" => source,
                    "block_root" => format!("{}", block_root),
                    "peer" => format!("{:?}", peer_id),
                );

                // Do nothing.

                None
            }
            PartialBeaconBlockCompletion::Complete(block) => {
                // The block exists in the queue, attempt to process it
                trace!(
                    self.log, "AttemptProcessParent";
                    "source" => source,
                    "block_root" => format!("{}", block_root),
                    "parent_slot" => block.slot,
                    "peer" => format!("{:?}", peer_id),
                );

                self.process_block(peer_id.clone(), block, network, source)
            }
        }
    }

    /// Processes the `block` that was received from `peer_id`.
    ///
    /// If the block was submitted to the beacon chain without internal error, `Some(outcome)` is
    /// returned, otherwise `None` is returned. Note: `Some(_)` does not necessarily indicate that
    /// the block was successfully processed or valid.
    ///
    /// This function performs the following duties:
    ///
    ///  - Attempting to import the block into the beacon chain.
    ///  - Logging
    ///  - Requesting unavailable blocks (e.g., if parent is unknown).
    ///  - Disconnecting faulty nodes.
    ///
    /// This function does not remove processed blocks from the import queue.
    fn process_block(
        &mut self,
        peer_id: PeerId,
        block: BeaconBlock<T::EthSpec>,
        network: &mut NetworkContext<T::EthSpec>,
        source: &str,
    ) -> Option<BlockProcessingOutcome> {
        let processing_result = self.chain.process_block(block.clone());

        if let Ok(outcome) = processing_result {
            match outcome {
                BlockProcessingOutcome::Processed { block_root } => {
                    // The block was valid and we processed it successfully.
                    debug!(
                        self.log, "Imported block from network";
                        "source" => source,
                        "slot" => block.slot,
                        "block_root" => format!("{}", block_root),
                        "peer" => format!("{:?}", peer_id),
                    );
                }
                BlockProcessingOutcome::ParentUnknown { parent } => {
                    // The parent has not been processed
                    trace!(
                        self.log, "ParentBlockUnknown";
                        "source" => source,
                        "parent_root" => format!("{}", parent),
                        "baby_block_slot" => block.slot,
                        "peer" => format!("{:?}", peer_id),
                    );

                    // If the parent is in the `import_queue` attempt to complete it then process it.
                    // All other cases leave `parent` in `import_queue` and return original outcome.
                    if let Some(BlockProcessingOutcome::Processed { .. }) =
                        self.attempt_process_partial_block(peer_id, parent, network, source)
                    {
                        // If processing parent is successful, re-process block and remove parent from queue
                        self.import_queue.remove(parent);

                        // Attempt to process `block` again
                        match self.chain.process_block(block) {
                            Ok(outcome) => return Some(outcome),
                            Err(_) => return None,
                        }
                    }
                }
                BlockProcessingOutcome::FutureSlot {
                    present_slot,
                    block_slot,
                } => {
                    if present_slot + FUTURE_SLOT_TOLERANCE >= block_slot {
                        // The block is too far in the future, drop it.
                        warn!(
                            self.log, "FutureBlock";
                            "source" => source,
                            "msg" => "block for future slot rejected, check your time",
                            "present_slot" => present_slot,
                            "block_slot" => block_slot,
                            "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                            "peer" => format!("{:?}", peer_id),
                        );
                        network.disconnect(peer_id, GoodbyeReason::Fault);
                    } else {
                        // The block is in the future, but not too far.
                        debug!(
                            self.log, "QueuedFutureBlock";
                            "source" => source,
                            "msg" => "queuing future block, check your time",
                            "present_slot" => present_slot,
                            "block_slot" => block_slot,
                            "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                            "peer" => format!("{:?}", peer_id),
                        );
                    }
                }
                _ => {
                    debug!(
                        self.log, "InvalidBlock";
                        "source" => source,
                        "msg" => "peer sent invalid block",
                        "outcome" => format!("{:?}", outcome),
                        "peer" => format!("{:?}", peer_id),
                    );
                }
            }

            Some(outcome)
        } else {
            error!(
                self.log, "BlockProcessingFailure";
                "source" => source,
                "msg" => "unexpected condition in processing block.",
                "outcome" => format!("{:?}", processing_result)
            );

            None
        }
    }
}

/// Build a `HelloMessage` representing the state of the given `beacon_chain`.
fn hello_message<T: BeaconChainTypes>(beacon_chain: &BeaconChain<T>) -> HelloMessage {
    let spec = &beacon_chain.spec;
    let state = &beacon_chain.head().beacon_state;

    HelloMessage {
        //TODO: Correctly define the chain/network id
        network_id: spec.chain_id,
        chain_id: u64::from(spec.chain_id),
        latest_finalized_root: state.finalized_checkpoint.root,
        latest_finalized_epoch: state.finalized_checkpoint.epoch,
        best_root: beacon_chain.head().beacon_block_root,
        best_slot: state.slot,
    }
}
