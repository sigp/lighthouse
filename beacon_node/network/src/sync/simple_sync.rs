use super::import_queue::ImportQueue;
use crate::message_handler::NetworkContext;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::{RPCRequest, RPCResponse, RequestId};
use eth2_libp2p::PeerId;
use slog::{debug, error, info, o, warn};
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
const QUEUE_STALE_SECS: u64 = 600;

/// If a block is more than `FUTURE_SLOT_TOLERANCE` slots ahead of our slot clock, we drop it.
/// Otherwise we queue it.
const FUTURE_SLOT_TOLERANCE: u64 = 1;

const SHOULD_FORWARD_GOSSIP_BLOCK: bool = true;
const SHOULD_NOT_FORWARD_GOSSIP_BLOCK: bool = false;

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
        let spec = &self.chain.spec;

        let remote = PeerSyncInfo::from(hello);
        let local = PeerSyncInfo::from(&self.chain);

        // Disconnect nodes who are on a different network.
        if local.network_id != remote.network_id {
            info!(
                self.log, "HandshakeFailure";
                "peer" => format!("{:?}", peer_id),
                "reason" => "network_id"
            );
            network.disconnect(peer_id.clone(), GoodbyeReason::IrreleventNetwork);
        // Disconnect nodes if our finalized epoch is greater than thieirs, and their finalized
        // epoch is not in our chain. Viz., they are on another chain.
        //
        // If the local or remote have a `latest_finalized_root == ZERO_HASH`, skips checks about
        // the finalized_root. The logic is akward and I think we're better without it.
        } else if (local.latest_finalized_epoch >= remote.latest_finalized_epoch)
            && (!self
                .chain
                .rev_iter_block_roots(local.best_slot)
                .any(|(root, _slot)| root == remote.latest_finalized_root))
            && (local.latest_finalized_root != spec.zero_hash)
            && (remote.latest_finalized_root != spec.zero_hash)
        {
            info!(
                self.log, "HandshakeFailure";
                "peer" => format!("{:?}", peer_id),
                "reason" => "wrong_finalized_chain"
            );
            network.disconnect(peer_id.clone(), GoodbyeReason::IrreleventNetwork);
        // Process handshakes from peers that seem to be on our chain.
        } else {
            info!(self.log, "HandshakeSuccess"; "peer" => format!("{:?}", peer_id));
            self.known_peers.insert(peer_id.clone(), remote);

            // If we have equal or better finalized epochs and best slots, we require nothing else from
            // this peer.
            //
            // We make an exception when our best slot is 0. Best slot does not indicate wether or
            // not there is a block at slot zero.
            if (remote.latest_finalized_epoch <= local.latest_finalized_epoch)
                && (remote.best_slot <= local.best_slot)
                && (local.best_slot > 0)
            {
                debug!(self.log, "Peer is naive"; "peer" => format!("{:?}", peer_id));
                return;
            }

            // If the remote has a higher finalized epoch, request all block roots from our finalized
            // epoch through to its best slot.
            if remote.latest_finalized_epoch > local.latest_finalized_epoch {
                debug!(self.log, "Peer has high finalized epoch"; "peer" => format!("{:?}", peer_id));
                let start_slot = local
                    .latest_finalized_epoch
                    .start_slot(T::EthSpec::slots_per_epoch());
                let required_slots = remote.best_slot - start_slot;

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
            } else if remote.best_slot > local.best_slot {
                debug!(self.log, "Peer has higher best slot"; "peer" => format!("{:?}", peer_id));
                let start_slot = local
                    .latest_finalized_epoch
                    .start_slot(T::EthSpec::slots_per_epoch());
                let required_slots = remote.best_slot - start_slot;

                self.request_block_roots(
                    peer_id,
                    BeaconBlockRootsRequest {
                        start_slot,
                        count: required_slots.into(),
                    },
                    network,
                );
            } else {
                debug!(self.log, "Nothing to request from peer"; "peer" => format!("{:?}", peer_id));
            }
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
            "start_slot" => req.start_slot,
        );

        let mut roots: Vec<BlockRootSlot> = self
            .chain
            .rev_iter_block_roots(req.start_slot + req.count)
            .skip(1)
            .take(req.count as usize)
            .map(|(block_root, slot)| BlockRootSlot { slot, block_root })
            .collect();

        if roots.len() as u64 != req.count {
            debug!(
                self.log,
                "BlockRootsRequest";
                "peer" => format!("{:?}", peer_id),
                "msg" => "Failed to return all requested hashes",
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

        let count = req.max_headers;

        // Collect the block roots.
        //
        // Instead of using `chain.rev_iter_blocks` we collect the roots first. This avoids
        // unnecessary block deserialization when `req.skip_slots > 0`.
        let mut roots: Vec<Hash256> = self
            .chain
            .rev_iter_block_roots(req.start_slot + (count - 1))
            .take(count as usize)
            .map(|(root, _slot)| root)
            .collect();

        roots.reverse();
        roots.dedup();

        let headers: Vec<BeaconBlockHeader> = roots
            .into_iter()
            .step_by(req.skip_slots as usize + 1)
            .filter_map(|root| {
                let block = self.chain.store.get::<BeaconBlock>(&root).ok()?;
                Some(block?.block_header())
            })
            .collect();

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
        let block_bodies: Vec<BeaconBlockBody> = req
            .block_roots
            .iter()
            .filter_map(|root| {
                if let Ok(Some(block)) = self.chain.store.get::<BeaconBlock>(root) {
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
    /// Attempts to apply to block to the beacon chain. May queue the block for later processing.
    ///
    /// Returns a `bool` which, if `true`, indicates we should forward the block to our peers.
    pub fn on_block_gossip(
        &mut self,
        peer_id: PeerId,
        block: BeaconBlock,
        network: &mut NetworkContext,
    ) -> bool {
        if let Some(outcome) =
            self.process_block(peer_id.clone(), block.clone(), network, &"gossip")
        {
            match outcome {
                BlockProcessingOutcome::Processed { .. } => SHOULD_FORWARD_GOSSIP_BLOCK,
                BlockProcessingOutcome::ParentUnknown { .. } => {
                    self.import_queue
                        .enqueue_full_blocks(vec![block], peer_id.clone());

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
                // We rely upon the lower layers (libp2p) to stop loops occuring from re-gossiped
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
        msg: Attestation,
        _network: &mut NetworkContext,
    ) {
        match self.chain.process_attestation(msg) {
            Ok(()) => info!(self.log, "ImportedAttestation"; "source" => "gossip"),
            Err(e) => {
                warn!(self.log, "InvalidAttestation"; "source" => "gossip", "error" => format!("{:?}", e))
            }
        }
    }

    /// Iterate through the `import_queue` and process any complete blocks.
    ///
    /// If a block is successfully processed it is removed from the queue, otherwise it remains in
    /// the queue.
    pub fn process_import_queue(&mut self, network: &mut NetworkContext) {
        let mut successful = 0;

        // Loop through all of the complete blocks in the queue.
        for (block_root, block, sender) in self.import_queue.complete_blocks() {
            let processing_result = self.process_block(sender, block.clone(), network, &"gossip");

            let should_dequeue = match processing_result {
                Some(BlockProcessingOutcome::ParentUnknown { .. }) => false,
                Some(BlockProcessingOutcome::FutureSlot {
                    present_slot,
                    block_slot,
                }) if present_slot + FUTURE_SLOT_TOLERANCE >= block_slot => false,
                _ => true,
            };

            if processing_result == Some(BlockProcessingOutcome::Processed { block_root }) {
                successful += 1;
            }

            if should_dequeue {
                self.import_queue.remove(block_root);
            }
        }

        if successful > 0 {
            info!(self.log, "Imported {} blocks", successful)
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

    /// Generates our current state in the form of a HELLO RPC message.
    pub fn generate_hello(&self) -> HelloMessage {
        hello_message(&self.chain)
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
        block: BeaconBlock,
        network: &mut NetworkContext,
        source: &str,
    ) -> Option<BlockProcessingOutcome> {
        let processing_result = self.chain.process_block(block.clone());

        if let Ok(outcome) = processing_result {
            match outcome {
                BlockProcessingOutcome::Processed { block_root } => {
                    info!(
                        self.log, "Imported block from network";
                        "source" => source,
                        "slot" => block.slot,
                        "block_root" => format!("{}", block_root),
                        "peer" => format!("{:?}", peer_id),
                    );
                }
                BlockProcessingOutcome::ParentUnknown { parent } => {
                    // The block was valid and we processed it successfully.
                    debug!(
                        self.log, "ParentBlockUnknown";
                        "source" => source,
                        "parent_root" => format!("{}", parent),
                        "peer" => format!("{:?}", peer_id),
                    );

                    // Send a hello to learn of the clients best slot so we can then sync the require
                    // parent(s).
                    network.send_rpc_request(
                        peer_id.clone(),
                        RPCRequest::Hello(hello_message(&self.chain)),
                    );

                    // Explicitly request the parent block from the peer.
                    //
                    // It is likely that this is duplicate work, given we already send a hello
                    // request. However, I believe there are some edge-cases where the hello
                    // message doesn't suffice, so we perform this request as well.
                    self.request_block_headers(
                        peer_id,
                        BeaconBlockHeadersRequest {
                            start_root: parent,
                            start_slot: block.slot - 1,
                            max_headers: 1,
                            skip_slots: 0,
                        },
                        network,
                    )
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
        network_id: spec.chain_id,
        latest_finalized_root: state.finalized_root,
        latest_finalized_epoch: state.finalized_epoch,
        best_root: beacon_chain.head().beacon_block_root,
        best_slot: state.slot,
    }
}
