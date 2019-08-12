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

/// The amount of seconds a block may exist in the import queue.
const QUEUE_STALE_SECS: u64 = 100;

/// If a block is more than `FUTURE_SLOT_TOLERANCE` slots ahead of our slot clock, we drop it.
/// Otherwise we queue it.
const FUTURE_SLOT_TOLERANCE: u64 = 1;

const SHOULD_FORWARD_GOSSIP_BLOCK: bool = true;
const SHOULD_NOT_FORWARD_GOSSIP_BLOCK: bool = false;

/// Keeps track of syncing information for known connected peers.
#[derive(Clone, Copy, Debug)]
pub struct PeerSyncInfo {
    fork_version: [u8,4],
    finalized_root: Hash256,
    finalized_epoch: Epoch,
    head_root: Hash256,
    head_slot: Slot,
    requested_slot_skip: Option<(Slot, usize)>,
}

impl From<HelloMessage> for PeerSyncInfo {
    fn from(hello: HelloMessage) -> PeerSyncInfo {
        PeerSyncInfo {
            fork_version: hello.fork_version,
            finalized_root: hello.finalized_root,
            finalized_epoch: hello.finalized_epoch,
            head_root: hello.head_root,
            head_slot: hello.head_slot,
            requested_slot_skip: None,
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
        let remote = PeerSyncInfo::from(hello);
        let local = PeerSyncInfo::from(&self.chain);

        let start_slot = |epoch: Epoch| epoch.start_slot(T::EthSpec::slots_per_epoch());

        if local.fork_version != remote.fork_version {
            // The node is on a different network/fork, disconnect them.
            info!(
                self.log, "HandshakeFailure";
                "peer" => format!("{:?}", peer_id),
                "reason" => "network_id"
            );

            network.disconnect(peer_id.clone(), GoodbyeReason::IrrelevantNetwork);
        } else if remote.finalized_epoch <= local.finalized_epoch
            && remote.finalized_root != Hash256::zero()
            && local.finalized_root != Hash256::zero()
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


            self.process_sync();
        }
    }

    self.proess_sync(&mut self) {
        loop {
            match self.sync_manager.poll() {
                SyncManagerState::RequestBlocks(peer_id, req) {
                    debug!(
                        self.log,
                        "RPCRequest(BeaconBlockBodies)";
                        "count" => req.block_roots.len(),
                        "peer" => format!("{:?}", peer_id)
                    );
                    network.send_rpc_request(peer_id.clone(), RPCRequest::BeaconBlocks(req));
                },
                SyncManagerState::Stalled {
                    // need more peers to continue sync
                    warn!(self.log, "No useable peers for sync");
                    break;
                },
                SyncManagerState::Idle {
                    // nothing to do
                    break;
                }
            }
        }
    }


    fn root_at_slot(&self, target_slot: Slot) -> Option<Hash256> {
        self.chain
            .rev_iter_block_roots(target_slot)
            .take(1)
            .find(|(_root, slot)| *slot == target_slot)
            .map(|(root, _slot)| root)
    }

    /// Handle a `BeaconBlocks` request from the peer.
    pub fn on_beacon_blocks_request(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        req: BeaconBlocksRequest,
        network: &mut NetworkContext,
    ) {
        let state = &self.chain.head().beacon_state;

        debug!(
            self.log,
            "BeaconBlocksRequest";
            "peer" => format!("{:?}", peer_id),
            "count" => req.count,
            "start_slot" => req.start_slot,
        );

        let blocks = Vec<BeaconBlock<T::EthSpec>> = self
            .chain.rev_iter_block_roots().filter(|(_root, slot) req.start_slot <= slot && req.start_slot + req.count >= slot).take_while(|(_root, slot) req.start_slot <= *slot)
            .filter_map(|root, slot| {
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

        roots.reverse();
        roots.dedup_by_key(|brs| brs.block_root);

        if roots.len() as u64 != req.count {
            debug!(
                self.log,
                "BeaconBlocksRequest";
                "peer" => format!("{:?}", peer_id),
                "msg" => "Failed to return all requested hashes",
                "start_slot" => req.start_slot,
                "current_slot" => self.chain.present_slot(),
                "requested" => req.count,
                "returned" => roots.len(),
            );
        }

        network.send_rpc_response(
            peer_id,
            request_id,
            RPCResponse::BeaconBlocks(blocks.as_ssz_bytes()),
        )
    }


    /// Handle a `BeaconBlocks` response from the peer.
    pub fn on_beacon_blocks_response(
        &mut self,
        peer_id: PeerId,
        res: Vec<BeaconBlock<T::EthSpec>>,
        network: &mut NetworkContext,
    ) {
        debug!(
            self.log,
            "BeaconBlocksResponse";
            "peer" => format!("{:?}", peer_id),
            "count" => res.block_bodies.len(),
        );

        if !res.is_empty() {
            self.sync_manager.add_blocks(peer_id, blocks);
        }

        self.process_sync();
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
        network: &mut NetworkContext,
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
        _network: &mut NetworkContext,
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
        network: &mut NetworkContext,
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
        network: &mut NetworkContext,
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
        network_id: spec.network_id,
        //TODO: Correctly define the chain id
        chain_id: spec.network_id as u64,
        latest_finalized_root: state.finalized_checkpoint.root,
        latest_finalized_epoch: state.finalized_checkpoint.epoch,
        best_root: beacon_chain.head().beacon_block_root,
        best_slot: state.slot,
    }
}
