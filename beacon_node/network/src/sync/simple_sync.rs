use super::manager::{ImportManager, ImportManagerOutcome};
use crate::service::{NetworkMessage, OutgoingMessage};
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::{RPCEvent, RPCRequest, RPCResponse, RequestId};
use eth2_libp2p::PeerId;
use slog::{debug, info, o, trace, warn};
use ssz::Encode;
use std::ops::Sub;
use std::sync::Arc;
use store::Store;
use tokio::sync::mpsc;
use types::{Attestation, BeaconBlock, Epoch, EthSpec, Hash256, Slot};

/// If a block is more than `FUTURE_SLOT_TOLERANCE` slots ahead of our slot clock, we drop it.
/// Otherwise we queue it.
pub(crate) const FUTURE_SLOT_TOLERANCE: u64 = 1;

/// The number of slots behind our head that we still treat a peer as a fully synced peer.
const FULL_PEER_TOLERANCE: u64 = 10;
const SHOULD_FORWARD_GOSSIP_BLOCK: bool = true;
const SHOULD_NOT_FORWARD_GOSSIP_BLOCK: bool = false;

/// Keeps track of syncing information for known connected peers.
#[derive(Clone, Copy, Debug)]
pub struct PeerSyncInfo {
    fork_version: [u8; 4],
    pub finalized_root: Hash256,
    pub finalized_epoch: Epoch,
    pub head_root: Hash256,
    pub head_slot: Slot,
}

impl From<HelloMessage> for PeerSyncInfo {
    fn from(hello: HelloMessage) -> PeerSyncInfo {
        PeerSyncInfo {
            fork_version: hello.fork_version,
            finalized_root: hello.finalized_root,
            finalized_epoch: hello.finalized_epoch,
            head_root: hello.head_root,
            head_slot: hello.head_slot,
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
    _Idle,
    _Downloading,
    _Stopped,
}

/// Simple Syncing protocol.
pub struct SimpleSync<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,
    manager: ImportManager<T>,
    network: NetworkContext,
    log: slog::Logger,
}

impl<T: BeaconChainTypes> SimpleSync<T> {
    /// Instantiate a `SimpleSync` instance, with no peers and an empty queue.
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_send: mpsc::UnboundedSender<NetworkMessage>,
        log: &slog::Logger,
    ) -> Self {
        let sync_logger = log.new(o!("Service"=> "Sync"));

        SimpleSync {
            chain: beacon_chain.clone(),
            manager: ImportManager::new(beacon_chain, log),
            network: NetworkContext::new(network_send, log.clone()),
            log: sync_logger,
        }
    }

    /// Handle a peer disconnect.
    ///
    /// Removes the peer from the manager.
    pub fn on_disconnect(&mut self, peer_id: PeerId) {
        self.manager.peer_disconnect(&peer_id);
    }

    /// Handle the connection of a new peer.
    ///
    /// Sends a `Hello` message to the peer.
    pub fn on_connect(&mut self, peer_id: PeerId) {
        self.network
            .send_rpc_request(None, peer_id, RPCRequest::Hello(hello_message(&self.chain)));
    }

    /// Handle a `Hello` request.
    ///
    /// Processes the `HelloMessage` from the remote peer and sends back our `Hello`.
    pub fn on_hello_request(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        hello: HelloMessage,
    ) {
        trace!(self.log, "HelloRequest"; "peer" => format!("{:?}", peer_id));

        // Say hello back.
        self.network.send_rpc_response(
            peer_id.clone(),
            request_id,
            RPCResponse::Hello(hello_message(&self.chain)),
        );

        self.process_hello(peer_id, hello);
    }

    /// Process a `Hello` response from a peer.
    pub fn on_hello_response(&mut self, peer_id: PeerId, hello: HelloMessage) {
        trace!(self.log, "HelloResponse"; "peer" => format!("{:?}", peer_id));

        // Process the hello message, without sending back another hello.
        self.process_hello(peer_id, hello);
    }

    /// Process a `Hello` message, requesting new blocks if appropriate.
    ///
    /// Disconnects the peer if required.
    fn process_hello(&mut self, peer_id: PeerId, hello: HelloMessage) {
        let remote = PeerSyncInfo::from(hello);
        let local = PeerSyncInfo::from(&self.chain);

        let start_slot = |epoch: Epoch| epoch.start_slot(T::EthSpec::slots_per_epoch());

        if local.fork_version != remote.fork_version {
            // The node is on a different network/fork, disconnect them.
            debug!(
                self.log, "HandshakeFailure";
                "peer" => format!("{:?}", peer_id),
                "reason" => "network_id"
            );

            self.network
                .disconnect(peer_id.clone(), GoodbyeReason::IrrelevantNetwork);
        } else if remote.finalized_epoch <= local.finalized_epoch
            && remote.finalized_root != Hash256::zero()
            && local.finalized_root != Hash256::zero()
            && (self.root_at_slot(start_slot(remote.finalized_epoch))
                != Some(remote.finalized_root))
        {
            // The remotes finalized epoch is less than or greater than ours, but the block root is
            // different to the one in our chain.
            //
            // Therefore, the node is on a different chain and we should not communicate with them.
            debug!(
                self.log, "HandshakeFailure";
                "peer" => format!("{:?}", peer_id),
                "reason" => "different finalized chain"
            );
            self.network
                .disconnect(peer_id.clone(), GoodbyeReason::IrrelevantNetwork);
        } else if remote.finalized_epoch < local.finalized_epoch {
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
            .exists::<BeaconBlock<T::EthSpec>>(&remote.head_root)
            .unwrap_or_else(|_| false)
        {
            // If the node's best-block is already known to us and they are close to our current
            // head, treat them as a fully sync'd peer.
            if self.chain.best_slot().sub(remote.head_slot).as_u64() < FULL_PEER_TOLERANCE {
                self.manager.add_full_peer(peer_id);
                self.process_sync();
            } else {
                debug!(
                    self.log,
                    "Out of sync peer connected";
                    "peer" => format!("{:?}", peer_id),
                );
            }
        } else {
            // The remote node has an equal or great finalized epoch and we don't know it's head.
            //
            // Therefore, there are some blocks between the local finalized epoch and the remote
            // head that are worth downloading.
            debug!(
                self.log, "UsefulPeer";
                "peer" => format!("{:?}", peer_id),
                "local_finalized_epoch" => local.finalized_epoch,
                "remote_latest_finalized_epoch" => remote.finalized_epoch,
            );

            self.manager.add_peer(peer_id, remote);
            self.process_sync();
        }
    }

    fn process_sync(&mut self) {
        loop {
            match self.manager.poll() {
                ImportManagerOutcome::Hello(peer_id) => {
                    trace!(
                        self.log,
                        "RPC Request";
                        "method" => "HELLO",
                        "peer" => format!("{:?}", peer_id)
                    );
                    self.network.send_rpc_request(
                        None,
                        peer_id,
                        RPCRequest::Hello(hello_message(&self.chain)),
                    );
                }
                ImportManagerOutcome::RequestBlocks {
                    peer_id,
                    request_id,
                    request,
                } => {
                    trace!(
                        self.log,
                        "RPC Request";
                        "method" => "BeaconBlocks",
                        "id" => request_id,
                        "count" => request.count,
                        "peer" => format!("{:?}", peer_id)
                    );
                    self.network.send_rpc_request(
                        Some(request_id),
                        peer_id.clone(),
                        RPCRequest::BeaconBlocks(request),
                    );
                }
                ImportManagerOutcome::RecentRequest(peer_id, req) => {
                    trace!(
                        self.log,
                        "RPC Request";
                        "method" => "RecentBeaconBlocks",
                        "count" => req.block_roots.len(),
                        "peer" => format!("{:?}", peer_id)
                    );
                    self.network.send_rpc_request(
                        None,
                        peer_id.clone(),
                        RPCRequest::RecentBeaconBlocks(req),
                    );
                }
                ImportManagerOutcome::DownvotePeer(peer_id) => {
                    trace!(
                        self.log,
                        "Peer downvoted";
                        "peer" => format!("{:?}", peer_id)
                    );
                    // TODO: Implement reputation
                    self.network
                        .disconnect(peer_id.clone(), GoodbyeReason::Fault);
                }
                ImportManagerOutcome::Idle => {
                    // nothing to do
                    return;
                }
            }
        }
    }

    //TODO: Move to beacon chain
    fn root_at_slot(&self, target_slot: Slot) -> Option<Hash256> {
        self.chain
            .rev_iter_block_roots()
            .find(|(_root, slot)| *slot == target_slot)
            .map(|(root, _slot)| root)
    }

    /// Handle a `RecentBeaconBlocks` request from the peer.
    pub fn on_recent_beacon_blocks_request(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        request: RecentBeaconBlocksRequest,
    ) {
        let blocks: Vec<BeaconBlock<_>> = request
            .block_roots
            .iter()
            .filter_map(|root| {
                if let Ok(Some(block)) = self.chain.store.get::<BeaconBlock<T::EthSpec>>(root) {
                    Some(block)
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
            "requested" => request.block_roots.len(),
            "returned" => blocks.len(),
        );

        self.network.send_rpc_response(
            peer_id,
            request_id,
            RPCResponse::BeaconBlocks(blocks.as_ssz_bytes()),
        )
    }

    /// Handle a `BeaconBlocks` request from the peer.
    pub fn on_beacon_blocks_request(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        req: BeaconBlocksRequest,
    ) {
        debug!(
            self.log,
            "BeaconBlocksRequest";
            "peer" => format!("{:?}", peer_id),
            "count" => req.count,
            "start_slot" => req.start_slot,
        );

        //TODO: Optimize this
        // Currently for skipped slots, the blocks returned could be less than the requested range.
        // In the current implementation we read from the db then filter out out-of-range blocks.
        // Improving the db schema to prevent this would be ideal.

        let mut blocks: Vec<BeaconBlock<T::EthSpec>> = self
            .chain
            .rev_iter_block_roots()
            .filter(|(_root, slot)| {
                req.start_slot <= slot.as_u64() && req.start_slot + req.count > slot.as_u64()
            })
            .take_while(|(_root, slot)| req.start_slot <= slot.as_u64())
            .filter_map(|(root, _slot)| {
                if let Ok(Some(block)) = self.chain.store.get::<BeaconBlock<T::EthSpec>>(&root) {
                    Some(block)
                } else {
                    warn!(
                        self.log,
                        "Block in the chain is not in the store";
                        "request_root" => format!("{:}", root),
                    );

                    None
                }
            })
            .filter(|block| block.slot >= req.start_slot)
            .collect();

        blocks.reverse();
        blocks.dedup_by_key(|brs| brs.slot);

        if blocks.len() as u64 != req.count {
            debug!(
                self.log,
                "BeaconBlocksRequest response";
                "peer" => format!("{:?}", peer_id),
                "msg" => "Failed to return all requested hashes",
                "start_slot" => req.start_slot,
                "current_slot" => format!("{:?}", self.chain.present_slot()),
                "requested" => req.count,
                "returned" => blocks.len(),
            );
        }

        self.network.send_rpc_response(
            peer_id,
            request_id,
            RPCResponse::BeaconBlocks(blocks.as_ssz_bytes()),
        )
    }

    /// Handle a `BeaconBlocks` response from the peer.
    pub fn on_beacon_blocks_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        beacon_blocks: Vec<BeaconBlock<T::EthSpec>>,
    ) {
        debug!(
            self.log,
            "BeaconBlocksResponse";
            "peer" => format!("{:?}", peer_id),
            "count" => beacon_blocks.len(),
        );

        self.manager
            .beacon_blocks_response(peer_id, request_id, beacon_blocks);

        self.process_sync();
    }

    /// Handle a `RecentBeaconBlocks` response from the peer.
    pub fn on_recent_beacon_blocks_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        beacon_blocks: Vec<BeaconBlock<T::EthSpec>>,
    ) {
        debug!(
            self.log,
            "BeaconBlocksResponse";
            "peer" => format!("{:?}", peer_id),
            "count" => beacon_blocks.len(),
        );

        self.manager
            .recent_blocks_response(peer_id, request_id, beacon_blocks);

        self.process_sync();
    }

    /// Process a gossip message declaring a new block.
    ///
    /// Attempts to apply to block to the beacon chain. May queue the block for later processing.
    ///
    /// Returns a `bool` which, if `true`, indicates we should forward the block to our peers.
    pub fn on_block_gossip(&mut self, peer_id: PeerId, block: BeaconBlock<T::EthSpec>) -> bool {
        if let Ok(outcome) = self.chain.process_block(block.clone()) {
            match outcome {
                BlockProcessingOutcome::Processed { .. } => {
                    trace!(self.log, "Gossipsub block processed";
                            "peer_id" => format!("{:?}",peer_id));
                    SHOULD_FORWARD_GOSSIP_BLOCK
                }
                BlockProcessingOutcome::ParentUnknown { parent: _ } => {
                    // Inform the sync manager to find parents for this block
                    trace!(self.log, "Unknown parent gossip";
                            "peer_id" => format!("{:?}",peer_id));
                    self.manager.add_unknown_block(block.clone(), peer_id);
                    SHOULD_FORWARD_GOSSIP_BLOCK
                }
                BlockProcessingOutcome::FutureSlot {
                    present_slot,
                    block_slot,
                } if present_slot + FUTURE_SLOT_TOLERANCE >= block_slot => {
                    //TODO: Decide the logic here
                    SHOULD_FORWARD_GOSSIP_BLOCK
                }
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
    pub fn on_attestation_gossip(&mut self, _peer_id: PeerId, msg: Attestation<T::EthSpec>) {
        match self.chain.process_attestation(msg) {
            Ok(outcome) => info!(
                self.log,
                "Processed attestation";
                "source" => "gossip",
                "outcome" => format!("{:?}", outcome)
            ),
            Err(e) => {
                warn!(self.log, "InvalidAttestation"; "source" => "gossip", "error" => format!("{:?}", e))
            }
        }
    }

    /// Generates our current state in the form of a HELLO RPC message.
    pub fn generate_hello(&self) -> HelloMessage {
        hello_message(&self.chain)
    }
}

/// Build a `HelloMessage` representing the state of the given `beacon_chain`.
fn hello_message<T: BeaconChainTypes>(beacon_chain: &BeaconChain<T>) -> HelloMessage {
    let state = &beacon_chain.head().beacon_state;

    HelloMessage {
        fork_version: state.fork.current_version,
        finalized_root: state.finalized_checkpoint.root,
        finalized_epoch: state.finalized_checkpoint.epoch,
        head_root: beacon_chain.head().beacon_block_root,
        head_slot: state.slot,
    }
}

/// Wraps a Network Channel to employ various RPC/Sync related network functionality.
pub struct NetworkContext {
    /// The network channel to relay messages to the Network service.
    network_send: mpsc::UnboundedSender<NetworkMessage>,
    /// Logger for the `NetworkContext`.
    log: slog::Logger,
}

impl NetworkContext {
    pub fn new(network_send: mpsc::UnboundedSender<NetworkMessage>, log: slog::Logger) -> Self {
        Self { network_send, log }
    }

    pub fn disconnect(&mut self, peer_id: PeerId, reason: GoodbyeReason) {
        self.send_rpc_request(None, peer_id, RPCRequest::Goodbye(reason))
        // TODO: disconnect peers.
    }

    pub fn send_rpc_request(
        &mut self,
        request_id: Option<RequestId>,
        peer_id: PeerId,
        rpc_request: RPCRequest,
    ) {
        // use 0 as the default request id, when an ID is not required.
        let request_id = request_id.unwrap_or_else(|| 0);
        self.send_rpc_event(peer_id, RPCEvent::Request(request_id, rpc_request));
    }

    //TODO: Handle Error responses
    pub fn send_rpc_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        rpc_response: RPCResponse,
    ) {
        self.send_rpc_event(
            peer_id,
            RPCEvent::Response(request_id, RPCErrorResponse::Success(rpc_response)),
        );
    }

    fn send_rpc_event(&mut self, peer_id: PeerId, rpc_event: RPCEvent) {
        self.send(peer_id, OutgoingMessage::RPC(rpc_event))
    }

    fn send(&mut self, peer_id: PeerId, outgoing_message: OutgoingMessage) {
        self.network_send
            .try_send(NetworkMessage::Send(peer_id, outgoing_message))
            .unwrap_or_else(|_| {
                warn!(
                    self.log,
                    "Could not send RPC message to the network service"
                )
            });
    }
}
