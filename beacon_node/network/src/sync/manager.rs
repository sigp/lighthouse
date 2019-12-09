//! The `SyncManager` facilities the block syncing logic of lighthouse. The current networking
//! specification provides two methods from which to obtain blocks from peers. The `BlocksByRange`
//! request and the `BlocksByRoot` request. The former is used to obtain a large number of
//! blocks and the latter allows for searching for blocks given a block-hash.
//!
//! These two RPC methods are designed for two type of syncing.
//! - Long range (batch) sync, when a client is out of date and needs to the latest head.
//! - Parent lookup - when a peer provides us a block whose parent is unknown to us.
//!
//! Both of these syncing strategies are built into the `SyncManager`.
//!
//! Currently the long-range (batch) syncing method functions by opportunistically downloading
//! batches blocks from all peers who know about a chain that we do not. When a new peer connects
//! which has a later head that is greater than `SLOT_IMPORT_TOLERANCE` from our current head slot,
//! the manager's state becomes `Syncing` and begins a batch syncing process with this peer. If
//! further peers connect, this process is run in parallel with those peers, until our head is
//! within `SLOT_IMPORT_TOLERANCE` of all connected peers.
//!
//! Batch Syncing
//!
//! This syncing process start by requesting `BLOCKS_PER_REQUEST` blocks from a peer with an
//! unknown chain (with a greater slot height) starting from our current head slot. If the earliest
//! block returned is known to us, then the group of blocks returned form part of a known chain,
//! and we process this batch of blocks, before requesting more batches forward and processing
//! those in turn until we reach the peer's chain's head. If the first batch doesn't contain a
//! block we know of, we must iteratively request blocks backwards (until our latest finalized head
//! slot) until we find a common ancestor before we can start processing the blocks. If no common
//! ancestor is found, the peer has a chain which is not part of our finalized head slot and we
//! drop the peer and the downloaded blocks.
//! Once we are fully synced with all known peers, the state of the manager becomes `Regular` which
//! then allows for parent lookups of propagated blocks.
//!
//! A schematic version of this logic with two chain variations looks like the following.
//!
//! |----------------------|---------------------------------|
//! ^finalized head        ^current local head               ^remotes head
//!
//!
//! An example of the remotes chain diverging before our current head.
//! |---------------------------|
//!          ^---------------------------------------------|
//!          ^chain diverges    |initial batch|            ^remotes head
//!
//! In this example, we cannot process the initial batch as it is not on a known chain. We must
//! then backwards sync until we reach a common chain to begin forwarding batch syncing.
//!
//!
//! Parent Lookup
//!
//! When a block with an unknown parent is received and we are in `Regular` sync mode, the block is
//! queued for lookup. A round-robin approach is used to request the parent from the known list of
//! fully sync'd peers. If `PARENT_FAIL_TOLERANCE` attempts at requesting the block fails, we
//! drop the propagated block and downvote the peer that sent it to us.
//!
//! Block Lookup
//!
//! To keep the logic maintained to the syncing thread (and manage the request_ids), when a block needs to be searched for (i.e
//! if an attestation references an unknown block) this manager can search for the block and
//! subsequently search for parents if needed.

use super::message_processor::PeerSyncInfo;
use super::network_context::SyncNetworkContext;
use super::range_sync::RangeSync;
use crate::service::NetworkMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::RequestId;
use eth2_libp2p::PeerId;
use fnv::FnvHashMap;
use futures::prelude::*;
use slog::{crit, debug, error, info, trace, warn, Logger};
use smallvec::SmallVec;
use std::collections::HashSet;
use std::ops::Sub;
use std::sync::Weak;
use tokio::sync::{mpsc, oneshot};
use types::{BeaconBlock, EthSpec, Hash256};

/// The number of slots ahead of us that is allowed before requesting a long-range (batch)  Sync
/// from a peer. If a peer is within this tolerance (forwards or backwards), it is treated as a
/// fully sync'd peer.
const SLOT_IMPORT_TOLERANCE: usize = 20;
/// How many attempts we try to find a parent of a block before we give up trying .
const PARENT_FAIL_TOLERANCE: usize = 3;
/// The maximum depth we will search for a parent block. In principle we should have sync'd any
/// canonical chain to its head once the peer connects. A chain should not appear where it's depth
/// is further back than the most recent head slot.
const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE * 2;

#[derive(Debug)]
/// A message than can be sent to the sync manager thread.
pub enum SyncMessage<T: EthSpec> {
    /// A useful peer has been discovered.
    AddPeer(PeerId, PeerSyncInfo),

    /// A `BlocksByRange` response has been received.
    BlocksByRangeResponse {
        peer_id: PeerId,
        request_id: RequestId,
        beacon_block: Option<Box<BeaconBlock<T>>>,
    },

    /// A `BlocksByRoot` response has been received.
    BlocksByRootResponse {
        peer_id: PeerId,
        request_id: RequestId,
        beacon_block: Option<Box<BeaconBlock<T>>>,
    },

    /// A block with an unknown parent has been received.
    UnknownBlock(PeerId, Box<BeaconBlock<T>>),

    /// A peer has sent an object that references a block that is unknown. This triggers the
    /// manager to attempt to find the block matching the unknown hash.
    UnknownBlockHash(PeerId, Hash256),

    /// A peer has disconnected.
    Disconnect(PeerId),

    /// An RPC Error has occurred on a request.
    RPCError(PeerId, RequestId),
}

/// Maintains a sequential list of parents to lookup and the lookup's current state.
struct ParentRequests<T: EthSpec> {
    /// The blocks that have currently been downloaded.
    downloaded_blocks: Vec<BeaconBlock<T>>,

    /// The number of failed attempts to retrieve a parent block. If too many attempts occur, this
    /// lookup is failed and rejected.
    failed_attempts: usize,

    /// The peer who last submitted a block. If the chain ends or fails, this is the peer that is
    /// downvoted.
    last_submitted_peer: PeerId,

    /// The request ID of this lookup is in progress.
    pending: Option<RequestId>,
}

#[derive(PartialEq, Debug, Clone)]
/// The current state of the `ImportManager`.
enum ManagerState {
    /// The manager is performing a long-range (batch) sync. In this mode, parent lookups are
    /// disabled.
    Syncing,

    /// The manager is up to date with all known peers and is connected to at least one
    /// fully-syncing peer. In this state, parent lookups are enabled.
    Regular,

    /// No useful peers are connected. Long-range sync's cannot proceed and we have no useful
    /// peers to download parents for. More peers need to be connected before we can proceed.
    Stalled,
}

/// The primary object for handling and driving all the current syncing logic. It maintains the
/// current state of the syncing process, the number of useful peers, downloaded blocks and
/// controls the logic behind both the long-range (batch) sync and the on-going potential parent
/// look-up of blocks.
pub struct SyncManager<T: BeaconChainTypes> {
    /// A weak reference to the underlying beacon chain.
    chain: Weak<BeaconChain<T>>,

    /// The current state of the import manager.
    state: ManagerState,

    /// A receiving channel sent by the message processor thread.
    input_channel: mpsc::UnboundedReceiver<SyncMessage<T::EthSpec>>,

    /// A network context to contact the network service.
    network: SyncNetworkContext,

    /// The object handling long-range batch load-balanced syncing.
    range_sync: RangeSync<T>,

    /// A collection of parent block lookups.
    parent_queue: SmallVec<[ParentRequests<T::EthSpec>; 3]>,

    /// A collection of block hashes being searched for
    single_block_lookups: FnvHashMap<RequestId, Hash256>,

    /// The collection of known, connected, fully-sync'd peers.
    full_peers: HashSet<PeerId>,

    /// The logger for the import manager.
    log: Logger,
}

/// Spawns a new `SyncManager` thread which has a weak reference to underlying beacon
/// chain. This allows the chain to be
/// dropped during the syncing process which will gracefully end the `SyncManager`.
pub fn spawn<T: BeaconChainTypes>(
    executor: &tokio::runtime::TaskExecutor,
    beacon_chain: Weak<BeaconChain<T>>,
    network_send: mpsc::UnboundedSender<NetworkMessage>,
    log: slog::Logger,
) -> (
    mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    oneshot::Sender<()>,
) {
    // generate the exit channel
    let (sync_exit, exit_rx) = tokio::sync::oneshot::channel();
    // generate the message channel
    let (sync_send, sync_recv) = mpsc::unbounded_channel::<SyncMessage<T::EthSpec>>();

    // create an instance of the SyncManager
    let sync_manager = SyncManager {
        chain: beacon_chain.clone(),
        state: ManagerState::Stalled,
        input_channel: sync_recv,
        network: SyncNetworkContext::new(network_send, log.clone()),
        range_sync: RangeSync::new(beacon_chain, log.clone()),
        parent_queue: SmallVec::new(),
        single_block_lookups: FnvHashMap::default(),
        full_peers: HashSet::new(),
        log: log.clone(),
    };

    // spawn the sync manager thread
    debug!(log, "Sync Manager started");
    executor.spawn(
        sync_manager
            .select(exit_rx.then(|_| Ok(())))
            .then(move |_| {
                info!(log.clone(), "Sync Manager shutdown");
                Ok(())
            }),
    );
    (sync_send, sync_exit)
}

impl<T: BeaconChainTypes> SyncManager<T> {
    /* Input Handling Functions */

    /// A peer has connected which has blocks that are unknown to us.
    ///
    /// This function handles the logic associated with the connection of a new peer. If the peer
    /// is sufficiently ahead of our current head, a range-sync (batch) sync is started and
    /// batches of blocks are queued to download from the peer. Batched blocks begin at our latest
    /// finalized head.
    ///
    /// If the peer is within the `SLOT_IMPORT_TOLERANCE`, then it's head is sufficiently close to
    /// ours that we consider it fully sync'd with respect to our current chain.
    fn add_peer(&mut self, peer_id: PeerId, remote: PeerSyncInfo) {
        // ensure the beacon chain still exists
        let chain = match self.chain.upgrade() {
            Some(chain) => chain,
            None => {
                warn!(self.log,
                      "Beacon chain dropped. Peer not considered for sync";
                      "peer_id" => format!("{:?}", peer_id));
                return;
            }
        };

        let local = PeerSyncInfo::from(&chain);

        // If a peer is within SLOT_IMPORT_TOLERANCE from our head slot, ignore a batch/range sync,
        // consider it a fully-sync'd peer.
        if remote.head_slot.sub(local.head_slot).as_usize() < SLOT_IMPORT_TOLERANCE {
            trace!(self.log, "Ignoring full sync with peer";
            "peer" => format!("{:?}", peer_id),
            "peer_head_slot" => remote.head_slot,
            "local_head_slot" => local.head_slot,
            );
            self.add_full_peer(peer_id);
            // notify the range sync that a peer has been added
            self.range_sync.fully_synced_peer_found();
            return;
        }

        // Check if the peer is significantly behind us. If within `SLOT_IMPORT_TOLERANCE`
        // treat them as a fully synced peer. If not, ignore them in the sync process
        if local.head_slot.sub(remote.head_slot).as_usize() < SLOT_IMPORT_TOLERANCE {
            self.add_full_peer(peer_id.clone());
        } else {
            debug!(
                self.log,
                "Out of sync peer connected";
                "peer" => format!("{:?}", peer_id),
            );
            return;
        }

        // Add the peer to our RangeSync
        self.range_sync.add_peer(&mut self.network, peer_id, remote);
        self.update_state();
    }

    /// The response to a `BlocksByRoot` request.
    /// The current implementation takes one block at a time. As blocks are streamed, any
    /// subsequent blocks will simply be ignored.
    /// There are two reasons we could have received a BlocksByRoot response
    /// - We requested a single hash and have received a response for the single_block_lookup
    /// - We are looking up parent blocks in parent lookup search
    fn blocks_by_root_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        block: Option<BeaconBlock<T::EthSpec>>,
    ) {
        // check if this is a single block lookup - i.e we were searching for a specific hash
        if block.is_some() {
            if let Some(block_hash) = self.single_block_lookups.remove(&request_id) {
                self.single_block_lookup_response(
                    peer_id,
                    block.expect("block exists"),
                    block_hash,
                );
                return;
            }
        }

        // this should be a response to a parent request search
        // find the request
        let mut parent_request = match self
            .parent_queue
            .iter()
            .position(|request| request.pending == Some(request_id))
        {
            Some(pos) => self.parent_queue.remove(pos),
            None => {
                if block.is_some() {
                    // No pending request, invalid request_id or coding error
                    warn!(self.log, "BlocksByRoot response unknown"; "request_id" => request_id);
                }
                // it could be a stream termination None, in which case we just ignore it
                return;
            }
        };

        match block {
            Some(block) => {
                // add the block to response
                parent_request.downloaded_blocks.push(block);
                // queue for processing
                self.process_parent_request(parent_request);
            }
            None => {
                // if an empty response is given, the peer didn't have the requested block, try again
                parent_request.failed_attempts += 1;
                parent_request.last_submitted_peer = peer_id;
                self.request_parent(parent_request);
            }
        }
    }

    /// Processes the response obtained from a single block lookup search. If the block is
    /// processed or errors, the search ends. If the blocks parent is unknown, a block parent
    /// lookup search is started.
    fn single_block_lookup_response(
        &mut self,
        peer_id: PeerId,
        block: BeaconBlock<T::EthSpec>,
        expected_block_hash: Hash256,
    ) {
        // verify the hash is correct and try and process the block
        if expected_block_hash != block.canonical_root() {
            // the peer that sent this, sent us the wrong block
            self.network.downvote_peer(peer_id);
            return;
        }

        // we have the correct block, try and process it
        if let Some(chain) = self.chain.upgrade() {
            match chain.process_block(block.clone()) {
                Ok(outcome) => {
                    match outcome {
                        BlockProcessingOutcome::Processed { block_root } => {
                            info!(self.log, "Processed block"; "block" => format!("{}", block_root));

                            match chain.fork_choice() {
                                Ok(()) => trace!(
                                    self.log,
                                    "Fork choice success";
                                    "location" => "single block"
                                ),
                                Err(e) => error!(
                                    self.log,
                                    "Fork choice failed";
                                    "error" => format!("{:?}", e),
                                    "location" => "single block"
                                ),
                            }
                        }
                        BlockProcessingOutcome::ParentUnknown { .. } => {
                            // We don't know of the blocks parent, begin a parent lookup search
                            self.add_unknown_block(peer_id, block);
                        }
                        BlockProcessingOutcome::BlockIsAlreadyKnown => {
                            trace!(self.log, "Single block lookup already known");
                        }
                        _ => {
                            warn!(self.log, "Single block lookup failed"; "outcome" => format!("{:?}", outcome));
                            self.network.downvote_peer(peer_id);
                        }
                    }
                }
                Err(e) => {
                    warn!(self.log, "Unexpected block processing error"; "error" => format!("{:?}", e));
                }
            }
        }
    }

    /// A block has been sent to us that has an unknown parent. This begins a parent lookup search
    /// to find the parent or chain of parents that match our current chain.
    fn add_unknown_block(&mut self, peer_id: PeerId, block: BeaconBlock<T::EthSpec>) {
        // If we are not in regular sync mode, ignore this block
        if self.state != ManagerState::Regular {
            return;
        }

        // Make sure this block is not already being searched for
        // TODO: Potentially store a hashset of blocks for O(1) lookups
        for parent_req in self.parent_queue.iter() {
            if parent_req
                .downloaded_blocks
                .iter()
                .any(|d_block| d_block == &block)
            {
                // we are already searching for this block, ignore it
                return;
            }
        }

        let parent_request = ParentRequests {
            downloaded_blocks: vec![block],
            failed_attempts: 0,
            last_submitted_peer: peer_id,
            pending: None,
        };

        self.request_parent(parent_request)
    }

    /// A request to search for a block hash has been received. This function begins a BlocksByRoot
    /// request to find the requested block.
    fn search_for_block(&mut self, peer_id: PeerId, block_hash: Hash256) {
        // If we are not in regular sync mode, ignore this block
        if self.state != ManagerState::Regular {
            return;
        }

        let request = BlocksByRootRequest {
            block_roots: vec![block_hash],
        };

        if let Ok(request_id) = self.network.blocks_by_root_request(peer_id, request) {
            self.single_block_lookups.insert(request_id, block_hash);
        }
    }

    fn inject_error(&mut self, peer_id: PeerId, request_id: RequestId) {
        trace!(self.log, "Sync manager received a failed RPC");
        // remove any single block lookups
        self.single_block_lookups.remove(&request_id);

        // notify the range sync
        self.range_sync
            .inject_error(&mut self.network, peer_id.clone(), request_id);

        // increment the failure of a parent lookup if the request matches a parent search
        if let Some(pos) = self
            .parent_queue
            .iter()
            .position(|request| request.pending == Some(request_id))
        {
            let mut parent_request = self.parent_queue.remove(pos);
            parent_request.failed_attempts += 1;
            parent_request.last_submitted_peer = peer_id;
            self.request_parent(parent_request);
        }
    }

    fn peer_disconnect(&mut self, peer_id: &PeerId) {
        self.range_sync.peer_disconnect(&mut self.network, peer_id);
        self.full_peers.remove(peer_id);
        self.update_state();
    }

    fn add_full_peer(&mut self, peer_id: PeerId) {
        debug!(
            self.log, "Fully synced peer added";
            "peer" => format!("{:?}", peer_id),
        );
        self.full_peers.insert(peer_id);
    }

    /* Processing State Functions */
    // These functions are called in the main poll function to transition the state of the sync
    // manager

    /// Updates the syncing state of the `SyncManager`.
    fn update_state(&mut self) {
        let previous_state = self.state.clone();
        self.state = {
            if self.range_sync.is_syncing() {
                ManagerState::Syncing
            } else if !self.full_peers.is_empty() {
                ManagerState::Regular
            } else {
                ManagerState::Stalled
            }
        };
        if self.state != previous_state {
            info!(self.log, "Syncing state updated";
                "old_state" => format!("{:?}", previous_state),
                "new_state" => format!("{:?}", self.state),
            );
        }
    }

    fn process_parent_request(&mut self, mut parent_request: ParentRequests<T::EthSpec>) {
        // verify the last added block is the parent of the last requested block

        if parent_request.downloaded_blocks.len() < 2 {
            crit!(
                self.log,
                "There must be at least two blocks in a parent request lookup at all times"
            );
            panic!("There must be at least two blocks in  parent request lookup at all time");
            // fail loudly
        }
        let previous_index = parent_request.downloaded_blocks.len() - 2;
        let expected_hash = parent_request.downloaded_blocks[previous_index].parent_root;

        // Note: the length must be greater than 2 so this cannot panic.
        let block_hash = parent_request
            .downloaded_blocks
            .last()
            .expect("Complete batch cannot be empty")
            .canonical_root();
        if block_hash != expected_hash {
            // The sent block is not the correct block, remove the head block and downvote
            // the peer
            let _ = parent_request.downloaded_blocks.pop();
            let peer = parent_request.last_submitted_peer.clone();

            debug!(self.log, "Peer sent invalid parent.";
            "peer_id" => format!("{:?}",peer),
            "received_block" => format!("{}", block_hash),
            "expected_parent" => format!("{}", expected_hash),
            );

            self.request_parent(parent_request);
            self.network.downvote_peer(peer);
        } else {
            let mut successes = 0;

            // try and process the list of blocks up to the requested block
            while let Some(block) = parent_request.downloaded_blocks.pop() {
                // check if the chain exists
                if let Some(chain) = self.chain.upgrade() {
                    match chain.process_block(block.clone()) {
                        Ok(BlockProcessingOutcome::ParentUnknown { .. }) => {
                            // need to keep looking for parents
                            parent_request.downloaded_blocks.push(block);
                            self.request_parent(parent_request);
                            break;
                        }
                        Ok(BlockProcessingOutcome::Processed { .. }) => successes += 1,
                        Ok(BlockProcessingOutcome::BlockIsAlreadyKnown { .. }) => {}
                        Ok(outcome) => {
                            // it's a future slot or an invalid block, remove it and try again
                            parent_request.failed_attempts += 1;
                            debug!(
                                self.log, "Invalid parent block";
                                "outcome" => format!("{:?}", outcome),
                                "peer" => format!("{:?}", parent_request.last_submitted_peer),
                            );
                            self.network
                                .downvote_peer(parent_request.last_submitted_peer.clone());
                            self.request_parent(parent_request);
                            break;
                        }
                        Err(e) => {
                            parent_request.failed_attempts += 1;
                            warn!(
                                self.log, "Parent processing error";
                                "error" => format!("{:?}", e)
                            );
                            self.network
                                .downvote_peer(parent_request.last_submitted_peer.clone());
                            self.request_parent(parent_request);
                            break;
                        }
                    }
                } else {
                    break;
                }
            }

            if successes > 0 {
                if let Some(chain) = self.chain.upgrade() {
                    match chain.fork_choice() {
                        Ok(()) => trace!(
                            self.log,
                            "Fork choice success";
                            "block_imports" => successes,
                            "location" => "parent request"
                        ),
                        Err(e) => error!(
                            self.log,
                            "Fork choice failed";
                            "error" => format!("{:?}", e),
                            "location" => "parent request"
                        ),
                    };
                }
            }
        }
    }

    fn request_parent(&mut self, mut parent_request: ParentRequests<T::EthSpec>) {
        // check to make sure there are peers to search for the parent from
        if self.full_peers.is_empty() {
            return;
        }

        // check to make sure this request hasn't failed
        if parent_request.failed_attempts >= PARENT_FAIL_TOLERANCE
            || parent_request.downloaded_blocks.len() >= PARENT_DEPTH_TOLERANCE
        {
            debug!(self.log, "Parent import failed";
            "block" => format!("{:?}",parent_request.downloaded_blocks[0].canonical_root()),
            "ancestors_found" => parent_request.downloaded_blocks.len()
            );
            return; // drop the request
        }

        let parent_hash = parent_request
            .downloaded_blocks
            .last()
            .expect("The parent queue should never be empty")
            .parent_root;
        let request = BlocksByRootRequest {
            block_roots: vec![parent_hash],
        };
        // select a random fully synced peer to attempt to download the parent block
        let peer_id = self.full_peers.iter().next().expect("List is not empty");

        if let Ok(request_id) = self
            .network
            .blocks_by_root_request(peer_id.clone(), request)
        {
            // if the request was successful add the queue back into self
            parent_request.pending = Some(request_id);
            self.parent_queue.push(parent_request);
        }
    }
}

impl<T: BeaconChainTypes> Future for SyncManager<T> {
    type Item = ();
    type Error = String;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        // process any inbound messages
        loop {
            match self.input_channel.poll() {
                Ok(Async::Ready(Some(message))) => match message {
                    SyncMessage::AddPeer(peer_id, info) => {
                        self.add_peer(peer_id, info);
                    }
                    SyncMessage::BlocksByRangeResponse {
                        peer_id,
                        request_id,
                        beacon_block,
                    } => {
                        self.range_sync.blocks_by_range_response(
                            &mut self.network,
                            peer_id,
                            request_id,
                            beacon_block.map(|b| *b),
                        );
                    }
                    SyncMessage::BlocksByRootResponse {
                        peer_id,
                        request_id,
                        beacon_block,
                    } => {
                        self.blocks_by_root_response(peer_id, request_id, beacon_block.map(|b| *b));
                    }
                    SyncMessage::UnknownBlock(peer_id, block) => {
                        self.add_unknown_block(peer_id, *block);
                    }
                    SyncMessage::UnknownBlockHash(peer_id, block_hash) => {
                        self.search_for_block(peer_id, block_hash);
                    }
                    SyncMessage::Disconnect(peer_id) => {
                        self.peer_disconnect(&peer_id);
                    }
                    SyncMessage::RPCError(peer_id, request_id) => {
                        self.inject_error(peer_id, request_id);
                    }
                },
                Ok(Async::NotReady) => break,
                Ok(Async::Ready(None)) => {
                    return Err("Sync manager channel closed".into());
                }
                Err(e) => {
                    return Err(format!("Sync Manager channel error: {:?}", e));
                }
            }
        }

        // update the state of the manager
        self.update_state();

        Ok(Async::NotReady)
    }
}
