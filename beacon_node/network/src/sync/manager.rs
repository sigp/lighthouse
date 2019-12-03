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

use super::message_processor::{
    status_message, NetworkContext, PeerSyncInfo, FUTURE_SLOT_TOLERANCE,
};
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::{RPCRequest, RequestId};
use eth2_libp2p::PeerId;
use fnv::FnvHashMap;
use futures::prelude::*;
use slog::{crit, debug, info, trace, warn, Logger};
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet};
use std::ops::{Add, Sub};
use std::sync::Weak;
use tokio::sync::{mpsc, oneshot};
use types::{BeaconBlock, EthSpec, Hash256, Slot};

/// Blocks are downloaded in batches from peers. This constant specifies how many blocks per batch
/// is requested. There is a timeout for each batch request. If this value is too high, we will
/// downvote peers with poor bandwidth. This can be set arbitrarily high, in which case the
/// responder will fill the response up to the max request size, assuming they have the bandwidth
/// to do so.
//TODO: Make this dynamic based on peer's bandwidth
const BLOCKS_PER_REQUEST: u64 = 50;

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
/// The number of empty batches we tolerate before dropping the peer. This prevents endless
/// requests to peers who never return blocks.
const EMPTY_BATCH_TOLERANCE: usize = 100;

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

#[derive(PartialEq)]
/// The current state of a block or batches lookup.
enum BlockRequestsState {
    /// The object is queued to be downloaded from a peer but has not yet been requested.
    Queued,

    /// The batch or parent has been requested with the `RequestId` and we are awaiting a response.
    Pending(RequestId),

    /// The downloaded blocks are ready to be processed by the beacon chain. For a batch process
    /// this means we have found a common chain.
    ReadyToProcess,

    /// The batch is complete, simply drop without downvoting the peer.
    Complete,

    /// A failure has occurred and we will drop and downvote the peer that caused the request.
    Failed,
}

/// `BlockRequests` keep track of the long-range (batch) sync process per peer.
struct BlockRequests<T: EthSpec> {
    /// The peer's head slot and the target of this batch download.
    target_head_slot: Slot,

    /// The peer's head root, used to specify which chain of blocks we are downloading from.
    target_head_root: Hash256,

    /// The blocks that we have currently downloaded from the peer that are yet to be processed.
    downloaded_blocks: Vec<BeaconBlock<T>>,

    /// The number of blocks successfully processed in this request.
    blocks_processed: usize,

    /// The number of empty batches we have consecutively received. If a peer returns more than
    /// EMPTY_BATCHES_TOLERANCE, they are dropped.
    consecutive_empty_batches: usize,

    /// The current state of this batch request.
    state: BlockRequestsState,

    /// The current `start_slot` of the batched block request.
    current_start_slot: Slot,
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

    /// The current state of the parent lookup.
    state: BlockRequestsState,
}

impl<T: EthSpec> BlockRequests<T> {
    /// Gets the next start slot for a batch and transitions the state to a Queued state.
    fn update_start_slot(&mut self) {
        // the last request may not have returned all the required blocks (hit the rpc size
        // limit). If so, start from the last returned slot
        if !self.downloaded_blocks.is_empty()
            && self.downloaded_blocks[self.downloaded_blocks.len() - 1].slot
                > self.current_start_slot
        {
            self.current_start_slot = self.downloaded_blocks[self.downloaded_blocks.len() - 1].slot
                + Slot::from(BLOCKS_PER_REQUEST);
        } else {
            self.current_start_slot += Slot::from(BLOCKS_PER_REQUEST);
        }
        self.state = BlockRequestsState::Queued;
    }
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
    network: NetworkContext,

    /// A collection of `BlockRequest` per peer that is currently being downloaded. Used in the
    /// long-range (batch) sync process.
    import_queue: HashMap<PeerId, BlockRequests<T::EthSpec>>,

    /// A collection of parent block lookups.
    parent_queue: SmallVec<[ParentRequests<T::EthSpec>; 3]>,

    /// A collection of block hashes being searched for
    single_block_lookups: FnvHashMap<RequestId, Hash256>,

    /// The collection of known, connected, fully-sync'd peers.
    full_peers: HashSet<PeerId>,

    /// The current request id. This is used to keep track of responses to various outbound
    /// requests. This is an internal accounting mechanism, request id's are never sent to any
    /// peers.
    current_req_id: usize,

    /// The logger for the import manager.
    log: Logger,
}

/// Spawns a new `SyncManager` thread which has a weak reference to underlying beacon
/// chain. This allows the chain to be
/// dropped during the syncing process which will gracefully end the `SyncManager`.
pub fn spawn<T: BeaconChainTypes>(
    executor: &tokio::runtime::TaskExecutor,
    beacon_chain: Weak<BeaconChain<T>>,
    network: NetworkContext,
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
        chain: beacon_chain,
        state: ManagerState::Stalled,
        input_channel: sync_recv,
        network,
        import_queue: HashMap::new(),
        parent_queue: SmallVec::new(),
        single_block_lookups: FnvHashMap::default(),
        full_peers: HashSet::new(),
        current_req_id: 0,
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
    /// is sufficiently ahead of our current head, a long-range (batch) sync is started and
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

        // If a peer is within SLOT_IMPORT_TOLERANCE from our head slot, ignore a batch sync,
        // consider it a fully-sync'd peer.
        if remote.head_slot.sub(local.head_slot).as_usize() < SLOT_IMPORT_TOLERANCE {
            trace!(self.log, "Ignoring full sync with peer";
            "peer" => format!("{:?}", peer_id),
            "peer_head_slot" => remote.head_slot,
            "local_head_slot" => local.head_slot,
            );
            // remove the peer from the queue if it exists
            self.import_queue.remove(&peer_id);
            self.add_full_peer(peer_id);
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

        // Check if we are already downloading blocks from this peer, if so update, if not set up
        // a new request structure
        if let Some(block_requests) = self.import_queue.get_mut(&peer_id) {
            // update the target head slot
            if remote.head_slot > block_requests.target_head_slot {
                block_requests.target_head_slot = remote.head_slot;
            }
        } else {
            // not already downloading blocks from this peer
            let block_requests = BlockRequests {
                target_head_slot: remote.head_slot, // this should be larger than the current head. It is checked before add_peer is called
                target_head_root: remote.head_root,
                consecutive_empty_batches: 0,
                downloaded_blocks: Vec::new(),
                blocks_processed: 0,
                state: BlockRequestsState::Queued,
                current_start_slot: local
                    .finalized_epoch
                    .start_slot(T::EthSpec::slots_per_epoch()),
            };
            self.import_queue.insert(peer_id, block_requests);
        }
    }

    /// A `BlocksByRange` request has received a response. This function process the response.
    fn blocks_by_range_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        block: Option<BeaconBlock<T::EthSpec>>,
    ) {
        // find the request associated with this response
        let block_requests = match self
            .import_queue
            .get_mut(&peer_id)
            .filter(|r| r.state == BlockRequestsState::Pending(request_id))
        {
            Some(req) => req,
            _ => {
                // No pending request, invalid request_id or coding error
                warn!(self.log, "BlocksByRange response unknown"; "request_id" => request_id);
                return;
            }
        };

        // add the downloaded block
        if let Some(downloaded_block) = block {
            // add the block to the request
            block_requests.downloaded_blocks.push(downloaded_block);
            return;
        }
        // the batch has finished processing, or terminated early

        // TODO: The following requirement may need to be relaxed as a node could fork and prune
        // their old head, given to us during a STATUS.
        // If we are syncing up to a target head block, at least the target head block should be
        // returned.
        let blocks = &block_requests.downloaded_blocks;
        if blocks.is_empty() {
            debug!(self.log, "BlocksByRange response was empty"; "request_id" => request_id);
            block_requests.consecutive_empty_batches += 1;
            if block_requests.consecutive_empty_batches >= EMPTY_BATCH_TOLERANCE {
                warn!(self.log, "Peer returned too many empty block batches";
                      "peer" => format!("{:?}", peer_id));
                block_requests.state = BlockRequestsState::Failed;
            } else if block_requests.current_start_slot + BLOCKS_PER_REQUEST
                >= block_requests.target_head_slot
            {
                warn!(self.log, "Peer did not return blocks it claimed to possess";
                      "peer" => format!("{:?}", peer_id));
                // This could be due to a re-org causing the peer to prune their head. In this
                // instance, we try to process what is currently downloaded, if there are blocks
                // downloaded.
                block_requests.state = BlockRequestsState::Complete;
            } else {
                // this batch was empty, request the next batch
                block_requests.update_start_slot();
            }
            return;
        }

        block_requests.consecutive_empty_batches = 0;

        // verify the range of received blocks
        // Note that the order of blocks is verified in block processing
        let last_sent_slot = blocks[blocks.len() - 1].slot;
        if block_requests.current_start_slot > blocks[0].slot
            || block_requests.current_start_slot.add(BLOCKS_PER_REQUEST) < last_sent_slot
        {
            warn!(self.log, "BlocksByRange response returned out of range blocks"; 
                          "request_id" => request_id, 
                          "response_initial_slot" => blocks[0].slot, 
                          "requested_initial_slot" => block_requests.current_start_slot);
            downvote_peer(&mut self.network, &self.log, peer_id);
            // consider this sync failed
            block_requests.state = BlockRequestsState::Failed;
            return;
        }

        // Process this batch
        block_requests.state = BlockRequestsState::ReadyToProcess;
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
        let parent_request = match self
            .parent_queue
            .iter_mut()
            .find(|request| request.state == BlockRequestsState::Pending(request_id))
        {
            Some(req) => req,
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
                parent_request.state = BlockRequestsState::ReadyToProcess;
            }
            None => {
                // if an empty response is given, the peer didn't have the requested block, try again
                parent_request.failed_attempts += 1;
                parent_request.state = BlockRequestsState::Queued;
                parent_request.last_submitted_peer = peer_id;
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
            downvote_peer(&mut self.network, &self.log, peer_id);
            return;
        }

        // we have the correct block, try and process it
        if let Some(chain) = self.chain.upgrade() {
            match chain.process_block(block.clone()) {
                Ok(outcome) => {
                    match outcome {
                        BlockProcessingOutcome::Processed { block_root } => {
                            info!(self.log, "Processed block"; "block" => format!("{}", block_root));
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
                            downvote_peer(&mut self.network, &self.log, peer_id);
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
        // if we are not in regular sync mode, ignore this block
        if self.state != ManagerState::Regular {
            return;
        }

        // make sure this block is not already being searched for
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

        let req = ParentRequests {
            downloaded_blocks: vec![block],
            failed_attempts: 0,
            last_submitted_peer: peer_id,
            state: BlockRequestsState::Queued,
        };

        self.parent_queue.push(req);
    }

    /// A request to search for a block hash has been received. This function begins a BlocksByRoot
    /// request to find the requested block.
    fn search_for_block(&mut self, peer_id: PeerId, block_hash: Hash256) {
        let request_id = self.current_req_id;
        self.single_block_lookups.insert(request_id, block_hash);
        self.current_req_id += 1;
        let request = BlocksByRootRequest {
            block_roots: vec![block_hash],
        };
        blocks_by_root_request(&mut self.network, &self.log, peer_id, request_id, request);
    }

    fn inject_error(&mut self, peer_id: PeerId, request_id: RequestId) {
        trace!(self.log, "Sync manager received a failed RPC");
        // remove any single block lookups
        self.single_block_lookups.remove(&request_id);

        // find the request associated with this response
        if let Some(block_requests) = self
            .import_queue
            .get_mut(&peer_id)
            .filter(|r| r.state == BlockRequestsState::Pending(request_id))
        {
            // TODO: Potentially implement a tolerance. For now, we try to process what have been
            // downloaded
            if !block_requests.downloaded_blocks.is_empty() {
                block_requests.current_start_slot = block_requests
                    .downloaded_blocks
                    .last()
                    .expect("is not empty")
                    .slot;
                block_requests.state = BlockRequestsState::ReadyToProcess;
            } else {
                block_requests.state = BlockRequestsState::Failed;
            }
        };

        // increment the failure of a parent lookup if the request matches a parent search
        if let Some(parent_req) = self
            .parent_queue
            .iter_mut()
            .find(|request| request.state == BlockRequestsState::Pending(request_id))
        {
            parent_req.failed_attempts += 1;
            parent_req.state = BlockRequestsState::Queued;
            parent_req.last_submitted_peer = peer_id;
        }
    }

    fn peer_disconnect(&mut self, peer_id: &PeerId) {
        self.import_queue.remove(peer_id);
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

    fn update_state(&mut self) {
        let previous_state = self.state.clone();
        self.state = {
            if !self.import_queue.is_empty() {
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

    fn process_potential_block_requests(&mut self) {
        // check if an outbound request is required

        // Managing a fixed number of outbound requests is maintained at the RPC protocol libp2p
        // layer and not needed here. Therefore we create many outbound requests and let the RPC
        // handle the number of simultaneous requests.
        // Request all queued objects.

        // remove any failed batches
        let debug_log = &self.log;
        let full_peer_ref = &mut self.full_peers;
        self.import_queue.retain(|peer_id, block_request| {
            match block_request.state {
                BlockRequestsState::Failed => {
                    debug!(debug_log, "Block import from peer failed";
                    "peer_id" => format!("{:?}", peer_id),
                    "downloaded_blocks" => block_request.blocks_processed
                    );
                    full_peer_ref.remove(peer_id);
                    false
                }
                BlockRequestsState::Complete => {
                    debug!(debug_log, "Block import from peer completed";
                    "peer_id" => format!("{:?}", peer_id),
                    );
                    false
                }
                _ => true, // keep all other states
            }
        });

        // process queued block requests
        for (peer_id, block_requests) in self.import_queue.iter_mut() {
            if block_requests.state == BlockRequestsState::Queued {
                let request_id = self.current_req_id;
                block_requests.state = BlockRequestsState::Pending(request_id);
                self.current_req_id += 1;

                let request = BlocksByRangeRequest {
                    head_block_root: block_requests.target_head_root,
                    start_slot: block_requests.current_start_slot.as_u64(),
                    count: BLOCKS_PER_REQUEST,
                    step: 0,
                };
                blocks_by_range_request(
                    &mut self.network,
                    &self.log,
                    peer_id.clone(),
                    request_id,
                    request,
                );
            }
        }
    }

    fn process_complete_batches(&mut self) -> bool {
        // This function can queue extra blocks and the main poll loop will need to be re-executed
        // to process these. This flag indicates that the main poll loop has to continue.
        let mut re_run_poll = false;

        // create reference variables to be moved into subsequent closure
        let chain_ref = self.chain.clone();
        let log_ref = &self.log;
        let network_ref = &mut self.network;

        self.import_queue.retain(|peer_id, block_requests| {
            if block_requests.state == BlockRequestsState::ReadyToProcess {
                let downloaded_blocks =
                    std::mem::replace(&mut block_requests.downloaded_blocks, Vec::new());
                let end_slot = downloaded_blocks
                    .last()
                    .expect("Batches to be processed should not be empty")
                    .slot;
                let total_blocks = downloaded_blocks.len();
                let start_slot = downloaded_blocks[0].slot;

                match process_blocks(chain_ref.clone(), downloaded_blocks, log_ref) {
                    Ok(()) => {
                        debug!(log_ref, "Blocks processed successfully";
                        "peer" => format!("{:?}", peer_id),
                        "start_slot" => start_slot,
                        "end_slot" => end_slot,
                        "no_blocks" => total_blocks,
                        );
                        block_requests.blocks_processed += total_blocks;

                        // check if the batch is complete, by verifying if we have reached the
                        // target head
                        if end_slot >= block_requests.target_head_slot {
                            // Completed, re-status the peer to ensure we are up to the latest head
                            status_peer(network_ref, log_ref, chain_ref.clone(), peer_id.clone());
                            // remove the request
                            false
                        } else {
                            // have not reached the end, queue another batch
                            block_requests.update_start_slot();
                            re_run_poll = true;
                            // keep the batch
                            true
                        }
                    }
                    Err(e) => {
                        warn!(log_ref, "Block processing failed";
                            "peer" => format!("{:?}", peer_id),
                            "start_slot" => start_slot,
                            "end_slot" => end_slot,
                            "no_blocks" => total_blocks,
                            "error" => format!("{:?}", e),
                        );
                        downvote_peer(network_ref, log_ref, peer_id.clone());
                        false
                    }
                }
            } else {
                // not ready to process
                true
            }
        });

        re_run_poll
    }

    fn process_parent_requests(&mut self) {
        // check to make sure there are peers to search for the parent from
        if self.full_peers.is_empty() {
            return;
        }

        // remove any failed requests
        let debug_log = &self.log;
        self.parent_queue.retain(|parent_request| {
            if parent_request.state == BlockRequestsState::Failed {
                debug!(debug_log, "Parent import failed";
                "block" => format!("{:?}",parent_request.downloaded_blocks[0].canonical_root()),
                "ancestors_found" => parent_request.downloaded_blocks.len()
                );
                false
            } else {
                true
            }
        });

        // check if parents need to be searched for
        for parent_request in self.parent_queue.iter_mut() {
            if parent_request.failed_attempts >= PARENT_FAIL_TOLERANCE {
                parent_request.state = BlockRequestsState::Failed;
                continue;
            } else if parent_request.state == BlockRequestsState::Queued {
                // check the depth isn't too large
                if parent_request.downloaded_blocks.len() >= PARENT_DEPTH_TOLERANCE {
                    parent_request.state = BlockRequestsState::Failed;
                    continue;
                }

                let request_id = self.current_req_id;
                parent_request.state = BlockRequestsState::Pending(request_id);
                self.current_req_id += 1;
                let last_element_index = parent_request.downloaded_blocks.len() - 1;
                let parent_hash = parent_request.downloaded_blocks[last_element_index].parent_root;
                let request = BlocksByRootRequest {
                    block_roots: vec![parent_hash],
                };

                // select a random fully synced peer to attempt to download the parent block
                let peer_id = self.full_peers.iter().next().expect("List is not empty");

                blocks_by_root_request(
                    &mut self.network,
                    &self.log,
                    peer_id.clone(),
                    request_id,
                    request,
                );
            }
        }
    }

    fn process_complete_parent_requests(&mut self) -> bool {
        // returned value indicating whether the manager can be switched to idle or not
        let mut re_run_poll = false;

        // Find any parent_requests ready to be processed
        for completed_request in self
            .parent_queue
            .iter_mut()
            .filter(|req| req.state == BlockRequestsState::ReadyToProcess)
        {
            // verify the last added block is the parent of the last requested block

            if completed_request.downloaded_blocks.len() < 2 {
                crit!(
                    self.log,
                    "There must be at least two blocks in a parent request lookup at all times"
                );
                panic!("There must be at least two blocks in  parent request lookup at all time");
                // fail loudly
            }
            let previous_index = completed_request.downloaded_blocks.len() - 2;
            let expected_hash = completed_request.downloaded_blocks[previous_index].parent_root;
            // Note: the length must be greater than 2 so this cannot panic.
            let block_hash = completed_request
                .downloaded_blocks
                .last()
                .expect("Complete batch cannot be empty")
                .canonical_root();
            if block_hash != expected_hash {
                // remove the head block
                let _ = completed_request.downloaded_blocks.pop();
                completed_request.state = BlockRequestsState::Queued;
                let peer = completed_request.last_submitted_peer.clone();
                debug!(self.log, "Peer sent invalid parent.";
                "peer_id" => format!("{:?}",peer),
                "received_block" => format!("{}", block_hash),
                "expected_parent" => format!("{}", expected_hash),
                );
                re_run_poll = true;
                downvote_peer(&mut self.network, &self.log, peer);
            }

            // try and process the list of blocks up to the requested block
            while !completed_request.downloaded_blocks.is_empty() {
                let block = completed_request
                    .downloaded_blocks
                    .pop()
                    .expect("Block must exist exist");

                // check if the chain exists
                if let Some(chain) = self.chain.upgrade() {
                    match chain.process_block(block.clone()) {
                        Ok(BlockProcessingOutcome::ParentUnknown { .. }) => {
                            // need to keep looking for parents
                            completed_request.downloaded_blocks.push(block);
                            completed_request.state = BlockRequestsState::Queued;
                            re_run_poll = true;
                            break;
                        }
                        Ok(BlockProcessingOutcome::Processed { .. })
                        | Ok(BlockProcessingOutcome::BlockIsAlreadyKnown { .. }) => {}
                        Ok(outcome) => {
                            // it's a future slot or an invalid block, remove it and try again
                            completed_request.failed_attempts += 1;
                            trace!(
                                self.log, "Invalid parent block";
                                "outcome" => format!("{:?}", outcome),
                                "peer" => format!("{:?}", completed_request.last_submitted_peer),
                            );
                            completed_request.state = BlockRequestsState::Queued;
                            re_run_poll = true;
                            downvote_peer(
                                &mut self.network,
                                &self.log,
                                completed_request.last_submitted_peer.clone(),
                            );
                            return re_run_poll;
                        }
                        Err(e) => {
                            completed_request.failed_attempts += 1;
                            warn!(
                                self.log, "Parent processing error";
                                "error" => format!("{:?}", e)
                            );
                            completed_request.state = BlockRequestsState::Queued;
                            re_run_poll = true;
                            downvote_peer(
                                &mut self.network,
                                &self.log,
                                completed_request.last_submitted_peer.clone(),
                            );
                            return re_run_poll;
                        }
                    }
                } else {
                    // chain doesn't exist - clear the event queue and return
                    return false;
                }
            }
        }

        // remove any fully processed parent chains
        self.parent_queue
            .retain(|req| req.state != BlockRequestsState::ReadyToProcess);
        re_run_poll
    }
}

/* Network Context Helper Functions */

fn status_peer<T: BeaconChainTypes>(
    network: &mut NetworkContext,
    log: &slog::Logger,
    chain: Weak<BeaconChain<T>>,
    peer_id: PeerId,
) {
    trace!(
        log,
        "Sending Status Request";
        "method" => "STATUS",
        "peer" => format!("{:?}", peer_id)
    );
    if let Some(chain) = chain.upgrade() {
        network.send_rpc_request(None, peer_id, RPCRequest::Status(status_message(&chain)));
    }
}

fn blocks_by_range_request(
    network: &mut NetworkContext,
    log: &slog::Logger,
    peer_id: PeerId,
    request_id: RequestId,
    request: BlocksByRangeRequest,
) {
    trace!(
        log,
        "Sending BlocksByRange Request";
        "method" => "BlocksByRange",
        "id" => request_id,
        "count" => request.count,
        "peer" => format!("{:?}", peer_id)
    );
    network.send_rpc_request(
        Some(request_id),
        peer_id.clone(),
        RPCRequest::BlocksByRange(request),
    );
}

fn blocks_by_root_request(
    network: &mut NetworkContext,
    log: &slog::Logger,
    peer_id: PeerId,
    request_id: RequestId,
    request: BlocksByRootRequest,
) {
    trace!(
        log,
        "Sending BlocksByRoot Request";
        "method" => "BlocksByRoot",
        "count" => request.block_roots.len(),
        "peer" => format!("{:?}", peer_id)
    );
    network.send_rpc_request(
        Some(request_id),
        peer_id.clone(),
        RPCRequest::BlocksByRoot(request),
    );
}

fn downvote_peer(network: &mut NetworkContext, log: &slog::Logger, peer_id: PeerId) {
    trace!(
        log,
        "Peer downvoted";
        "peer" => format!("{:?}", peer_id)
    );
    // TODO: Implement reputation
    network.disconnect(peer_id.clone(), GoodbyeReason::Fault);
}

// Helper function to process blocks which only consumes the chain and blocks to process
fn process_blocks<T: BeaconChainTypes>(
    weak_chain: Weak<BeaconChain<T>>,
    blocks: Vec<BeaconBlock<T::EthSpec>>,
    log: &Logger,
) -> Result<(), String> {
    for block in blocks {
        if let Some(chain) = weak_chain.upgrade() {
            let processing_result = chain.process_block(block.clone());

            if let Ok(outcome) = processing_result {
                match outcome {
                    BlockProcessingOutcome::Processed { block_root } => {
                        // The block was valid and we processed it successfully.
                        trace!(
                            log, "Imported block from network";
                            "slot" => block.slot,
                            "block_root" => format!("{}", block_root),
                        );
                    }
                    BlockProcessingOutcome::ParentUnknown { parent } => {
                        // blocks should be sequential and all parents should exist
                        trace!(
                            log, "Parent block is unknown";
                            "parent_root" => format!("{}", parent),
                            "baby_block_slot" => block.slot,
                        );
                        return Err(format!(
                            "Block at slot {} has an unknown parent.",
                            block.slot
                        ));
                    }
                    BlockProcessingOutcome::BlockIsAlreadyKnown => {
                        // this block is already known to us, move to the next
                        debug!(
                            log, "Imported a block that is already known";
                            "block_slot" => block.slot,
                        );
                    }
                    BlockProcessingOutcome::FutureSlot {
                        present_slot,
                        block_slot,
                    } => {
                        if present_slot + FUTURE_SLOT_TOLERANCE >= block_slot {
                            // The block is too far in the future, drop it.
                            trace!(
                                log, "Block is ahead of our slot clock";
                                "msg" => "block for future slot rejected, check your time",
                                "present_slot" => present_slot,
                                "block_slot" => block_slot,
                                "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                            );
                            return Err(format!(
                                "Block at slot {} is too far in the future",
                                block.slot
                            ));
                        } else {
                            // The block is in the future, but not too far.
                            trace!(
                                log, "Block is slightly ahead of our slot clock, ignoring.";
                                "present_slot" => present_slot,
                                "block_slot" => block_slot,
                                "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                            );
                        }
                    }
                    BlockProcessingOutcome::WouldRevertFinalizedSlot { .. } => {
                        trace!(
                            log, "Finalized or earlier block processed";
                            "outcome" => format!("{:?}", outcome),
                        );
                        // block reached our finalized slot or was earlier, move to the next block
                    }
                    BlockProcessingOutcome::GenesisBlock => {
                        trace!(
                            log, "Genesis block was processed";
                            "outcome" => format!("{:?}", outcome),
                        );
                    }
                    _ => {
                        warn!(
                            log, "Invalid block received";
                            "msg" => "peer sent invalid block",
                            "outcome" => format!("{:?}", outcome),
                        );
                        return Err(format!("Invalid block at slot {}", block.slot));
                    }
                }
            } else {
                warn!(
                    log, "BlockProcessingFailure";
                    "msg" => "unexpected condition in processing block.",
                    "outcome" => format!("{:?}", processing_result)
                );
                return Err(format!(
                    "Unexpected block processing error: {:?}",
                    processing_result
                ));
            }
        } else {
            return Ok(()); // terminate early due to dropped beacon chain
        }
    }

    Ok(())
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
                        self.blocks_by_range_response(
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

        loop {
            //TODO: Optimize the lookups. Potentially keep state of whether each of these functions
            //need to be called.
            let mut re_run = false;

            // only process batch requests if there are any
            if !self.import_queue.is_empty() {
                // process potential block requests
                self.process_potential_block_requests();

                // process any complete long-range batches
                re_run = re_run || self.process_complete_batches();
            }

            // only process parent objects if we are in regular sync
            if !self.parent_queue.is_empty() {
                // process any parent block lookup-requests
                self.process_parent_requests();

                // process any complete parent lookups
                re_run = re_run || self.process_complete_parent_requests();
            }

            // Shutdown the thread if the chain has termined
            if self.chain.upgrade().is_none() {
                return Ok(Async::Ready(()));
            }

            if !re_run {
                break;
            }
        }

        // update the state of the manager
        self.update_state();

        Ok(Async::NotReady)
    }
}
