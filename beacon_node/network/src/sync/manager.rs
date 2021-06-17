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
//! ## Batch Syncing
//!
//! See `RangeSync` for further details.
//!
//! ## Parent Lookup
//!
//! When a block with an unknown parent is received and we are in `Regular` sync mode, the block is
//! queued for lookup. A round-robin approach is used to request the parent from the known list of
//! fully sync'd peers. If `PARENT_FAIL_TOLERANCE` attempts at requesting the block fails, we
//! drop the propagated block and downvote the peer that sent it to us.
//!
//! Block Lookup
//!
//! To keep the logic maintained to the syncing thread (and manage the request_ids), when a block
//! needs to be searched for (i.e if an attestation references an unknown block) this manager can
//! search for the block and subsequently search for parents if needed.

use super::network_context::SyncNetworkContext;
use super::peer_sync_info::{remote_sync_type, PeerSyncType};
use super::range_sync::{ChainId, RangeSync, RangeSyncType, EPOCHS_PER_BATCH};
use super::RequestId;
use crate::beacon_processor::{ProcessId, WorkEvent as BeaconWorkEvent};
use crate::service::NetworkMessage;
use crate::status::ToStatusMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockError};
use eth2_libp2p::rpc::{methods::MAX_REQUEST_BLOCKS, BlocksByRootRequest, GoodbyeReason};
use eth2_libp2p::types::{NetworkGlobals, SyncState};
use eth2_libp2p::SyncInfo;
use eth2_libp2p::{PeerAction, PeerId};
use fnv::FnvHashMap;
use lru_cache::LRUCache;
use slog::{crit, debug, error, info, trace, warn, Logger};
use smallvec::SmallVec;
use ssz_types::VariableList;
use std::boxed::Box;
use std::ops::Sub;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{Epoch, EthSpec, Hash256, SignedBeaconBlock, Slot};

/// The number of slots ahead of us that is allowed before requesting a long-range (batch)  Sync
/// from a peer. If a peer is within this tolerance (forwards or backwards), it is treated as a
/// fully sync'd peer.
///
/// This means that we consider ourselves synced (and hence subscribe to all subnets and block
/// gossip if no peers are further than this range ahead of us that we have not already downloaded
/// blocks for.
pub const SLOT_IMPORT_TOLERANCE: usize = 32;
/// How many attempts we try to find a parent of a block before we give up trying .
const PARENT_FAIL_TOLERANCE: usize = 5;
/// The maximum depth we will search for a parent block. In principle we should have sync'd any
/// canonical chain to its head once the peer connects. A chain should not appear where it's depth
/// is further back than the most recent head slot.
const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE * 2;

#[derive(Debug)]
/// A message than can be sent to the sync manager thread.
pub enum SyncMessage<T: EthSpec> {
    /// A useful peer has been discovered.
    AddPeer(PeerId, SyncInfo),

    /// A `BlocksByRange` response has been received.
    BlocksByRangeResponse {
        peer_id: PeerId,
        request_id: RequestId,
        beacon_block: Option<Box<SignedBeaconBlock<T>>>,
    },

    /// A `BlocksByRoot` response has been received.
    BlocksByRootResponse {
        peer_id: PeerId,
        request_id: RequestId,
        beacon_block: Option<Box<SignedBeaconBlock<T>>>,
    },

    /// A block with an unknown parent has been received.
    UnknownBlock(PeerId, Box<SignedBeaconBlock<T>>),

    /// A peer has sent an object that references a block that is unknown. This triggers the
    /// manager to attempt to find the block matching the unknown hash.
    UnknownBlockHash(PeerId, Hash256),

    /// A peer has disconnected.
    Disconnect(PeerId),

    /// An RPC Error has occurred on a request.
    RPCError(PeerId, RequestId),

    /// A batch has been processed by the block processor thread.
    BatchProcessed {
        chain_id: ChainId,
        epoch: Epoch,
        result: BatchProcessResult,
    },

    /// A parent lookup has failed.
    ParentLookupFailed {
        /// The head of the chain of blocks that failed to process.
        chain_head: Hash256,
        /// The peer that instigated the chain lookup.
        peer_id: PeerId,
    },
}

/// The result of processing a multiple blocks (a chain segment).
#[derive(Debug)]
pub enum BatchProcessResult {
    /// The batch was completed successfully. It carries whether the sent batch contained blocks.
    Success(bool),
    /// The batch processing failed. It carries whether the processing imported any block.
    Failed(bool),
}

/// Maintains a sequential list of parents to lookup and the lookup's current state.
struct ParentRequests<T: EthSpec> {
    /// The blocks that have currently been downloaded.
    downloaded_blocks: Vec<SignedBeaconBlock<T>>,

    /// The number of failed attempts to retrieve a parent block. If too many attempts occur, this
    /// lookup is failed and rejected.
    failed_attempts: usize,

    /// The peer who last submitted a block. If the chain ends or fails, this is the peer that is
    /// penalized.
    last_submitted_peer: PeerId,

    /// The request ID of this lookup is in progress.
    pending: Option<RequestId>,
}

/// The primary object for handling and driving all the current syncing logic. It maintains the
/// current state of the syncing process, the number of useful peers, downloaded blocks and
/// controls the logic behind both the long-range (batch) sync and the on-going potential parent
/// look-up of blocks.
pub struct SyncManager<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,

    /// A reference to the network globals and peer-db.
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,

    /// A receiving channel sent by the message processor thread.
    input_channel: mpsc::UnboundedReceiver<SyncMessage<T::EthSpec>>,

    /// A network context to contact the network service.
    network: SyncNetworkContext<T::EthSpec>,

    /// The object handling long-range batch load-balanced syncing.
    range_sync: RangeSync<T>,

    /// A collection of parent block lookups.
    parent_queue: SmallVec<[ParentRequests<T::EthSpec>; 3]>,

    /// A cache of failed chain lookups to prevent duplicate searches.
    failed_chains: LRUCache<Hash256>,

    /// A collection of block hashes being searched for and a flag indicating if a result has been
    /// received or not.
    ///
    /// The flag allows us to determine if the peer returned data or sent us nothing.
    single_block_lookups: FnvHashMap<RequestId, SingleBlockRequest>,

    /// A multi-threaded, non-blocking processor for applying messages to the beacon chain.
    beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T>>,

    /// The logger for the import manager.
    log: Logger,
}

/// Object representing a single block lookup request.
struct SingleBlockRequest {
    /// The hash of the requested block.
    pub hash: Hash256,
    /// Whether a block was received from this request, or the peer returned an empty response.
    pub block_returned: bool,
}

impl SingleBlockRequest {
    pub fn new(hash: Hash256) -> Self {
        Self {
            hash,
            block_returned: false,
        }
    }
}

/// Spawns a new `SyncManager` thread which has a weak reference to underlying beacon
/// chain. This allows the chain to be
/// dropped during the syncing process which will gracefully end the `SyncManager`.
pub fn spawn<T: BeaconChainTypes>(
    executor: task_executor::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T>>,
    log: slog::Logger,
) -> mpsc::UnboundedSender<SyncMessage<T::EthSpec>> {
    assert!(
        MAX_REQUEST_BLOCKS >= T::EthSpec::slots_per_epoch() * EPOCHS_PER_BATCH,
        "Max blocks that can be requested in a single batch greater than max allowed blocks in a single request"
    );
    // generate the message channel
    let (sync_send, sync_recv) = mpsc::unbounded_channel::<SyncMessage<T::EthSpec>>();

    // create an instance of the SyncManager
    let mut sync_manager = SyncManager {
        range_sync: RangeSync::new(
            beacon_chain.clone(),
            beacon_processor_send.clone(),
            log.clone(),
        ),
        network: SyncNetworkContext::new(network_send, network_globals.clone(), log.clone()),
        chain: beacon_chain,
        network_globals,
        input_channel: sync_recv,
        parent_queue: SmallVec::new(),
        failed_chains: LRUCache::new(500),
        single_block_lookups: FnvHashMap::default(),
        beacon_processor_send,
        log: log.clone(),
    };

    // spawn the sync manager thread
    debug!(log, "Sync Manager started");
    executor.spawn(async move { Box::pin(sync_manager.main()).await }, "sync");
    sync_send
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
    fn add_peer(&mut self, peer_id: PeerId, remote: SyncInfo) {
        // ensure the beacon chain still exists
        let local = match self.chain.status_message() {
            Ok(status) => SyncInfo {
                head_slot: status.head_slot,
                head_root: status.head_root,
                finalized_epoch: status.finalized_epoch,
                finalized_root: status.finalized_root,
            },
            Err(e) => {
                return error!(self.log, "Failed to get peer sync info";
                    "msg" => "likely due to head lock contention", "err" => ?e)
            }
        };

        let sync_type = remote_sync_type(&local, &remote, &self.chain);

        // update the state of the peer.
        let should_add = self.update_peer_sync_state(&peer_id, &local, &remote, &sync_type);

        if matches!(sync_type, PeerSyncType::Advanced) && should_add {
            self.range_sync
                .add_peer(&mut self.network, local, peer_id, remote);
        }

        self.update_sync_state();
    }

    /// The response to a `BlocksByRoot` request.
    /// The current implementation takes one block at a time. As blocks are streamed, any
    /// subsequent blocks will simply be ignored.
    /// There are two reasons we could have received a BlocksByRoot response
    /// - We requested a single hash and have received a response for the single_block_lookup
    /// - We are looking up parent blocks in parent lookup search
    async fn blocks_by_root_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        block: Option<SignedBeaconBlock<T::EthSpec>>,
    ) {
        match block {
            Some(block) => {
                // data was returned, not just a stream termination

                // check if this is a single block lookup - i.e we were searching for a specific hash
                let mut single_block_hash = None;
                if let Some(block_request) = self.single_block_lookups.get_mut(&request_id) {
                    // update the state of the lookup indicating a block was received from the peer
                    block_request.block_returned = true;
                    single_block_hash = Some(block_request.hash);
                }
                if let Some(block_hash) = single_block_hash {
                    self.single_block_lookup_response(peer_id, block, block_hash)
                        .await;
                    return;
                }

                // This wasn't a single block lookup request, it must be a response to a parent request search
                // find the request
                let mut parent_request = match self
                    .parent_queue
                    .iter()
                    .position(|request| request.pending == Some(request_id))
                {
                    // we remove from the queue and process it. It will get re-added if required
                    Some(pos) => self.parent_queue.remove(pos),
                    None => {
                        // No pending request, invalid request_id or coding error
                        warn!(self.log, "BlocksByRoot response unknown"; "request_id" => request_id);
                        return;
                    }
                };

                // check if the parent of this block isn't in our failed cache. If it is, this
                // chain should be dropped and the peer downscored.
                if self.failed_chains.contains(&block.message.parent_root) {
                    debug!(self.log, "Parent chain ignored due to past failure"; "block" => ?block.message.parent_root, "slot" => block.message.slot);
                    if !parent_request.downloaded_blocks.is_empty() {
                        // Add the root block to failed chains
                        self.failed_chains
                            .insert(parent_request.downloaded_blocks[0].canonical_root());
                    } else {
                        crit!(self.log, "Parent chain has no blocks");
                    }
                    self.network
                        .report_peer(peer_id, PeerAction::MidToleranceError);
                    return;
                }
                // add the block to response
                parent_request.downloaded_blocks.push(block);
                // queue for processing
                self.process_parent_request(parent_request).await;
            }
            None => {
                // this is a stream termination

                // stream termination for a single block lookup, remove the key
                if let Some(single_block_request) = self.single_block_lookups.remove(&request_id) {
                    // The peer didn't respond with a block that it referenced.
                    // This can be allowed as some clients may implement pruning. We mildly
                    // tolerate this behaviour.
                    if !single_block_request.block_returned {
                        warn!(self.log, "Peer didn't respond with a block it referenced"; "referenced_block_hash" => %single_block_request.hash, "peer_id" =>  %peer_id);
                        self.network
                            .report_peer(peer_id, PeerAction::MidToleranceError);
                    }
                    return;
                }

                // This wasn't a single block lookup request, it must be a response to a parent request search
                // find the request and remove it
                let mut parent_request = match self
                    .parent_queue
                    .iter()
                    .position(|request| request.pending == Some(request_id))
                {
                    Some(pos) => self.parent_queue.remove(pos),
                    None => {
                        // No pending request, the parent request has been processed and this is
                        // the resulting stream termination.
                        return;
                    }
                };
                // An empty response has been returned to a parent request
                // if an empty response is given, the peer didn't have the requested block, try again
                parent_request.failed_attempts += 1;
                parent_request.last_submitted_peer = peer_id;
                self.request_parent(parent_request);
            }
        }
    }

    async fn process_block_async(
        &mut self,
        block: SignedBeaconBlock<T::EthSpec>,
    ) -> Option<Result<Hash256, BlockError<T::EthSpec>>> {
        let (event, rx) = BeaconWorkEvent::rpc_beacon_block(Box::new(block));
        match self.beacon_processor_send.try_send(event) {
            Ok(_) => {}
            Err(e) => {
                error!(
                    self.log,
                    "Failed to send sync block to processor";
                    "error" => ?e
                );
                return None;
            }
        }

        match rx.await {
            Ok(block_result) => Some(block_result),
            Err(_) => {
                warn!(
                    self.log,
                    "Sync block not processed";
                    "msg" => "likely due to system resource exhaustion"
                );
                None
            }
        }
    }

    /// Processes the response obtained from a single block lookup search. If the block is
    /// processed or errors, the search ends. If the blocks parent is unknown, a block parent
    /// lookup search is started.
    async fn single_block_lookup_response(
        &mut self,
        peer_id: PeerId,
        block: SignedBeaconBlock<T::EthSpec>,
        expected_block_hash: Hash256,
    ) {
        // verify the hash is correct and try and process the block
        if expected_block_hash != block.canonical_root() {
            // The peer that sent this, sent us the wrong block.
            // We do not tolerate this behaviour. The peer is instantly disconnected and banned.
            warn!(self.log, "Peer sent incorrect block for single block lookup"; "peer_id" => %peer_id);
            self.network.goodbye_peer(peer_id, GoodbyeReason::Fault);
            return;
        }

        let block_result = match self.process_block_async(block.clone()).await {
            Some(block_result) => block_result,
            None => return,
        };

        // we have the correct block, try and process it
        match block_result {
            Ok(block_root) => {
                info!(self.log, "Processed block"; "block" => %block_root);

                match self.chain.fork_choice() {
                    Ok(()) => trace!(
                        self.log,
                        "Fork choice success";
                        "location" => "single block"
                    ),
                    Err(e) => error!(
                        self.log,
                        "Fork choice failed";
                        "error" => ?e,
                        "location" => "single block"
                    ),
                }
            }
            Err(BlockError::ParentUnknown { .. }) => {
                // We don't know of the blocks parent, begin a parent lookup search
                self.add_unknown_block(peer_id, block);
            }
            Err(BlockError::BlockIsAlreadyKnown) => {
                trace!(self.log, "Single block lookup already known");
            }
            Err(BlockError::BeaconChainError(e)) => {
                warn!(self.log, "Unexpected block processing error"; "error" => ?e);
            }
            outcome => {
                warn!(self.log, "Single block lookup failed"; "outcome" => ?outcome);
                // This could be a range of errors. But we couldn't process the block.
                // For now we consider this a mid tolerance error.
                self.network
                    .report_peer(peer_id, PeerAction::MidToleranceError);
            }
        }
    }

    /// A block has been sent to us that has an unknown parent. This begins a parent lookup search
    /// to find the parent or chain of parents that match our current chain.
    fn add_unknown_block(&mut self, peer_id: PeerId, block: SignedBeaconBlock<T::EthSpec>) {
        // If we are not synced or within SLOT_IMPORT_TOLERANCE of the block, ignore
        if !self.network_globals.sync_state.read().is_synced() {
            let head_slot = self
                .chain
                .head_info()
                .map(|info| info.slot)
                .unwrap_or_else(|_| Slot::from(0u64));
            let unknown_block_slot = block.message.slot;

            // if the block is far in the future, ignore it. If its within the slot tolerance of
            // our current head, regardless of the syncing state, fetch it.
            if (head_slot >= unknown_block_slot
                && head_slot.sub(unknown_block_slot).as_usize() > SLOT_IMPORT_TOLERANCE)
                || (head_slot < unknown_block_slot
                    && unknown_block_slot.sub(head_slot).as_usize() > SLOT_IMPORT_TOLERANCE)
            {
                return;
            }
        }

        let block_root = block.canonical_root();
        // If this block or it's parent is part of a known failed chain, ignore it.
        if self.failed_chains.contains(&block.message.parent_root)
            || self.failed_chains.contains(&block_root)
        {
            debug!(self.log, "Block is from a past failed chain. Dropping"; "block_root" => ?block_root, "block_slot" => block.message.slot);
            return;
        }

        // Make sure this block is not already being searched for
        // NOTE: Potentially store a hashset of blocks for O(1) lookups
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

        debug!(self.log, "Unknown block received. Starting a parent lookup"; "block_slot" => block.message.slot, "block_hash" => %block.canonical_root());

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
        // If we are not synced, ignore this block
        if !self.network_globals.sync_state.read().is_synced() {
            return;
        }

        // Do not re-request a block that is already being requested
        if self
            .single_block_lookups
            .values()
            .any(|single_block_request| single_block_request.hash == block_hash)
        {
            return;
        }

        debug!(
            self.log,
            "Searching for block";
            "peer_id" => %peer_id,
            "block" => %block_hash
        );

        let request = BlocksByRootRequest {
            block_roots: VariableList::from(vec![block_hash]),
        };

        if let Ok(request_id) = self.network.blocks_by_root_request(peer_id, request) {
            self.single_block_lookups
                .insert(request_id, SingleBlockRequest::new(block_hash));
        }
    }

    fn inject_error(&mut self, peer_id: PeerId, request_id: RequestId) {
        trace!(self.log, "Sync manager received a failed RPC");
        // remove any single block lookups
        if self.single_block_lookups.remove(&request_id).is_some() {
            // this was a single block request lookup, look no further
            return;
        }

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
            return;
        }

        // otherwise, this is a range sync issue, notify the range sync
        self.range_sync
            .inject_error(&mut self.network, peer_id, request_id);
        self.update_sync_state();
    }

    fn peer_disconnect(&mut self, peer_id: &PeerId) {
        self.range_sync.peer_disconnect(&mut self.network, peer_id);
        self.update_sync_state();
    }

    /// Updates the syncing state of a peer.
    /// Return whether the peer should be used for range syncing or not, according to its
    /// connection status.
    fn update_peer_sync_state(
        &mut self,
        peer_id: &PeerId,
        local_sync_info: &SyncInfo,
        remote_sync_info: &SyncInfo,
        sync_type: &PeerSyncType,
    ) -> bool {
        // NOTE: here we are gracefully handling two race conditions: Receiving the status message
        // of a peer that is 1) disconnected 2) not in the PeerDB.

        if let Some(peer_info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            let new_state = sync_type.as_sync_status(remote_sync_info);
            let rpr = new_state.as_str();
            let was_updated = peer_info.sync_status.update(new_state);
            if was_updated {
                debug!(self.log, "Peer transitioned sync state"; "peer_id" => %peer_id, "new_state" => rpr,
                    "our_head_slot" => local_sync_info.head_slot, "out_finalized_epoch" => local_sync_info.finalized_epoch,
                    "their_head_slot" => remote_sync_info.head_slot, "their_finalized_epoch" => remote_sync_info.finalized_epoch,
                    "is_connected" => peer_info.is_connected());
            }
            peer_info.is_connected()
        } else {
            crit!(self.log, "Status'd peer is unknown"; "peer_id" => %peer_id);
            false
        }
    }

    /// Updates the global sync state and logs any changes.
    fn update_sync_state(&mut self) {
        let new_state: SyncState = match self.range_sync.state() {
            Err(e) => {
                crit!(self.log, "Error getting range sync state"; "error" => %e);
                return;
            }
            Ok(state) => match state {
                None => {
                    // no range sync, decide if we are stalled or synced.
                    // For this we check if there is at least one advanced peer. An advanced peer
                    // with Idle range is possible since a peer's status is updated periodically.
                    // If we synced a peer between status messages, most likely the peer has
                    // advanced and will produce a head chain on re-status. Otherwise it will shift
                    // to being synced
                    let head = self.chain.best_slot().unwrap_or_else(|_| Slot::new(0));
                    let current_slot = self.chain.slot().unwrap_or_else(|_| Slot::new(0));

                    let peers = self.network_globals.peers.read();
                    if current_slot >= head
                        && current_slot.sub(head) <= (SLOT_IMPORT_TOLERANCE as u64)
                        && head > 0
                    {
                        SyncState::Synced
                    } else if peers.advanced_peers().next().is_some() {
                        SyncState::SyncTransition
                    } else if peers.synced_peers().next().is_none() {
                        SyncState::Stalled
                    } else {
                        // There are no peers that require syncing and we have at least one synced
                        // peer
                        SyncState::Synced
                    }
                }
                Some((RangeSyncType::Finalized, start_slot, target_slot)) => {
                    SyncState::SyncingFinalized {
                        start_slot,
                        target_slot,
                    }
                }
                Some((RangeSyncType::Head, start_slot, target_slot)) => SyncState::SyncingHead {
                    start_slot,
                    target_slot,
                },
            },
        };

        let old_state = self.network_globals.set_sync_state(new_state);
        let new_state = self.network_globals.sync_state.read();
        if !new_state.eq(&old_state) {
            info!(self.log, "Sync state updated"; "old_state" => %old_state, "new_state" => %new_state);
            // If we have become synced - Subscribe to all the core subnet topics
            if new_state.is_synced() {
                self.network.subscribe_core_topics();
            }
        }
    }

    /* Processing State Functions */
    // These functions are called in the main poll function to transition the state of the sync
    // manager

    /// A new block has been received for a parent lookup query, process it.
    async fn process_parent_request(&mut self, mut parent_request: ParentRequests<T::EthSpec>) {
        // verify the last added block is the parent of the last requested block

        if parent_request.downloaded_blocks.len() < 2 {
            crit!(
                self.log,
                "There must be at least two blocks in a parent request lookup at all times"
            );
            panic!("There must be at least two blocks in parent request lookup at all times");
            // fail loudly
        }
        let previous_index = parent_request.downloaded_blocks.len() - 2;
        let expected_hash = parent_request.downloaded_blocks[previous_index].parent_root();

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
            let peer = parent_request.last_submitted_peer;

            warn!(self.log, "Peer sent invalid parent.";
                "peer_id" => %peer,
                "received_block" => %block_hash,
                "expected_parent" => %expected_hash,
            );

            // We try again, but downvote the peer.
            self.request_parent(parent_request);
            // We do not tolerate these kinds of errors. We will accept a few but these are signs
            // of a faulty peer.
            self.network
                .report_peer(peer, PeerAction::LowToleranceError);
        } else {
            // The last block in the queue is the only one that has not attempted to be processed yet.
            //
            // The logic here attempts to process the last block. If it can be processed, the rest
            // of the blocks must have known parents. If any of them cannot be processed, we
            // consider the entire chain corrupt and drop it, notifying the user.
            //
            // If the last block in the queue cannot be processed, we also drop the entire queue.
            // If the last block in the queue has an unknown parent, we continue the parent
            // lookup-search.

            let chain_block_hash = parent_request.downloaded_blocks[0].canonical_root();

            let newest_block = parent_request
                .downloaded_blocks
                .pop()
                .expect("There is always at least one block in the queue");

            let block_result = match self.process_block_async(newest_block.clone()).await {
                Some(block_result) => block_result,
                None => return,
            };

            match block_result {
                Err(BlockError::ParentUnknown { .. }) => {
                    // need to keep looking for parents
                    // add the block back to the queue and continue the search
                    parent_request.downloaded_blocks.push(newest_block);
                    self.request_parent(parent_request);
                }
                Ok(_) | Err(BlockError::BlockIsAlreadyKnown { .. }) => {
                    let process_id = ProcessId::ParentLookup(
                        parent_request.last_submitted_peer,
                        chain_block_hash,
                    );
                    let blocks = parent_request.downloaded_blocks;

                    match self
                        .beacon_processor_send
                        .try_send(BeaconWorkEvent::chain_segment(process_id, blocks))
                    {
                        Ok(_) => {}
                        Err(e) => {
                            error!(
                                self.log,
                                "Failed to send chain segment to processor";
                                "error" => ?e
                            );
                        }
                    }
                }
                Err(outcome) => {
                    // all else we consider the chain a failure and downvote the peer that sent
                    // us the last block
                    warn!(
                        self.log, "Invalid parent chain";
                        "score_adjustment" => %PeerAction::MidToleranceError,
                        "outcome" => ?outcome,
                        "last_peer" => %parent_request.last_submitted_peer,
                    );

                    // Add this chain to cache of failed chains
                    self.failed_chains.insert(chain_block_hash);

                    // This currently can be a host of errors. We permit this due to the partial
                    // ambiguity.
                    self.network.report_peer(
                        parent_request.last_submitted_peer,
                        PeerAction::MidToleranceError,
                    );
                }
            }
        }
    }

    /// Progresses a parent request query.
    ///
    /// This checks to ensure there a peers to progress the query, checks for failures and
    /// initiates requests.
    fn request_parent(&mut self, mut parent_request: ParentRequests<T::EthSpec>) {
        // check to make sure this request hasn't failed
        if parent_request.failed_attempts >= PARENT_FAIL_TOLERANCE
            || parent_request.downloaded_blocks.len() >= PARENT_DEPTH_TOLERANCE
        {
            let error = if parent_request.failed_attempts >= PARENT_FAIL_TOLERANCE {
                // This is a peer-specific error and the chain could be continued with another
                // peer. We don't consider this chain a failure and prevent retries with another
                // peer.
                "too many failed attempts"
            } else {
                if !parent_request.downloaded_blocks.is_empty() {
                    self.failed_chains
                        .insert(parent_request.downloaded_blocks[0].canonical_root());
                } else {
                    crit!(self.log, "Parent lookup has no blocks");
                }
                "reached maximum lookup-depth"
            };

            debug!(self.log, "Parent import failed";
            "block" => ?parent_request.downloaded_blocks[0].canonical_root(),
            "ancestors_found" => parent_request.downloaded_blocks.len(),
            "reason" => error
            );
            // Downscore the peer.
            self.network.report_peer(
                parent_request.last_submitted_peer,
                PeerAction::LowToleranceError,
            );
            return; // drop the request
        }

        let parent_hash = if let Some(block) = parent_request.downloaded_blocks.last() {
            block.parent_root()
        } else {
            crit!(self.log, "Parent queue is empty. This should never happen");
            return;
        };

        let request = BlocksByRootRequest {
            block_roots: VariableList::from(vec![parent_hash]),
        };

        // We continue to search for the chain of blocks from the same peer. Other peers are not
        // guaranteed to have this chain of blocks.
        let peer_id = parent_request.last_submitted_peer;

        if let Ok(request_id) = self.network.blocks_by_root_request(peer_id, request) {
            // if the request was successful add the queue back into self
            parent_request.pending = Some(request_id);
            self.parent_queue.push(parent_request);
        }
    }

    /// The main driving future for the sync manager.
    async fn main(&mut self) {
        // process any inbound messages
        loop {
            if let Some(sync_message) = self.input_channel.recv().await {
                match sync_message {
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
                        self.update_sync_state();
                    }
                    SyncMessage::BlocksByRootResponse {
                        peer_id,
                        request_id,
                        beacon_block,
                    } => {
                        self.blocks_by_root_response(peer_id, request_id, beacon_block.map(|b| *b))
                            .await;
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
                    SyncMessage::BatchProcessed {
                        chain_id,
                        epoch,
                        result,
                    } => {
                        self.range_sync.handle_block_process_result(
                            &mut self.network,
                            chain_id,
                            epoch,
                            result,
                        );
                        self.update_sync_state();
                    }
                    SyncMessage::ParentLookupFailed {
                        chain_head,
                        peer_id,
                    } => {
                        // A peer sent an object (block or attestation) that referenced a parent.
                        // The processing of this chain failed.
                        self.failed_chains.insert(chain_head);
                        self.network
                            .report_peer(peer_id, PeerAction::MidToleranceError);
                    }
                }
            }
        }
    }
}
