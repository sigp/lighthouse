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
//! To keep the logic maintained to the syncing thread (and manage the request_ids), when a block needs to be searched for (i.e
//! if an attestation references an unknown block) this manager can search for the block and
//! subsequently search for parents if needed.

use super::block_processor::{spawn_block_processor, BatchProcessResult, ProcessId};
use super::network_context::SyncNetworkContext;
use super::range_sync::{BatchId, RangeSync};
use crate::router::processor::PeerSyncInfo;
use crate::service::NetworkMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::rpc::{methods::*, RequestId};
use eth2_libp2p::types::NetworkGlobals;
use eth2_libp2p::{PeerId, PeerSyncStatus};
use fnv::FnvHashMap;
use futures::prelude::*;
use rand::seq::SliceRandom;
use slog::{crit, debug, error, info, trace, warn, Logger};
use smallvec::SmallVec;
use std::boxed::Box;
use std::ops::Sub;
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use types::{EthSpec, Hash256, SignedBeaconBlock, Slot};

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
        batch_id: BatchId,
        downloaded_blocks: Vec<SignedBeaconBlock<T>>,
        result: BatchProcessResult,
    },

    /// A parent lookup has failed for a block given by this `peer_id`.
    ParentLookupFailed(PeerId),
}

/// Maintains a sequential list of parents to lookup and the lookup's current state.
struct ParentRequests<T: EthSpec> {
    /// The blocks that have currently been downloaded.
    downloaded_blocks: Vec<SignedBeaconBlock<T>>,

    /// The number of failed attempts to retrieve a parent block. If too many attempts occur, this
    /// lookup is failed and rejected.
    failed_attempts: usize,

    /// The peer who last submitted a block. If the chain ends or fails, this is the peer that is
    /// downvoted.
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

    /// A collection of block hashes being searched for and a flag indicating if a result has been
    /// received or not.
    ///
    /// The flag allows us to determine if the peer returned data or sent us nothing.
    single_block_lookups: FnvHashMap<RequestId, (Hash256, bool)>,

    /// The logger for the import manager.
    log: Logger,

    /// The sending part of input_channel
    sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
}

/// Spawns a new `SyncManager` thread which has a weak reference to underlying beacon
/// chain. This allows the chain to be
/// dropped during the syncing process which will gracefully end the `SyncManager`.
pub fn spawn<T: BeaconChainTypes>(
    executor: &tokio::runtime::TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    network_send: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
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
        range_sync: RangeSync::new(
            beacon_chain.clone(),
            network_globals.clone(),
            sync_send.clone(),
            log.clone(),
        ),
        network: SyncNetworkContext::new(network_send, log.clone()),
        chain: beacon_chain,
        network_globals,
        input_channel: sync_recv,
        parent_queue: SmallVec::new(),
        single_block_lookups: FnvHashMap::default(),
        log: log.clone(),
        sync_send: sync_send.clone(),
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
        let local = match PeerSyncInfo::from_chain(&self.chain) {
            Some(local) => local,
            None => {
                return error!(
                    self.log,
                    "Failed to get peer sync info";
                    "msg" => "likely due to head lock contention"
                )
            }
        };

        // If a peer is within SLOT_IMPORT_TOLERANCE from our head slot, ignore a batch/range sync,
        // consider it a fully-sync'd peer.
        if remote.head_slot.sub(local.head_slot).as_usize() < SLOT_IMPORT_TOLERANCE {
            trace!(self.log, "Peer synced to our head found";
            "peer" => format!("{:?}", peer_id),
            "peer_head_slot" => remote.head_slot,
            "local_head_slot" => local.head_slot,
            );
            self.synced_peer(&peer_id, remote.head_slot);
            // notify the range sync that a peer has been added
            self.range_sync.fully_synced_peer_found();
            return;
        }

        // Check if the peer is significantly behind us. If within `SLOT_IMPORT_TOLERANCE`
        // treat them as a fully synced peer. If not, ignore them in the sync process
        if local.head_slot.sub(remote.head_slot).as_usize() < SLOT_IMPORT_TOLERANCE {
            // Add the peer to our RangeSync
            self.range_sync
                .add_peer(&mut self.network, peer_id.clone(), remote);
            self.synced_peer(&peer_id, remote.head_slot);
        } else {
            self.behind_peer(&peer_id, remote.head_slot);
        }
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
        block: Option<SignedBeaconBlock<T::EthSpec>>,
    ) {
        match block {
            Some(block) => {
                // data was returned, not just a stream termination

                // check if this is a single block lookup - i.e we were searching for a specific hash
                let mut single_block_hash = None;
                if let Some((block_hash, data_received)) =
                    self.single_block_lookups.get_mut(&request_id)
                {
                    // update the state of the lookup indicating a block was received from the peer
                    *data_received = true;
                    single_block_hash = Some(block_hash.clone());
                }
                if let Some(block_hash) = single_block_hash {
                    self.single_block_lookup_response(peer_id, block, block_hash);
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
                // add the block to response
                parent_request.downloaded_blocks.push(block);
                // queue for processing
                self.process_parent_request(parent_request);
            }
            None => {
                // this is a stream termination

                // stream termination for a single block lookup, remove the key
                if let Some((block_hash, data_received)) =
                    self.single_block_lookups.remove(&request_id)
                {
                    // the peer didn't respond with a block that it referenced
                    if !data_received {
                        warn!(self.log, "Peer didn't respond with a block it referenced"; "referenced_block_hash" => format!("{}", block_hash), "peer_id" =>  format!("{}", peer_id));
                        self.network.downvote_peer(peer_id);
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

    /// Processes the response obtained from a single block lookup search. If the block is
    /// processed or errors, the search ends. If the blocks parent is unknown, a block parent
    /// lookup search is started.
    fn single_block_lookup_response(
        &mut self,
        peer_id: PeerId,
        block: SignedBeaconBlock<T::EthSpec>,
        expected_block_hash: Hash256,
    ) {
        // verify the hash is correct and try and process the block
        if expected_block_hash != block.canonical_root() {
            // the peer that sent this, sent us the wrong block
            warn!(self.log, "Peer sent incorrect block for single block lookup"; "peer_id" => format!("{}", peer_id));
            self.network.downvote_peer(peer_id);
            return;
        }

        // we have the correct block, try and process it
        match BlockProcessingOutcome::shim(self.chain.process_block(block.clone())) {
            Ok(outcome) => {
                match outcome {
                    BlockProcessingOutcome::Processed { block_root } => {
                        info!(self.log, "Processed block"; "block" => format!("{}", block_root));

                        match self.chain.fork_choice() {
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

    /// A block has been sent to us that has an unknown parent. This begins a parent lookup search
    /// to find the parent or chain of parents that match our current chain.
    fn add_unknown_block(&mut self, peer_id: PeerId, block: SignedBeaconBlock<T::EthSpec>) {
        // If we are not synced ignore the block
        if !self.network_globals.sync_state.read().is_synced() {
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

        let request = BlocksByRootRequest {
            block_roots: vec![block_hash],
        };

        if let Ok(request_id) = self.network.blocks_by_root_request(peer_id, request) {
            self.single_block_lookups
                .insert(request_id, (block_hash, false));
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
            .inject_error(&mut self.network, peer_id.clone(), request_id);
    }

    fn peer_disconnect(&mut self, peer_id: &PeerId) {
        self.range_sync.peer_disconnect(&mut self.network, peer_id);
        self.update_sync_state();
    }

    /// Updates the syncing state of a peer to be synced.
    fn synced_peer(&mut self, peer_id: &PeerId, status_head_slot: Slot) {
        if let Some(peer_info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            match peer_info.sync_status {
                PeerSyncStatus::Synced { .. } => {
                    peer_info.sync_status = PeerSyncStatus::Synced { status_head_slot }
                } // just update block
                PeerSyncStatus::Behind { .. } | PeerSyncStatus::Unknown => {
                    peer_info.sync_status = PeerSyncStatus::Synced { status_head_slot };
                    debug!(self.log, "Peer transitioned to synced status"; "peer_id" => format!("{}", peer_id));
                }
            }
        } else {
            crit!(self.log, "Status'd peer is unknown"; "peer_id" => format!("{}", peer_id));
        }
        self.update_sync_state();
    }

    /// Updates the syncing state of a peer to be behind.
    fn behind_peer(&mut self, peer_id: &PeerId, status_head_slot: Slot) {
        if let Some(peer_info) = self.network_globals.peers.write().peer_info_mut(peer_id) {
            match peer_info.sync_status {
                PeerSyncStatus::Synced { .. } => {
                    debug!(self.log, "Peer transitioned to from synced state to behind"; "peer_id" => format!("{}", peer_id), "head_slot" => status_head_slot);
                    peer_info.sync_status = PeerSyncStatus::Behind { status_head_slot }
                }
                PeerSyncStatus::Behind { .. } => {
                    peer_info.sync_status = PeerSyncStatus::Behind { status_head_slot }
                } // just update

                PeerSyncStatus::Unknown => {
                    debug!(self.log, "Peer transitioned to behind sync status"; "peer_id" => format!("{}", peer_id), "head_slot" => status_head_slot);
                    peer_info.sync_status = PeerSyncStatus::Behind { status_head_slot }
                }
            }
        } else {
            crit!(self.log, "Status'd peer is unknown"; "peer_id" => format!("{}", peer_id));
        }
        self.update_sync_state();
    }

    /// Updates the global sync state and logs any changes.
    fn update_sync_state(&mut self) {
        if let Some((old_state, new_state)) = self.network_globals.update_sync_state() {
            info!(self.log, "Sync state updated"; "old_state" => format!("{}", old_state), "new_state" => format!("{}",new_state));
        }
    }
    /* Processing State Functions */
    // These functions are called in the main poll function to transition the state of the sync
    // manager

    /// A new block has been received for a parent lookup query, process it.
    fn process_parent_request(&mut self, mut parent_request: ParentRequests<T::EthSpec>) {
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
            let peer = parent_request.last_submitted_peer.clone();

            warn!(self.log, "Peer sent invalid parent.";
                "peer_id" => format!("{:?}",peer),
                "received_block" => format!("{}", block_hash),
                "expected_parent" => format!("{}", expected_hash),
            );

            self.request_parent(parent_request);
            self.network.downvote_peer(peer);
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

            let newest_block = parent_request
                .downloaded_blocks
                .pop()
                .expect("There is always at least one block in the queue");
            match BlockProcessingOutcome::shim(self.chain.process_block(newest_block.clone())) {
                Ok(BlockProcessingOutcome::ParentUnknown { .. }) => {
                    // need to keep looking for parents
                    // add the block back to the queue and continue the search
                    parent_request.downloaded_blocks.push(newest_block);
                    self.request_parent(parent_request);
                    return;
                }
                Ok(BlockProcessingOutcome::Processed { .. })
                | Ok(BlockProcessingOutcome::BlockIsAlreadyKnown { .. }) => {
                    spawn_block_processor(
                        Arc::downgrade(&self.chain),
                        ProcessId::ParentLookup(parent_request.last_submitted_peer.clone()),
                        parent_request.downloaded_blocks,
                        self.sync_send.clone(),
                        self.log.clone(),
                    );
                }
                Ok(outcome) => {
                    // all else we consider the chain a failure and downvote the peer that sent
                    // us the last block
                    warn!(
                        self.log, "Invalid parent chain. Downvoting peer";
                        "outcome" => format!("{:?}", outcome),
                        "last_peer" => format!("{:?}", parent_request.last_submitted_peer),
                    );
                    self.network
                        .downvote_peer(parent_request.last_submitted_peer.clone());
                    return;
                }
                Err(e) => {
                    warn!(
                        self.log, "Parent chain processing error. Downvoting peer";
                        "error" => format!("{:?}", e),
                        "last_peer" => format!("{:?}", parent_request.last_submitted_peer),
                    );
                    self.network
                        .downvote_peer(parent_request.last_submitted_peer.clone());
                    return;
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
            debug!(self.log, "Parent import failed";
            "block" => format!("{:?}",parent_request.downloaded_blocks[0].canonical_root()),
            "ancestors_found" => parent_request.downloaded_blocks.len()
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
            block_roots: vec![parent_hash],
        };
        // select a random fully synced peer to attempt to download the parent block
        let available_peers = self
            .network_globals
            .peers
            .read()
            .synced_peers()
            .cloned()
            .collect::<Vec<_>>();
        let peer_id = if let Some(peer_id) = available_peers.choose(&mut rand::thread_rng()) {
            (*peer_id).clone()
        } else {
            // there were no peers to choose from. We drop the lookup request
            return;
        };

        if let Ok(request_id) = self.network.blocks_by_root_request(peer_id, request) {
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
                    SyncMessage::BatchProcessed {
                        batch_id,
                        downloaded_blocks,
                        result,
                    } => {
                        self.range_sync.handle_block_process_result(
                            &mut self.network,
                            batch_id,
                            downloaded_blocks,
                            result,
                        );
                    }
                    SyncMessage::ParentLookupFailed(peer_id) => {
                        self.network.downvote_peer(peer_id);
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

        Ok(Async::NotReady)
    }
}
