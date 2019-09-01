//! The `ImportManager` facilities the block syncing logic of lighthouse. The current networking
//! specification provides two methods from which to obtain blocks from peers. The `BeaconBlocks`
//! request and the `RecentBeaconBlocks` request. The former is used to obtain a large number of
//! blocks and the latter allows for searching for blocks given a block-hash.
//!
//! These two RPC methods are designed for two type of syncing.
//! - Long range (batch) sync, when a client is out of date and needs to the latest head.
//! - Parent lookup - when a peer provides us a block whose parent is unknown to us.
//!
//! Both of these syncing strategies are built into the `ImportManager`.
//!
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
//! This syncing process start by requesting `MAX_BLOCKS_PER_REQUEST` blocks from a peer with an
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

use super::simple_sync::{PeerSyncInfo, FUTURE_SLOT_TOLERANCE};
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::RequestId;
use eth2_libp2p::PeerId;
use slog::{debug, info, trace, warn, Logger};
use smallvec::SmallVec;
use std::collections::{HashMap, HashSet};
use std::ops::{Add, Sub};
use std::sync::{Arc, Weak};
use types::{BeaconBlock, EthSpec, Hash256, Slot};

/// Blocks are downloaded in batches from peers. This constant specifies how many blocks per batch
/// is requested. Currently the value is small for testing. This will be incremented for
/// production.
const MAX_BLOCKS_PER_REQUEST: u64 = 10;

/// The number of slots ahead of us that is allowed before requesting a long-range (batch)  Sync
/// from a peer. If a peer is within this tolerance (forwards or backwards), it is treated as a
/// fully sync'd peer.
const SLOT_IMPORT_TOLERANCE: usize = 10;
/// How many attempts we try to find a parent of a block before we give up trying .
const PARENT_FAIL_TOLERANCE: usize = 3;
/// The maximum depth we will search for a parent block. In principle we should have sync'd any
/// canonical chain to its head once the peer connects. A chain should not appear where it's depth
/// is further back than the most recent head slot.
const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE * 2;

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
    /// A failure has occurred and we will drop and downvote the peer that caused the request.
    Failed,
}

/// `BlockRequests` keep track of the long-range (batch) sync process per peer.
struct BlockRequests<T: EthSpec> {
    /// The peer's head slot and the target of this batch download.
    target_head_slot: Slot,
    /// The peer's head root, used to specify which chain of blocks we are downloading from the
    /// blocks.
    target_head_root: Hash256,
    /// The blocks that we have currently downloaded from the peer that are yet to be processed.
    downloaded_blocks: Vec<BeaconBlock<T>>,
    /// The current state of this batch request.
    state: BlockRequestsState,
    /// Specifies whether the current state is syncing forwards or backwards.
    forward_sync: bool,
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
        if self.forward_sync {
            self.current_start_slot += Slot::from(MAX_BLOCKS_PER_REQUEST);
        } else {
            self.current_start_slot -= Slot::from(MAX_BLOCKS_PER_REQUEST);
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

/// The output states that can occur from driving (polling) the manager state machine.
pub(crate) enum ImportManagerOutcome {
    /// There is no further work to complete. The manager is waiting for further input.
    Idle,
    /// A `BeaconBlocks` request is required.
    RequestBlocks {
        peer_id: PeerId,
        request_id: RequestId,
        request: BeaconBlocksRequest,
    },
    /// A `RecentBeaconBlocks` request is required.
    RecentRequest(PeerId, RecentBeaconBlocksRequest),
    /// Updates information with peer via requesting another HELLO handshake.
    Hello(PeerId),
    /// A peer has caused a punishable error and should be downvoted.
    DownvotePeer(PeerId),
}

/// The primary object for handling and driving all the current syncing logic. It maintains the
/// current state of the syncing process, the number of useful peers, downloaded blocks and
/// controls the logic behind both the long-range (batch) sync and the on-going potential parent
/// look-up of blocks.
pub struct ImportManager<T: BeaconChainTypes> {
    /// A weak reference to the underlying beacon chain.
    chain: Weak<BeaconChain<T>>,
    /// The current state of the import manager.
    state: ManagerState,
    /// A collection of `BlockRequest` per peer that is currently being downloaded. Used in the
    /// long-range (batch) sync process.
    import_queue: HashMap<PeerId, BlockRequests<T::EthSpec>>,
    /// A collection of parent block lookups.
    parent_queue: SmallVec<[ParentRequests<T::EthSpec>; 3]>,
    /// The collection of known, connected, fully-sync'd peers.
    full_peers: HashSet<PeerId>,
    /// The current request Id. This is used to keep track of responses to various outbound
    /// requests. This is an internal accounting mechanism, request id's are never sent to any
    /// peers.
    current_req_id: usize,
    /// The logger for the import manager.
    log: Logger,
}

impl<T: BeaconChainTypes> ImportManager<T> {
    /// Generates a new `ImportManager` given a logger and an Arc reference to a beacon chain. The
    /// import manager keeps a weak reference to the beacon chain, which allows the chain to be
    /// dropped during the syncing process. The syncing handles this termination gracefully.
    pub fn new(beacon_chain: Arc<BeaconChain<T>>, log: &slog::Logger) -> Self {
        ImportManager {
            chain: Arc::downgrade(&beacon_chain),
            state: ManagerState::Regular,
            import_queue: HashMap::new(),
            parent_queue: SmallVec::new(),
            full_peers: HashSet::new(),
            current_req_id: 0,
            log: log.clone(),
        }
    }

    /// A peer has connected which has blocks that are unknown to us.
    ///
    /// This function handles the logic associated with the connection of a new peer. If the peer
    /// is sufficiently ahead of our current head, a long-range (batch) sync is started and
    /// batches of blocks are queued to download from the peer. Batched blocks begin at our
    /// current head. If the resulting downloaded blocks are part of our current chain, we
    /// continue with a forward sync. If not, we download blocks (in batches) backwards until we
    /// reach a common ancestor. Batches are then processed and downloaded sequentially forwards.
    ///
    /// If the peer is within the `SLOT_IMPORT_TOLERANCE`, then it's head is sufficiently close to
    /// ours that we consider it fully sync'd with respect to our current chain.
    pub fn add_peer(&mut self, peer_id: PeerId, remote: PeerSyncInfo) {
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
            //
            return;
        }

        // Check if the peer is significantly is behind us. If within `SLOT_IMPORT_TOLERANCE`
        // treat them as a fully synced peer. If not, ignore them in the sync process
        if local.head_slot.sub(remote.head_slot).as_usize() < SLOT_IMPORT_TOLERANCE {
            self.add_full_peer(peer_id);
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
                target_head_slot: remote.head_slot, // this should be larger than the current head. It is checked in the SyncManager before add_peer is called
                target_head_root: remote.head_root,
                downloaded_blocks: Vec::new(),
                state: BlockRequestsState::Queued,
                forward_sync: true,
                current_start_slot: chain.best_slot(),
            };
            self.import_queue.insert(peer_id, block_requests);
        }
    }

    /// A `BeaconBlocks` request has received a response. This function process the response.
    pub fn beacon_blocks_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        mut blocks: Vec<BeaconBlock<T::EthSpec>>,
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
                warn!(self.log, "BeaconBlocks response unknown"; "request_id" => request_id);
                return;
            }
        };

        // If we are syncing up to a target head block, at least the target head block should be
        // returned. If we are syncing back to our last finalized block the request should return
        // at least the last block we received (last known block). In diagram form:
        //
        //     unknown blocks       requested blocks        downloaded blocks
        // |-------------------|------------------------|------------------------|
        // ^finalized slot     ^ requested start slot   ^ last known block       ^ remote head

        if blocks.is_empty() {
            debug!(self.log, "BeaconBlocks response was empty"; "request_id" => request_id);
            block_requests.update_start_slot();
            return;
        }

        // verify the range of received blocks
        // Note that the order of blocks is verified in block processing
        let last_sent_slot = blocks[blocks.len() - 1].slot;
        if block_requests.current_start_slot > blocks[0].slot
            || block_requests
                .current_start_slot
                .add(MAX_BLOCKS_PER_REQUEST)
                < last_sent_slot
        {
            //TODO: Downvote peer - add a reason to failed
            dbg!(&blocks);
            warn!(self.log, "BeaconBlocks response returned out of range blocks"; 
                          "request_id" => request_id, 
                          "response_initial_slot" => blocks[0].slot, 
                          "requested_initial_slot" => block_requests.current_start_slot);
            // consider this sync failed
            block_requests.state = BlockRequestsState::Failed;
            return;
        }

        // Determine if more blocks need to be downloaded. There are a few cases:
        // - We have downloaded a batch from our head_slot, which has not reached the remotes head
        //      (target head). Therefore we need to download another sequential batch.
        // - The latest batch includes blocks that greater than or equal to the target_head slot,
        //      which means we have caught up to their head. We then check to see if the first
        //      block downloaded matches our head. If so, we are on the same chain and can process
        //      the blocks. If not we need to sync back further until we are on the same chain. So
        //      request more blocks.
        // - We are syncing backwards (from our head slot) and need to check if we are on the same
        //      chain. If so, process the blocks, if not, request more blocks all the way up to
        //      our last finalized slot.

        if block_requests.forward_sync {
            // append blocks if syncing forward
            block_requests.downloaded_blocks.append(&mut blocks);
        } else {
            // prepend blocks if syncing backwards
            block_requests.downloaded_blocks.splice(..0, blocks);
        }

        // does the batch contain the target_head_slot
        let last_element_index = block_requests.downloaded_blocks.len() - 1;
        if block_requests.downloaded_blocks[last_element_index].slot
            >= block_requests.target_head_slot
            || !block_requests.forward_sync
        {
            // if the batch is on our chain, this is complete and we can then process.
            // Otherwise start backwards syncing until we reach a common chain.
            let earliest_slot = block_requests.downloaded_blocks[0].slot;
            //TODO: Decide which is faster. Reading block from db and comparing or calculating
            //the hash tree root and comparing.
            if Some(block_requests.downloaded_blocks[0].canonical_root())
                == root_at_slot(&self.chain, earliest_slot)
            {
                block_requests.state = BlockRequestsState::Complete;
                return;
            }

            // not on the same chain, request blocks backwards
            let state = &self.chain.head().beacon_state;
            let local_finalized_slot = state
                .finalized_checkpoint
                .epoch
                .start_slot(T::EthSpec::slots_per_epoch());

            // check that the request hasn't failed by having no common chain
            if local_finalized_slot >= block_requests.current_start_slot {
                warn!(self.log, "Peer returned an unknown chain."; "request_id" => request_id);
                block_requests.state = BlockRequestsState::Failed;
                return;
            }

            // if this is a forward sync, then we have reached the head without a common chain
            // and we need to start syncing backwards.
            if block_requests.forward_sync {
                // Start a backwards sync by requesting earlier blocks
                block_requests.forward_sync = false;
                block_requests.current_start_slot = std::cmp::min(
                    self.chain.best_slot(),
                    block_requests.downloaded_blocks[0].slot,
                );
            }
        }

        // update the start slot and re-queue the batch
        block_requests.update_start_slot();
    }

    pub fn recent_blocks_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        blocks: Vec<BeaconBlock<T::EthSpec>>,
    ) {
        // find the request
        let parent_request = match self
            .parent_queue
            .iter_mut()
            .find(|request| request.state == BlockRequestsState::Pending(request_id))
        {
            Some(req) => req,
            None => {
                // No pending request, invalid request_id or coding error
                warn!(self.log, "RecentBeaconBlocks response unknown"; "request_id" => request_id);
                return;
            }
        };

        // if an empty response is given, the peer didn't have the requested block, try again
        if blocks.is_empty() {
            parent_request.failed_attempts += 1;
            parent_request.state = BlockRequestsState::Queued;
            parent_request.last_submitted_peer = peer_id;
            return;
        }

        // currently only support a single block lookup. Reject any response that has more than 1
        // block
        if blocks.len() != 1 {
            //TODO: Potentially downvote the peer
            debug!(self.log, "Peer sent more than 1 parent. Ignoring";
            "peer_id" => format!("{:?}", peer_id),
            "no_parents" => blocks.len()
            );
            return;
        }

        // queue for processing
        parent_request.state = BlockRequestsState::Complete;
    }

    pub fn _inject_error(_peer_id: PeerId, _id: RequestId) {
        //TODO: Remove block state from pending
    }

    pub fn peer_disconnect(&mut self, peer_id: &PeerId) {
        self.import_queue.remove(peer_id);
        self.full_peers.remove(peer_id);
        self.update_state();
    }

    pub fn add_full_peer(&mut self, peer_id: PeerId) {
        debug!(
            self.log, "Fully synced peer added";
            "peer" => format!("{:?}", peer_id),
        );
        self.full_peers.insert(peer_id);
        self.update_state();
    }

    pub fn add_unknown_block(&mut self, block: BeaconBlock<T::EthSpec>, peer_id: PeerId) {
        // if we are not in regular sync mode, ignore this block
        if let ManagerState::Regular = self.state {
            return;
        }

        // make sure this block is not already being searched for
        // TODO: Potentially store a hashset of blocks for O(1) lookups
        for parent_req in self.parent_queue.iter() {
            if let Some(_) = parent_req
                .downloaded_blocks
                .iter()
                .find(|d_block| d_block == &&block)
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

    pub(crate) fn poll(&mut self) -> ImportManagerOutcome {
        loop {
            // update the state of the manager
            self.update_state();

            // process potential block requests
            if let Some(outcome) = self.process_potential_block_requests() {
                return outcome;
            }

            // process any complete long-range batches
            if let Some(outcome) = self.process_complete_batches() {
                return outcome;
            }

            // process any parent block lookup-requests
            if let Some(outcome) = self.process_parent_requests() {
                return outcome;
            }

            // process any complete parent lookups
            let (re_run, outcome) = self.process_complete_parent_requests();
            if let Some(outcome) = outcome {
                return outcome;
            } else if !re_run {
                break;
            }
        }

        return ImportManagerOutcome::Idle;
    }

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

    fn process_potential_block_requests(&mut self) -> Option<ImportManagerOutcome> {
        // check if an outbound request is required
        // Managing a fixed number of outbound requests is maintained at the RPC protocol libp2p
        // layer and not needed here.
        // If any in queued state we submit a request.

        // remove any failed batches
        let debug_log = &self.log;
        self.import_queue.retain(|peer_id, block_request| {
            if let BlockRequestsState::Failed = block_request.state {
                debug!(debug_log, "Block import from peer failed";
                "peer_id" => format!("{:?}", peer_id),
                "downloaded_blocks" => block_request.downloaded_blocks.len()
                );
                false
            } else {
                true
            }
        });

        // process queued block requests
        for (peer_id, block_requests) in self
            .import_queue
            .iter_mut()
            .find(|(_peer_id, req)| req.state == BlockRequestsState::Queued)
        {
            let request_id = self.current_req_id;
            block_requests.state = BlockRequestsState::Pending(request_id);
            self.current_req_id += 1;

            let request = BeaconBlocksRequest {
                head_block_root: block_requests.target_head_root,
                start_slot: block_requests.current_start_slot.as_u64(),
                count: MAX_BLOCKS_PER_REQUEST,
                step: 0,
            };
            return Some(ImportManagerOutcome::RequestBlocks {
                peer_id: peer_id.clone(),
                request,
                request_id,
            });
        }

        None
    }

    fn process_complete_batches(&mut self) -> Option<ImportManagerOutcome> {
        let completed_batches = self
            .import_queue
            .iter()
            .filter(|(_peer, block_requests)| block_requests.state == BlockRequestsState::Complete)
            .map(|(peer, _)| peer)
            .cloned()
            .collect::<Vec<PeerId>>();
        for peer_id in completed_batches {
            let block_requests = self.import_queue.remove(&peer_id).expect("key exists");
            match self.process_blocks(block_requests.downloaded_blocks.clone()) {
                Ok(()) => {
                    //TODO: Verify it's impossible to have empty downloaded_blocks
                    let last_element = block_requests.downloaded_blocks.len() - 1;
                    debug!(self.log, "Blocks processed successfully";
                    "peer" => format!("{:?}", peer_id),
                    "start_slot" => block_requests.downloaded_blocks[0].slot,
                    "end_slot" => block_requests.downloaded_blocks[last_element].slot,
                    "no_blocks" => last_element + 1,
                    );
                    // Re-HELLO to ensure we are up to the latest head
                    return Some(ImportManagerOutcome::Hello(peer_id));
                }
                Err(e) => {
                    let last_element = block_requests.downloaded_blocks.len() - 1;
                    warn!(self.log, "Block processing failed";
                        "peer" => format!("{:?}", peer_id),
                        "start_slot" => block_requests.downloaded_blocks[0].slot,
                        "end_slot" => block_requests.downloaded_blocks[last_element].slot,
                        "no_blocks" => last_element + 1,
                        "error" => format!("{:?}", e),
                    );
                    return Some(ImportManagerOutcome::DownvotePeer(peer_id));
                }
            }
        }
        None
    }

    fn process_parent_requests(&mut self) -> Option<ImportManagerOutcome> {
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

        // check to make sure there are peers to search for the parent from
        if self.full_peers.is_empty() {
            return None;
        }

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

                parent_request.state = BlockRequestsState::Pending(self.current_req_id);
                self.current_req_id += 1;
                let last_element_index = parent_request.downloaded_blocks.len() - 1;
                let parent_hash = parent_request.downloaded_blocks[last_element_index].parent_root;
                let req = RecentBeaconBlocksRequest {
                    block_roots: vec![parent_hash],
                };

                // select a random fully synced peer to attempt to download the parent block
                let peer_id = self.full_peers.iter().next().expect("List is not empty");

                return Some(ImportManagerOutcome::RecentRequest(peer_id.clone(), req));
            }
        }

        None
    }

    fn process_complete_parent_requests(&mut self) -> (bool, Option<ImportManagerOutcome>) {
        // flag to determine if there is more process to drive or if the manager can be switched to
        // an idle state
        let mut re_run = false;

        // Find any parent_requests ready to be processed
        for completed_request in self
            .parent_queue
            .iter_mut()
            .filter(|req| req.state == BlockRequestsState::Complete)
        {
            // verify the last added block is the parent of the last requested block
            let last_index = completed_request.downloaded_blocks.len() - 1;
            let expected_hash = completed_request.downloaded_blocks[last_index].parent_root;
            // Note: the length must be greater than 1 so this cannot panic.
            let block_hash = completed_request.downloaded_blocks[last_index - 1].canonical_root();
            if block_hash != expected_hash {
                // remove the head block
                let _ = completed_request.downloaded_blocks.pop();
                completed_request.state = BlockRequestsState::Queued;
                //TODO: Potentially downvote the peer
                let peer = completed_request.last_submitted_peer.clone();
                debug!(self.log, "Peer sent invalid parent. Ignoring";
                "peer_id" => format!("{:?}",peer),
                "received_block" => format!("{}", block_hash),
                "expected_parent" => format!("{}", expected_hash),
                );
                return (true, Some(ImportManagerOutcome::DownvotePeer(peer)));
            }

            // try and process the list of blocks up to the requested block
            while !completed_request.downloaded_blocks.is_empty() {
                let block = completed_request
                    .downloaded_blocks
                    .pop()
                    .expect("Block must exist exist");
                match self.chain.process_block(block.clone()) {
                    Ok(BlockProcessingOutcome::ParentUnknown { parent: _ }) => {
                        // need to keep looking for parents
                        completed_request.downloaded_blocks.push(block);
                        completed_request.state = BlockRequestsState::Queued;
                        re_run = true;
                        break;
                    }
                    Ok(BlockProcessingOutcome::Processed { block_root: _ }) => {}
                    Ok(outcome) => {
                        // it's a future slot or an invalid block, remove it and try again
                        completed_request.failed_attempts += 1;
                        trace!(
                            self.log, "Invalid parent block";
                            "outcome" => format!("{:?}", outcome),
                            "peer" => format!("{:?}", completed_request.last_submitted_peer),
                        );
                        completed_request.state = BlockRequestsState::Queued;
                        re_run = true;
                        return (
                            re_run,
                            Some(ImportManagerOutcome::DownvotePeer(
                                completed_request.last_submitted_peer.clone(),
                            )),
                        );
                    }
                    Err(e) => {
                        completed_request.failed_attempts += 1;
                        warn!(
                            self.log, "Parent processing error";
                            "error" => format!("{:?}", e)
                        );
                        completed_request.state = BlockRequestsState::Queued;
                        re_run = true;
                        return (
                            re_run,
                            Some(ImportManagerOutcome::DownvotePeer(
                                completed_request.last_submitted_peer.clone(),
                            )),
                        );
                    }
                }
            }
        }

        // remove any full completed and processed parent chains
        self.parent_queue.retain(|req| {
            if req.state == BlockRequestsState::Complete {
                false
            } else {
                true
            }
        });
        (re_run, None)
    }

    fn process_blocks(&mut self, blocks: Vec<BeaconBlock<T::EthSpec>>) -> Result<(), String> {
        for block in blocks {
            let processing_result = self.chain.process_block(block.clone());

            if let Ok(outcome) = processing_result {
                match outcome {
                    BlockProcessingOutcome::Processed { block_root } => {
                        // The block was valid and we processed it successfully.
                        trace!(
                            self.log, "Imported block from network";
                            "slot" => block.slot,
                            "block_root" => format!("{}", block_root),
                        );
                    }
                    BlockProcessingOutcome::ParentUnknown { parent } => {
                        // blocks should be sequential and all parents should exist
                        trace!(
                            self.log, "ParentBlockUnknown";
                            "parent_root" => format!("{}", parent),
                            "baby_block_slot" => block.slot,
                        );
                        return Err(format!(
                            "Block at slot {} has an unknown parent.",
                            block.slot
                        ));
                    }
                    BlockProcessingOutcome::FutureSlot {
                        present_slot,
                        block_slot,
                    } => {
                        if present_slot + FUTURE_SLOT_TOLERANCE >= block_slot {
                            // The block is too far in the future, drop it.
                            trace!(
                                self.log, "FutureBlock";
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
                                self.log, "QueuedFutureBlock";
                                "msg" => "queuing future block, check your time",
                                "present_slot" => present_slot,
                                "block_slot" => block_slot,
                                "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                            );
                        }
                    }
                    BlockProcessingOutcome::FinalizedSlot => {
                        trace!(
                            self.log, "Finalized or earlier block processed";
                            "outcome" => format!("{:?}", outcome),
                        );
                        // block reached our finalized slot or was earlier, move to the next block
                    }
                    _ => {
                        trace!(
                            self.log, "InvalidBlock";
                            "msg" => "peer sent invalid block",
                            "outcome" => format!("{:?}", outcome),
                        );
                        return Err(format!("Invalid block at slot {}", block.slot));
                    }
                }
            } else {
                trace!(
                    self.log, "BlockProcessingFailure";
                    "msg" => "unexpected condition in processing block.",
                    "outcome" => format!("{:?}", processing_result)
                );
                return Err(format!(
                    "Unexpected block processing error: {:?}",
                    processing_result
                ));
            }
        }
        Ok(())
    }
}

fn root_at_slot<T: BeaconChainTypes>(
    chain: &Arc<BeaconChain<T>>,
    target_slot: Slot,
) -> Option<Hash256> {
    chain
        .rev_iter_block_roots()
        .find(|(_root, slot)| *slot == target_slot)
        .map(|(root, _slot)| root)
}
