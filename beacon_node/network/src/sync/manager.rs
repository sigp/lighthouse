use super::simple_sync::{PeerSyncInfo, FUTURE_SLOT_TOLERANCE};
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::RequestId;
use eth2_libp2p::PeerId;
use slog::{debug, info, trace, warn, Logger};
use std::collections::{HashMap, HashSet};
use std::ops::{Add, Sub};
use std::sync::Arc;
use types::{BeaconBlock, EthSpec, Hash256, Slot};

const MAX_BLOCKS_PER_REQUEST: u64 = 10;

/// The number of slots that we can import blocks ahead of us, before going into full Sync mode.
const SLOT_IMPORT_TOLERANCE: usize = 10;
const PARENT_FAIL_TOLERANCE: usize = 3;
const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE * 2;

#[derive(PartialEq)]
enum BlockRequestsState {
    Queued,
    Pending(RequestId),
    Complete,
    Failed,
}

struct BlockRequests<T: EthSpec> {
    target_head_slot: Slot,
    target_head_root: Hash256,
    downloaded_blocks: Vec<BeaconBlock<T>>,
    state: BlockRequestsState,
    /// Specifies whether the current state is syncing forwards or backwards.
    forward_sync: bool,
    /// The current `start_slot` of the batched block request.
    current_start_slot: Slot,
}

struct ParentRequests<T: EthSpec> {
    downloaded_blocks: Vec<BeaconBlock<T>>,
    failed_attempts: usize,
    last_submitted_peer: PeerId, // to downvote the submitting peer.
    state: BlockRequestsState,
}

impl<T: EthSpec> BlockRequests<T> {
    // gets the start slot for next batch
    // last block slot downloaded plus 1
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
enum ManagerState {
    Syncing,
    Regular,
    Stalled,
}

pub(crate) enum ImportManagerOutcome {
    Idle,
    RequestBlocks {
        peer_id: PeerId,
        request_id: RequestId,
        request: BeaconBlocksRequest,
    },
    /// Updates information with peer via requesting another HELLO handshake.
    Hello(PeerId),
    RecentRequest(PeerId, RecentBeaconBlocksRequest),
    DownvotePeer(PeerId),
}

pub struct ImportManager<T: BeaconChainTypes> {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,
    state: ManagerState,
    import_queue: HashMap<PeerId, BlockRequests<T::EthSpec>>,
    parent_queue: Vec<ParentRequests<T::EthSpec>>,
    full_peers: HashSet<PeerId>,
    current_req_id: usize,
    log: Logger,
}

impl<T: BeaconChainTypes> ImportManager<T> {
    pub fn new(beacon_chain: Arc<BeaconChain<T>>, log: &slog::Logger) -> Self {
        ImportManager {
            chain: beacon_chain.clone(),
            state: ManagerState::Regular,
            import_queue: HashMap::new(),
            parent_queue: Vec::new(),
            full_peers: HashSet::new(),
            current_req_id: 0,
            log: log.clone(),
        }
    }

    pub fn add_peer(&mut self, peer_id: PeerId, remote: PeerSyncInfo) {
        // TODO: Improve comments.
        // initially try to download blocks from our current head
        // then backwards search all the way back to our finalized epoch until we match on a chain
        // has to be done sequentially to find next slot to start the batch from

        let local = PeerSyncInfo::from(&self.chain);

        // If a peer is within SLOT_IMPORT_TOLERANCE from our head slot, ignore a batch sync
        if remote.head_slot.sub(local.head_slot).as_usize() < SLOT_IMPORT_TOLERANCE {
            trace!(self.log, "Ignoring full sync with peer";
            "peer" => format!("{:?}", peer_id),
            "peer_head_slot" => remote.head_slot,
            "local_head_slot" => local.head_slot,
            );
            // remove the peer from the queue if it exists
            self.import_queue.remove(&peer_id);
            return;
        }

        if let Some(block_requests) = self.import_queue.get_mut(&peer_id) {
            // update the target head slot
            if remote.head_slot > block_requests.target_head_slot {
                block_requests.target_head_slot = remote.head_slot;
            }
        } else {
            let block_requests = BlockRequests {
                target_head_slot: remote.head_slot, // this should be larger than the current head. It is checked in the SyncManager before add_peer is called
                target_head_root: remote.head_root,
                downloaded_blocks: Vec::new(),
                state: BlockRequestsState::Queued,
                forward_sync: true,
                current_start_slot: self.chain.best_slot(),
            };
            self.import_queue.insert(peer_id, block_requests);
        }
    }

    pub fn beacon_blocks_response(
        &mut self,
        peer_id: PeerId,
        request_id: RequestId,
        mut blocks: Vec<BeaconBlock<T::EthSpec>>,
    ) {
        // find the request
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
