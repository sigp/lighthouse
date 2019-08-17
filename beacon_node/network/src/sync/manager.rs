const MAX_BLOCKS_PER_REQUEST: usize = 10;

/// The number of slots that we can import blocks ahead of us, before going into full Sync mode.
const SLOT_IMPORT_TOLERANCE: u64 = 10;

const PARENT_FAIL_TOLERANCE: usize = 3;
const PARENT_DEPTH_TOLERANCE: usize = SLOT_IMPORT_TOLERANCE*2;

enum BlockRequestsState {
    QueuedForward,
    QueuedBackward,
    Pending(RequestId),
    Complete,
}

struct BlockRequests {
    target_head_slot: Slot
    target_head_root: Hash256,
    downloaded_blocks: Vec<BeaconBlock>,
    state: State,
}

struct ParentRequests {
    downloaded_blocks: Vec<BeaconBlock>,
    attempts: usize,
    last_submitted_peer: PeerId, // to downvote the submitting peer.
    state: BlockRequestsState,
}

impl BlockRequests {

    // gets the start slot for next batch
    // last block slot downloaded plus 1
    fn next_start_slot(&self) -> Option<Slot> {
        if !self.downloaded_blocks.is_empty() {
            match self.state {
                BlockRequestsState::QueuedForward => {
                    let last_element_index = self.downloaded_blocks.len() -1;
                    Some(downloaded_blocks[last_element_index].slot.add(1))
                }
                BlockRequestsState::QueuedBackward => {
                    let earliest_known_slot = self.downloaded_blocks[0].slot;
                    Some(earliest_known_slot.add(1).sub(MAX_BLOCKS_PER_REQUEST))
                }
            }
        }
        else {
            None
        }
    }
}

enum ManagerState {
    Syncing,
    Regular,
    Stalled,
}

enum ImportManagerOutcome {
    Idle,
    RequestBlocks{
        peer_id: PeerId,
        request_id: RequestId,
        request: BeaconBlocksRequest,
    },
    RecentRequest(PeerId, RecentBeaconBlocksRequest),
    DownvotePeer(PeerId),
}

    
pub struct ImportManager {
    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,
    state: MangerState,
    import_queue: HashMap<PeerId, BlockRequests>,
    parent_queue: Vec<ParentRequests>,
    full_peers: Hashset<PeerId>,
    current_req_id: usize,
    log: Logger,
}

impl ImportManager {

    pub fn add_peer(&mut self, peer_id, remote: PeerSyncInfo) { 
        // TODO: Improve comments.
        // initially try to download blocks from our current head
        // then backwards search all the way back to our finalized epoch until we match on a chain
        // has to be done sequentially to find next slot to start the batch from
        
        let local = PeerSyncInfo::from(&self.chain);

        // If a peer is within SLOT_IMPORT_TOLERANCE from out head slot, ignore a batch sync
        if remote.head_slot.sub(local.head_slot) < SLOT_IMPORT_TOLERANCE {
            trace!(self.log, "Ignoring full sync with peer";
                   "peer" => peer_id,
                   "peer_head_slot" => remote.head_slot,
                   "local_head_slot" => local.head_slot,
                   );
            // remove the peer from the queue if it exists
            self.import_queue.remove(&peer_id); 
            return;
        }

        if let Some(block_requests) = self.import_queue.get_mut(&peer_id) {
            // update the target head slot
            if remote.head_slot > requested_block.target_head_slot {
                block_requests.target_head_slot = remote.head_slot;
            }
        }  else  {
            let block_requests = BlockRequests {
                target_head_slot: remote.head_slot, // this should be larger than the current head. It is checked in the SyncManager before add_peer is called
                target_head_root: remote.head_root,
                downloaded_blocks: Vec::new(),
                state: RequestedBlockState::Queued
            }
            self.import_queue.insert(peer_id, block_requests);
        }

    }

    pub fn beacon_blocks_response(peer_id: PeerId, request_id: RequestId, blocks: Vec<BeaconBlock>) {
        
        // find the request
        let block_requests = match self.import_queue.get_mut(&peer_id) {
            Some(req) if req.state = RequestedBlockState::Pending(request_id) => req,
            None => {
                // No pending request, invalid request_id or coding error
                warn!(self.log, "BeaconBlocks response unknown"; "request_id" => request_id);
                return;
            }
        };

        // The response should contain at least one block.
        //
        // If we are syncing up to a target head block, at least the target head block should be
        // returned. If we are syncing back to our last finalized block the request should return
        // at least the last block we received (last known block). In diagram form:
        //
        //     unknown blocks       requested blocks        downloaded blocks
        // |-------------------|------------------------|------------------------|
        // ^finalized slot     ^ requested start slot   ^ last known block       ^ remote head

        if blocks.is_empty() {
            warn!(self.log, "BeaconBlocks response was empty"; "request_id" => request_id);
            block_requests.state = RequestedBlockState::Failed;
            return;
        }

        // Add the newly downloaded blocks to the current list of downloaded blocks. This also
        // determines if we are syncing forward or backward.
        let syncing_forwards = {
            if block_requests.blocks.is_empty() {
                block_requests.blocks.push(blocks);
                true
            }
            else if block_requests.blocks[0].slot < blocks[0].slot { // syncing forwards
                    // verify the peer hasn't sent overlapping blocks - ensuring the strictly
                    // increasing blocks in a batch will be verified during the processing
                    if block_requests.next_slot() > blocks[0].slot {
                        warn!(self.log, "BeaconBlocks response returned duplicate blocks", "request_id" => request_id, "response_initial_slot" => blocks[0].slot, "requested_initial_slot" => block_requests.next_slot());
                        block_requests.state = RequestedBlockState::Failed;
                        return;
                    }

                    block_requests.blocks.push(blocks);
                    true
                }
                else { false }
        };
        

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
        
        if syncing_forwards {
            // does the batch contain the target_head_slot
            let last_element_index = block_requests.blocks.len()-1;
            if block_requests[last_element_index].slot >= block_requests.target_slot {
                // if the batch is on our chain, this is complete and we can then process.
                // Otherwise start backwards syncing until we reach a common chain.
                let earliest_slot = block_requests_blocks[0].slot
                if block_requests.blocks[0] == self.chain.get_block_by_slot(earliest_slot) {
                    block_requests.state = RequestedBlockState::Complete;
                    return;
                }

                // not on the same chain, request blocks backwards
                // binary search, request half the distance between the earliest block and our
                // finalized slot
                let state = &beacon_chain.head().beacon_state;
                let local_finalized_slot = state.finalized_checkpoint.epoch; //TODO: Convert to slot
                // check that the request hasn't failed by having no common chain 
                if local_finalized_slot >= block_requests.blocks[0] {
                    warn!(self.log, "Peer returned an unknown chain."; "request_id" => request_id);
                    block_requests.state = RequestedBlockState::Failed;
                    return;
                }

                // Start a backwards sync by requesting earlier blocks 
                // There can be duplication in downloaded blocks here if there are a large number
                // of skip slots. In all cases we at least re-download the earliest known block.
                // It is unlikely that a backwards sync in required, so we accept this duplication
                // for now.
                block_requests.state = RequestedBlockState::QueuedBackward;
            }
            else {
             // batch doesn't contain the head slot, request the next batch
            block_requests.state = RequestedBlockState::QueuedForward;
            }
        }
        else {
            // syncing backwards
            // if the batch is on our chain, this is complete and we can then process.
            // Otherwise continue backwards
            let earliest_slot = block_requests_blocks[0].slot
            if block_requests.blocks[0] == self.chain.get_block_by_slot(earliest_slot) {
                block_requests.state = RequestedBlockState::Complete;
                return;
            }
            block_requests.state = RequestedBlockState::QueuedBackward;
            
        }
    }

    pub fn recent_blocks_response(peer_id: PeerId, request_id: RequestId, blocks: Vec<BeaconBlock>) {

        // find the request
        let parent_request = match self.parent_queue.get_mut(&peer_id) {
            Some(req) if req.state = RequestedBlockState::Pending(request_id) => req,
            None => {
                // No pending request, invalid request_id or coding error
                warn!(self.log, "RecentBeaconBlocks response unknown"; "request_id" => request_id);
                return;
            }
        };

        // if an empty response is given, the peer didn't have the requested block, try again
        if blocks.is_empty() {
            parent_request.attempts += 1;
            parent_request.state = RequestedBlockState::QueuedForward;
            parent_request.last_submitted_peer = peer_id;
            return;
        }

        // currently only support a single block lookup. Reject any response that has more than 1
        // block
        if blocks.len() != 1 {
            //TODO: Potentially downvote the peer
            debug!(self.log, "Peer sent more than 1 parent. Ignoring";
                   "peer_id" => peer_id, 
                   "no_parents" => blocks.len()
                   );
            return;
        }


        // queue for processing
        parent_request.state = RequestedBlockState::Complete;
    }


    pub fn inject_error(peer_id: PeerId, id: RequestId) {
        //TODO: Remove block state from pending
    }

    pub fn peer_disconnect(peer_id: PeerId)  {
        self.import_queue.remove(&peer_id);
        self.full_peers.remove(&peer_id);
        self.update_state();
    }

    pub fn add_full_peer(peer_id: PeerId) {
        debug!(
            self.log, "Fully synced peer added";
            "peer" => format!("{:?}", peer_id),
        );
        self.full_peers.insert(peer_id);
        self.update_state();
    }

    pub fn add_unknown_block(&mut self,block: BeaconBlock) {
        // if we are not in regular sync mode, ignore this block
        if self.state == ManagerState::Regular {
            return;
        }

        // make sure this block is not already being searched for
        // TODO: Potentially store a hashset of blocks for O(1) lookups
        for parent_req in self.parent_queue.iter() {
            if let Some(_) = parent_req.downloaded_blocks.iter().find(|d_block| d_block == block) {
                // we are already searching for this block, ignore it
                return;
            }
        }

        let req = ParentRequests { 
            downloaded_blocks: vec![block],
            failed_attempts: 0,
            state: RequestedBlockState::QueuedBackward
        }

        self.parent_queue.push(req);
    }

    pub fn poll() -> ImportManagerOutcome {

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
            if let (re_run, outcome) = self.process_complete_parent_requests() {
                if let Some(outcome) = outcome {
                    return outcome;
                }
                else if !re_run {
                    break;
                }
            }
        }
        
    return ImportManagerOutcome::Idle;

    }


    fn update_state(&mut self) {
        let previous_state = self.state;
        self.state = {
            if !self.import_queue.is_empty() {
                ManagerState::Syncing
            }
            else if !self.full_peers.is_empty() {
                ManagerState::Regualar
            }
            else {
                ManagerState::Stalled }
        };
        if self.state != previous_state {
            info!(self.log, "Syncing state updated",
                  "old_state" => format!("{:?}", previous_state)
                  "new_state" => format!("{:?}", self.state)
              );
        }
    }



    fn process_potential_block_requests(&mut self) -> Option<ImportManagerOutcome>  {
        // check if an outbound request is required
        // Managing a fixed number of outbound requests is maintained at the RPC protocol libp2p
        // layer and not needed here.
        // If any in queued state we submit a request. 
       

        // remove any failed batches
        self.import_queue.retain(|peer_id, block_request| {
            if block_request.state == RequestedBlockState::Failed {
                debug!(self.log, "Block import from peer failed",
                       "peer_id" => peer_id,
                       "downloaded_blocks" => block_request.downloaded.blocks.len()
                       );
                false
            }
            else { true }
        });


        for (peer_id, block_requests) in self.import_queue.iter_mut() {
            if let Some(request) = requests.iter().find(|req| req.state == RequestedBlockState::QueuedForward || req.state == RequestedBlockState::QueuedBackward) {

                let request.state = RequestedBlockState::Pending(self.current_req_id);
                self.current_req_id +=1;

                let req = BeaconBlocksRequest {
                    head_block_root: request.target_root,
                    start_slot: request.next_start_slot().unwrap_or_else(|| self.chain.head().slot),
                    count: MAX_BLOCKS_PER_REQUEST,
                    step: 0
                }
                return Some(ImportManagerOutCome::RequestBlocks{ peer_id, req });
            }
        }

        None
    }

    fn process_complete_batches(&mut self) -> Option<ImportManagerOutcome> {

        let completed_batches = self.import_queue.iter().filter(|_peer, block_requests| block_requests.state == RequestedState::Complete).map(|peer, _| peer).collect::<Vec<PeerId>>();
        for peer_id in completed_batches {
            let block_requests = self.import_queue.remove(&peer_id).unwrap("key exists");
            match self.process_blocks(block_requests.downloaded_blocks) {
                    Ok(()) =>  {
                        //TODO: Verify it's impossible to have empty downloaded_blocks
                        last_element = block_requests.downloaded_blocks.len() -1
                        debug!(self.log, "Blocks processed successfully";
                               "peer" => peer_id,
                               "start_slot" => block_requests.downloaded_blocks[0].slot,
                               "end_slot" => block_requests.downloaded_blocks[last_element].slot,
                               "no_blocks" => last_element + 1,
                               );
                        // Re-HELLO to ensure we are up to the latest head
                        return Some(ImportManagerOutcome::Hello(peer_id));
                    }
                    Err(e) => {
                        last_element = block_requests.downloaded_blocks.len() -1
                        warn!(self.log, "Block processing failed";
                               "peer" => peer_id,
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
        self.parent_queue.retain(|parent_request| {
            if parent_request.state == RequestedBlockState::Failed {
                debug!(self.log, "Parent import failed",
                       "block" => parent_request.downloaded_blocks[0].hash,
                       "siblings found" => parent_request.len()
                       );
                false
            }
            else { true }
        });

        // check to make sure there are peers to search for the parent from
        if self.full_peers.is_empty() {
            return;
        }

        // check if parents need to be searched for
        for parent_request in self.parent_queue.iter_mut() {
            if parent_request.failed_attempts >= PARENT_FAIL_TOLERANCE {
                parent_request.state == BlockRequestsState::Failed
                continue; 
            }
            else if parent_request.state == BlockRequestsState::QueuedForward {
                parent_request.state = BlockRequestsState::Pending(self.current_req_id);
                self.current_req_id +=1;
                let parent_hash =
                let req = RecentBeaconBlocksRequest {
                    block_roots: vec![parent_hash],
                };

                // select a random fully synced peer to attempt to download the parent block
                let peer_id = self.full_peers.iter().next().expect("List is not empty"); 

                return Some(ImportManagerOutcome::RecentRequest(peer_id, req);
            }
        }

        None
        }


    fn process_complete_parent_requests(&mut self) => (bool, Option<ImportManagerOutcome>) {

        // flag to determine if there is more process to drive or if the manager can be switched to
        // an idle state
        let mut re_run = false; 

        // verify the last added block is the parent of the last requested block
        let last_index = parent_requests.downloaded_blocks.len() -1;
        let expected_hash = parent_requests.downloaded_blocks[last_index].parent ;
        let block_hash = parent_requests.downloaded_blocks[0].tree_hash_root();
        if block_hash != expected_hash {
            //TODO: Potentially downvote the peer
            debug!(self.log, "Peer sent invalid parent. Ignoring";
                   "peer_id" => peer_id, 
                   "received_block" => block_hash,
                   "expected_parent" => expected_hash,
                   );
            return;
        }

        // Find any parent_requests ready to be processed
        for completed_request in self.parent_queue.iter_mut().filter(|req| req.state == BlockRequestsState::Complete) {
            // try and process the list of blocks up to the requested block
            while !completed_request.downloaded_blocks.is_empty() {
                let block = completed_request.downloaded_blocks.pop();
                match self.chain_process_block(block.clone()) {
                    Ok(BlockProcessingOutcome::ParentUnknown { parent }  => {
                        // need to keep looking for parents
                        completed_request.downloaded_blocks.push(block);
                        completed_request.state == BlockRequestsState::QueuedForward;
                        re_run = true;
                        break;
                    }
                    Ok(BlockProcessingOutcome::Processed { _ } => { }
                    Ok(outcome) => { // it's a future slot or an invalid block, remove it and try again
                        completed_request.failed_attempts +=1;
                        trace!(
                            self.log, "Invalid parent block";
                            "outcome" => format!("{:?}", outcome);
                            "peer" => format!("{:?}", completed_request.last_submitted_peer),
                        );
                        completed_request.state == BlockRequestsState::QueuedForward;
                        re_run = true;
                        return (re_run, Some(ImportManagerOutcome::DownvotePeer(completed_request.last_submitted_peer)));
                    }
                    Err(e) => { 
                        completed_request.failed_attempts +=1;
                        warn!(
                            self.log, "Parent processing error";
                            "error" => format!("{:?}", e);
                        );
                        completed_request.state == BlockRequestsState::QueuedForward;
                        re_run = true;
                        return (re_run, Some(ImportManagerOutcome::DownvotePeer(completed_request.last_submitted_peer)));
                    }
                    }
            }
        }

        // remove any full completed and processed parent chains
        self.parent_queue.retain(|req| if req.state == BlockRequestsState::Complete { false } else { true }); 
        (re_run, None)

    }


    fn process_blocks(
        &mut self,
        blocks: Vec<BeaconBlock<T::EthSpec>>,
    ) -> Result<(), String> {

        for block in blocks {
        let processing_result = self.chain.process_block(block.clone());

        if let Ok(outcome) = processing_result {
            match outcome {
                BlockProcessingOutcome::Processed { block_root } => {
                    // The block was valid and we processed it successfully.
                    trace!(
                        self.log, "Imported block from network";
                        "source" => source,
                        "slot" => block.slot,
                        "block_root" => format!("{}", block_root),
                        "peer" => format!("{:?}", peer_id),
                    );
                }
                BlockProcessingOutcome::ParentUnknown { parent } => {
                    // blocks should be sequential and all parents should exist
                    trace!(
                        self.log, "ParentBlockUnknown";
                        "source" => source,
                        "parent_root" => format!("{}", parent),
                        "baby_block_slot" => block.slot,
                    );
                    return Err(format!("Block at slot {} has an unknown parent.", block.slot));
                }
                BlockProcessingOutcome::FutureSlot {
                    present_slot,
                    block_slot,
                } => {
                    if present_slot + FUTURE_SLOT_TOLERANCE >= block_slot {
                        // The block is too far in the future, drop it.
                        trace!(
                            self.log, "FutureBlock";
                            "source" => source,
                            "msg" => "block for future slot rejected, check your time",
                            "present_slot" => present_slot,
                            "block_slot" => block_slot,
                            "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                            "peer" => format!("{:?}", peer_id),
                        );
                        return Err(format!("Block at slot {} is too far in the future", block.slot));
                    } else {
                        // The block is in the future, but not too far.
                        trace!(
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
                    trace!(
                        self.log, "InvalidBlock";
                        "source" => source,
                        "msg" => "peer sent invalid block",
                        "outcome" => format!("{:?}", outcome),
                        "peer" => format!("{:?}", peer_id),
                    );
                    return Err(format!("Invalid block at slot {}", block.slot));
                }
            }
            Ok(())
        } else {
            trace!(
                self.log, "BlockProcessingFailure";
                "source" => source,
                "msg" => "unexpected condition in processing block.",
                "outcome" => format!("{:?}", processing_result)
            );
            return Err(format!("Unexpected block processing error: {:?}", processing_result));
        }
    }
    }
}
