//! This provides the logic for syncing a chain when the local node is far behind it's current
//! peers.




/// Blocks are downloaded in batches from peers. This constant specifies how many blocks per batch
/// is requested. There is a timeout for each batch request. If this value is too high, we will
/// downvote peers with poor bandwidth. This can be set arbitrarily high, in which case the
/// responder will fill the response up to the max request size, assuming they have the bandwidth
/// to do so.
//TODO: Make this dynamic based on peer's bandwidth
const BLOCKS_PER_REQUEST: u64 = 50;

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

enum BatchState {
    Completed,
    Pending(RequestId),
    Failed,
}

struct Batch<T: EthSpec> {
    id: u64,
    start_slot: Slot,
    end_slot: Slot,
    current_peer: PeerId, 
    retries: u8,
    state: BatchState,
    downloaded_blocks: Vec<BeaconBlock<T>,
}

enum SyncingChainState {
    Stopped,
    Syncing,
}


struct SyncingChain<T: EthSpec> {
    target_head_slot: Slot,

    target_head_root: Hash256,

    downloaded_batches: Vec<Batch>,

    blocks_processed: usize,

    peer_pool: Vec<PeerId>,

    /// The current `start_slot` of the batched block request.
    current_batch_id: u64,

    state: SyncingChainState
}

impl SyncingChain<T: EthSpec> {


    pub fn stop_syncing(&mut self) {
        self.state = SyncingChainState::Stopped;
    }

    // either a new chain, or an old one with a peer list
    pub fn start_syncing(&mut self) {

        // update the start slot from current chain
        // given the peer pool start batch requests



    }

    // a peer has been added, start batch requests for this peer
    pub fn peer_added(peer_id: PeerId) { }
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

enum SyncState {
    Finalized
    Head
    Idle
}

// Note - May have to split batches as one may have hit the RPC size limit. In which case attempt
// to retry

struct RangeSync<T: EthSpec> {
    chain: Weak<BeaconChain>,
    state: SyncState,
    finalized_chains: Vec<SyncingChain>,
    head_chains: Vec<SyncingChain>,
}




        pub fn add_peer(peer: PeerId, remote: PeerSyncInfo) {
        // evaluate which chain to sync from

        // determine if we need to run a sync to the nearest finalized state or simply sync to
        // its current head
        let local_info = match self.chain.upgrade() {
            Some(chain) => PeerSynfInfo::from(chain),
            None => {
                warn!(self.log,
                      "Beacon chain dropped. Peer not considered for sync";
                      "peer_id" => format!("{:?}", peer_id));
                return;
            }
        };

        if remote.finalized_epoch > local_info.finalized_epoch {
            // finalized chain search
            
            // firstly, remove any out of date chains
            self.finalized_chains.retain(|chain| chain.target_head_slot > Slot::from(local_info.finalized_epoch));

            // if a finalized chain already exists that matches, add our peer to the chain's peer
            // pool.
            if let Some(index) = self.finalized_chains.iter().position(|chain| chain.target_root == remote.finalized_root && chain.target_slot == Slot::from(remote.finalized_epoch)) {

                // add the peer to the chain's peer pool
                self.finalized_chains[index].peer_pool.push(peer_id);

                // check if the new peer's addition will favour a new syncing chain. 
                if index != 0 && self.finalized_chains[index].peer_pool.len() > self.finalized_chains[0].peer_pool.len() {
                    // switch to the new syncing chain and stop the old

                    self.finalized_chains[0].stop_syncing();
                   let new_best = self.finalized_chains.swap_remove(index);
                   self.finalized_chains.insert(0, new_best);
                   // start syncing the new chain
                   self.finalized_chains[0].start_syncing();
                } else {
                    // no new chain to sync, peer has been added to current syncing chain.
                    // Inform it to request batches from the peer
                    self.finalized_chains[0].peer_added(peer_id);


                // add the peer to this chain's peer pool
                let is_new_peer = self.finalized_chains[index].add_peer(peer_id);




                   // begin/resume the syncing
                   self.finalized_chains[0]


                // as a new peer has been added
            }
            else {



            }
            




        } else {
            // head chain search




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

        pub fn is_syncing() {
        }

        // if a peer disconnects, re-evaluate which chain to sync
        pub fn peer_disconnect(&mut self, peer_id: PeerId) { }

        pub fn inject_error(&mut self, peer_id: PeerId, request_id: RequestId) {

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





