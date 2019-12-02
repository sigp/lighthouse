//! This provides the logic for syncing a chain when the local node is far behind it's current
//! peers.




/// Blocks are downloaded in batches from peers. This constant specifies how many blocks per batch
/// is requested. There is a timeout for each batch request. If this value is too high, we will
/// downvote peers with poor bandwidth. This can be set arbitrarily high, in which case the
/// responder will fill the response up to the max request size, assuming they have the bandwidth
/// to do so.
//TODO: Make this dynamic based on peer's bandwidth
const BLOCKS_PER_REQUEST: u64 = 50;


struct Batch<T: EthSpec> {
    id: usize,
    start_slot: Slot,
    end_slot: Slot,
    head_root: Hash256,
    current_peer: PeerId, 
    retries: u8,
    downloaded_blocks: Vec<BeaconBlock<T>,
}

impl<T: EthSpec> Batch<T> {

    fn new(id: usize, start_slot: Slot, end_slot: Slot, head_root: Hash256, current_peer: PeerId) -> Self {
        Batch {
            id,
            start_slot,
            end_slot,
            head_root,
            current_peer,
            retries: 0,
            downloaded_blocks: Vec::new(),
        }
    }

    fn to_blocks_by_range_request(&self) => BlocksByRangeRequest {
        BlocksByRangeRequest {
            head_block_root: self.head_root,
            start_slot: self.start_slot,
            count: BLOCKS_PER_REQUEST,
            step: 1
        }
    }

}



enum SyncingChainState {
    Stopped,
    Syncing,
}


struct SyncingChain<T: EthSpec> {

    start_slot: Slot,

    target_head_slot: Slot,

    target_head_root: Hash256,

    downloaded_batches: Vec<Batch>,

    pending_batches: FnHashMap<RequestId, Batch>,

    completed_batches: Vec<Batch>,

    blocks_processed: usize,

    peer_pool: HashSet<PeerId>,

    current_batch_id: usize,

    last_processed_batch_id: usize,

    state: SyncingChainState
}

impl SyncingChain<T: EthSpec> {

    pub fn new(start_slot: Slot, target_head_slot: Slot, target_head_root: Hash256, peer: PeerId) -> Self {

        SyncingChain {
            start_slot,
            target_head_slot,
            target_head_root,
            downloaded_batches: Vec::new(),
            blocks_processed: 0,
            peer_pool: vec![peer],
            current_batch_id: 0,
            processed_batches: 0
            failed_batches: Vec<usize>,
            completed_batches:
            state: SyncingChainState::Stopped
        }
    }


    pub fn stop_syncing(&mut self) {
        self.state = SyncingChainState::Stopped;
    }

    // either a new chain, or an old one with a peer list
    pub fn start_syncing(&mut self, &mut network: NetworkContext, local_head_slot: Option<Slot>, log: &slog::Logger) {

        // a local head is provided for finalized chains, as other chains may have made
        // progress whilst this chain was Stopped. If so, update the `processed_batch_id` to
        // accommodate potentially downloaded batches from other chains. Also prune any old batches
        // awaiting processing
        if let Some(local_head) = local_head {
            
            // only important if the local head is more than a batch worth of blocks ahead of
            // what this chain believes is downloaded
            if let Some(batches_ahead) = local_head_slot.sub(self.start_slot + self.processed_batches*BLOCKS_PER_REQUEST).into().checked_rem(BLOCKS_PER_REQUEST) {
                // there are `batches_ahead` whole batches that have been downloaded by another
                // chain. Set the current processed_batch_id to this value.
                debug!(log, "Updating chains processed batches"; "old_completed_slot" => self.start_slot + self.processed_batches*BLOCKS_PER_REQUEST; "new_completed_slot" => self.start_slot + (self.processed_batches+ batches_ahead)*BLOCKS_PER_REQUEST);
                self.processed_batches += batches_ahead;

                if self.processed_batches*BLOCKS_PER_REQUEST > self.target_head_slot {
                    crit!(log, "Current head slot is above the target head - Coding error"); 
                    return;
                }

                // update the `current_batch_id`
                if self.current_batch_id < self.processed_batch {
                    self.current_batch_id = processed_batches;
                }

            }
        }

        // now begin requesting blocks from the peer pool. Ignore any peers with currently
        // pending requests
        let pending_peers = self.pending_batches.values().map(|batch| batch.current_peer).collect::<Vec<_>>();
        for peer_id in self.peer_pool.iter().filter(!peer| !pending_peers.contains(peer)) {
            // send a blocks by range request to the peer
            self.send_range_request(network, peer_id);
        };
    }

    // a peer has been added, start batch requests for this peer
    // this should only be called for a syncing chain
    pub fn peer_added(&mut self, &mut network: NetworkContext, peer_id: PeerId) {
        // function should only be called on syncing chains
        if let SyncingChainState::Stopped =  self.state  {
            crit!(self.log, "Peer added to a non-syncing chain"; "peer_id" => format!("{:?}", peer_id));
            return;
        }

        // find the next batch and request it from the peer
        self.send_range_request(network, peer_id);
    }

    fn send_range_request(&mut self, network: &mut SyncNetworkContext,  peer_id: PeerId) {
        // find the next pending batch and request it from the peer
        let batch = self.get_next_batch(peer_id);

        // request the next batch
        let request = batch.to_blocks_by_range_request(); 
        let request_id = match network.blocks_by_range_request(peer_id, request) {
            Ok(id) => id,
            Err(_) => {
                // the network channel failed. This is a critical unrecoverable error. We
                // simply ignore this peer for now.
                crit!(self.log, "Cannot communicate to the network server"; "error"=> "The network channel failed. Syncing cannot be completed");
                return;
            }
        };

        // add the batch to pending list
        self.pending_batches.insert(request_id, batch);
    }

    fn get_next_batch(&mut self, peer_id: PeerId) -> Batch {
        let batch_start_slot = self.start_slot + self.current_batch_id*BLOCKS_PER_REQUEST;
        let batch_end_slot = batch_start_slot + BLOCKS_PER_REQUEST - 1;

        let batch_id = self.current_batch_id;
        self.current_batch_id +=1;

        let  batch = Batch::new(batch_id, batch_start_slot, batch_end_slot, peer_id);
    }



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
    network: SyncNetworkContext,
    state: SyncState,
    finalized_chains: Vec<SyncingChain>,
    head_chains: Vec<SyncingChain>,
    /// The request ID for BlocksByRange sync requests. These ID's cannot overlap with other
    /// requests from the sync manager as requests are segregated by RPC type and the manager
    /// does not call `BlocksByRange`. Regardless, we start at 2^20. 
    request_id: usize,
    // In principle we could store this in the manager and reference it, but we store it here also
    // for the time being
    known_peers: HashSet<PeerId>,
    log: slog::Logger,
}

        pub fn add_peer(peer_id: PeerId, remote: PeerSyncInfo) {

        // add the peer to our list of known peers
        self.known_peers.insert(peer_id);

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

        // convenience variables
        let remote_finalized_slot = remote.finalized_epoch.start_slot(T::slots_per_epoch());
        let local_finalized_slot = local_info.finalized_epoch.start_slot(T::slots_per_epoch());
        
        // firstly, remove any out of date chains
        self.finalized_chains.retain(|chain| chain.target_head_slot > local_finalized_slot);
        self.head_chains.retain(|chain| chain.target_head_slot > local_info.head_slot);

        if remote.finalized_epoch > local_info.finalized_epoch {
            trace!(self.log, "Peer added - Beginning a finalization sync"; "peer_id" => format!("{:?}", peer_id));
            // finalized chain search

            // if a finalized chain already exists that matches, add this peer to the chain's peer
            // pool.
            if let Some(index) = self.finalized_chains.iter().position(|chain| chain.target_root == remote.finalized_root && chain.target_slot == remote_finalized_slot) {

                trace!(self.log, "Finalized chain exists, adding peer"; "peer_id" => format!("{:?}", peer_id));
                // add the peer to the chain's peer pool
                self.finalized_chains[index].peer_pool.insert(peer_id);

                // check if the new peer's addition will favour a new syncing chain. 
                if index != 0 && self.finalized_chains[index].peer_pool.len() > self.finalized_chains[0].peer_pool.len() {
                    // switch to the new syncing chain and stop the old
                    trace!(self.log, "Switching finalized chains to sync"; "peer_id" => format!("{:?}", peer_id));

                   self.finalized_chains[0].stop_syncing();
                   let new_best = self.finalized_chains.swap_remove(index);
                   self.finalized_chains.insert(0, new_best);
                   // start syncing the better chain
                   self.finalized_chains[0].start_syncing(local_finalized_slot);
                } else {
                    // no new chain to sync, peer has been added to current syncing chain.
                    // Inform it to request batches from the peer
                    debug!(self.log, "Peer added to chain pool"; "peer_id" => format!("{:?}", peer_id));
                    self.finalized_chains[0].peer_added(peer_id);
                }
            } else {  // there is no finalized chain that matches this peer's last finalized target
                // create a new finalized chain
                trace!(self.log, "New finalized chain added to sync"; "peer_id" => format!("{:?}", peer_id));
                self.finalized_chains.push(SyncingChain::new(local_finalized_slot,remote_finalized_slot,
                    remote.finalized_root,peer_id));

                // this chain will only have a single peer, and will only become the syncing chain
                // if no other chain exists
                if self.finalized_chains.len() == 1 {
                    self.finalized_chains[0].start_syncing(local_finalized_slot);
                }
            }
        } else {
            if !self.finalized_chains.is_empty() {
                // if there are finalized chains to sync, finish these first, before syncing head
                // chains. This allows us to re-sync all known peers
                debug!(self.log, "Peer added - Waiting for finalized sync to complete"; "peer_id" => format!("{:?}", peer_id));
                return;
            }

            // The new peer has the same finalized (earlier filters should prevent a peer with an
            // earlier finalized chain from reaching here). 
            trace!(self.log, "New peer added for recent head sync"; "peer_id" => format!("{:?}", peer_id));
            
            // search if their is a matching head chain, then add the peer to the chain
            if let Some(index) = self.head_chains.iter().position(|chain| chain.target_root == remote.head_root && chain.target_slot == remote.head_slot) {
                trace!(self.log, "Head chain exists, adding peer to the pool"; "peer_id" => format!("{:?}", peer_id));

                // add the peer to the head's pool
                self.head_chains[index].peer_pool.insert(peer_id);
                self.head_chains[index].peer_added();
            }
            // there are no other head chains that match this peers status, create a new one, and
            // remove the peer from any old ones
            self.head_chains.retain(|chain|  {
                                    chain.peer_pool.remove(peer_id);
                                    !chain.peer_pool.is_empty()
            });
            let new_head_chain = SyncingChain::new(local_finalized_slot, remote.head_slot, remote.head_root, peer_id); 
            // All head chains can sync simultaneously
            new_head_chain.start_syncing(local_finalized_slot);
            self.head_chains.insert(new_head_chain);
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





