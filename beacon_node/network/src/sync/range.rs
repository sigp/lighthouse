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
    /// The ID of the batch, batches are ID's sequentially.
    id: usize,
    /// The requested start slot of the batch.
    start_slot: Slot,
    /// The requested end slot of batch.
    end_slot: Slot,
    /// The hash of the chain root to requested from the peer.
    head_root: Hash256,
    /// The peer that was originally assigned to the batch.
    original_peer: PeerId,
    /// The peer that is currently assigned to the batch.
    current_peer: PeerId, 
    /// The number of retries this batch has undergone.
    retries: u8,
    /// The blocks that have been downloaded.
    downloaded_blocks: Vec<BeaconBlock<T>,
}

impl<T: EthSpec> Batch<T> {

    fn new(id: usize, start_slot: Slot, end_slot: Slot, head_root: Hash256, peer_id: PeerId) -> Self {
        Batch {
            id,
            start_slot,
            end_slot,
            head_root,
            original_peer: peer_id,
            current_peer: peer_id,
            retries: 0,
            downloaded_blocks: Vec::new(),
        }
    }

    fn to_blocks_by_range_request(&self) => BlocksByRangeRequest {
        BlocksByRangeRequest {
            head_block_root: self.head_root,
            start_slot: self.start_slot,
            count: std::cmp::min(BLOCKS_PER_REQUEST, self.end_slot - self.start_slot),
            step: 1
        }
    }

}


enum SyncingChainState {
    /// The chain is not being synced.
    Stopped,
    /// The chain is undergoing syncing.
    Syncing,
    /// The chain is temporarily paused whilst an error is rectified.
    Paused,
}


struct SyncingChain<T: EthSpec> {
    /// The original start slot when this chain was initialised.
    start_slot: Slot,

    /// The target head slot.
    target_head_slot: Slot,

    /// The target head root.
    target_head_root: Hash256,


    /// The batches that are currently awaiting a response from a peer. An RPC request for these
    /// have been sent.
    pending_batches: FnHashMap<RequestId, Batch>,

    /// The batches that have been downloaded and are awaiting processing and/or validation.
    completed_batches: Vec<Batch>,

    /// The peers that agree on the `target_head_slot` and `target_head_root` as a canonical chain
    /// and thus available to download this chain from.
    peer_pool: HashSet<PeerId>,

    /// The next batch_id that needs to be downloaded.
    to_be_downloaded_id: usize,

    /// The next batch id that needs to be processed.
    to_be_processed_id: usize,

    /// The last batch id that was processed.
    last_processed_id: usize,

    /// The current state of the chain.
    state: SyncingChainState
}

impl SyncingChain<T: EthSpec> {

    pub fn new(start_slot: Slot, target_head_slot: Slot, target_head_root: Hash256, peer_id: PeerId) -> Self {

        let peer_pool = HashSet::new();
        peer_pool.insert(peer_id);

        SyncingChain {
            start_slot,
            target_head_slot,
            target_head_root,
            pending_batches: FnvHashMap::default(),
            completed_batches: Vec::new(),
            peer_pool,
            to_be_downloaded_id: 0,
            to_be_processed_id: 0
            last_processed_id: 0
            state: SyncingChainState::Stopped
        }
    }

    pub fn on_block_response(&mut self, chain: Weak<BeaconChain>, network: &mut SyncNetwork, request_id: RequestId, beacon_block: Option<BeaconBlock>, log: &slog::Logger) -> bool {
        // returns true if this response completes the chain

        // If this is not a stream termination, simply add the block to the request
        if let Some(block) = beacon_block {
            let batch = match self.pending_batches.get_mut(&request_id) {
                Some(batch) => batch.downloaded_blocks.push(block),
                None => {
                    // the request must exist before this function is called
                    crit!(log, "Request doesn't exist - coding error");
                    return;
                }
            };
        } else {
            // A stream termination has been sent. This batch has ended. Process a completed batch.
            let batch = match = self.pending_batches.remove(&request_id {
                Some(batch) => batch, 
                None => {
                    // the request must exist before this function is called
                    crit!(log, "Request doesn't exist - coding error");
                    return;
                }
            };
            let current_peer = batch.current_peer.clone();
            self.process_completed_batch(chain, network, batch, log)
        }
        }

    fn process_completed_batch(&mut self,chain: Weak<BeaconChain>, network: &mut SyncNetwork, batch: Batch, log: &slog::Logger) -> bool {
        // An entire batch of blocks has been received. This functions checks to see if it can be processed,
        // remove any batches waiting to be verified and if this chain is syncing, request new
        // blocks for the peer.
        
        // The peer that completed this batch, may be re-requested if this batch doesn't complete
        // the chain and there is no error in processing
        let current_peer = batch.current_peer.clone();

        // verify the range of received blocks
        // Note that the order of blocks is verified in block processing
        if let Some(last_slot) = batch.downloaded_blocks.last().map(|b| b.slot) {
            // the batch is non-empty
            if batch.start_slot > batch.downloaded_blocks[0].slot
            || batch.end_slot < last_slot
        {
            warn!(self.log, "BlocksByRange response returned out of range blocks"; 
                          "request_id" => request_id, 
                          "response_initial_slot" => blocks[0].slot, 
                          "requested_initial_slot" => block_requests.current_start_slot);
            network.downvote_peer(peer_id);
            self.to_be_processed_id = batch.id; // reset the id back to here, when incrementing, it will check against completed batches
            return;
        }

        // Add this completed batch to the list of completed batches. This list will then need to
        // be checked if any batches can be processed and verified for errors or invalid responses
        // from peers. The logic is simpler to create this ordered batch list and to then process
        // the list. 
        
        let insert_index = self.completed_batches.iter().position(|iter_batch| iter_batch.id > batch.id).unwrap_or_else(|| 0);
        self.completed_batches.insert(insert_index, batch);

        // We have a list of completed batches. It is not sufficient to process batch successfully
        // to consider the batch correct. This is because batches could be erroneously empty, or
        // incomplete. Therefore, a batch is considered valid, only if the next sequential batch is
        // processed successfully. Therefore the `completed_batches` will store batches that have
        // already be processed but not verified and therefore have Id's less than
        // `self.to_be_processed_id`.
        

        if self.state != SyncingState::Paused {

        // Try and process batches sequentially in the ordered list.
        let current_process_id = self.to_be_processed_id;
        for batch in self.completed_batches.iter().filter(|batch| batch.id >= current_process_id) {
            if batch.id == self.to_be_processed_id {
                if batch.downloaded_blocks.is_empty() {
                    // the batch was empty, progress to the next block
                    self.to_be_processed_id +=1;
                    continue;
                } else if self.process(chain, batch) {
                    // batch was successfully processed 
                    self.last_processed_id;
                    self.to_be_processed_id +=1;
                } else {
                    // batch processing failed
                    // this could be because this batch is invalid, or a previous invalidated batch
                    // is invalid. We need to find out which and downvote the peer that has sent us
                    // an invalid batch.
                    
                    // firstly remove any validated batches
                    self.completed_batches.retain(|batch| batch.id >= self.last_processed_id);
                    self.handle_invalid_batch(chain, network);
                    return;
                }
            } else {
                // there are no more batches to be processed, end
            break;
            }
        }
        // remove any validated batches 
        self.completed_batches.retain(|batch| batch.id >= self.last_processed_id);

        // check if the chain has completed syncing, if not, request another batch from this peer
        if self.start_slot + self.last_processed_id*BLOCKS_PER_REQUEST >= self.target_head_slot {
            // chain is completed
            return true;
        } else {
            self.send_range_request(network, peer_id);
            // chain is not completed
            return false;
        }
        }
        }

        fn handle_invalid_batch(network) {
            // The current batch could not be processed, indicating either the current or previous
            // batches are invalid

            // The previous batch could be
            // incomplete due to the block sizes being too large to fit in a single RPC
            // request or there could be consecutive empty batches which are not supposed to be
            
            // Prevent processing and downloading blocks from peers, whilst this is being resolved
            // self.state = SyncingChainState::Paused;
        }


        /*
                // empty. In this case we re-request backwards
                if let Some(batch) = self.pending_verification_batch.take() {
                    // find the latest downloaded slot
                    if !batch.downloaded_blocks.is_empty() {
                        let last_slot = batch.downloaded_blocks.iter().max_by_key(|block| block.slot).slot;
                        // this MUST be less than `batch.end_slot` otherwise this batch should never
                        // have been inserted into `pending_verification_batch`. We log a crit, to
                        // ensure.
                        if last_slot == batch.end_slot {
                            crit!(log, "Pending verified batch incorrectly added");
                            return;
                        }
                        batch.start_slot = last_slot+ 1;
                    }
                    // Start the batch from the last processed slot and retry with a different peer
                    // (if possible)
                    if self.peer_pool.len() > 1 {
                        let peer = self.peer_pool.iter().find(|peer| peer != batch.peer).expect("must be another peer");
                        self.batch.current_peer = peer.clone();
                    }
                    self.send_batch(batch);

                }
                */
                    
    pub fn stop_syncing(&mut self) {
        self.state = SyncingChainState::Stopped;
    }

    // Either a new chain, or an old one with a peer list
    pub fn start_syncing(&mut self, &mut network: NetworkContext, local_head_slot: Option<Slot>, log: &slog::Logger) {

        // A local head is provided for finalized chains, as other chains may have made
        // progress whilst this chain was Stopped. If so, update the `processed_batch_id` to
        // accommodate potentially downloaded batches from other chains. Also prune any old batches
        // awaiting processing
        if let Some(local_head) = local_head {
            
            // Only important if the local head is more than a batch worth of blocks ahead of
            // what this chain believes is downloaded
            if let Some(batches_ahead) = local_head_slot.sub(self.start_slot + self.last_processed_id*BLOCKS_PER_REQUEST).into().checked_rem(BLOCKS_PER_REQUEST) {
                // there are `batches_ahead` whole batches that have been downloaded by another
                // chain. Set the current processed_batch_id to this value.
                debug!(log, "Updating chains processed batches"; "old_completed_slot" => self.start_slot + self.processed_batches*BLOCKS_PER_REQUEST; "new_completed_slot" => self.start_slot + (self.last_processed_id + batches_ahead)*BLOCKS_PER_REQUEST);
                self.last_processed_id += batches_ahead;

                if self.last_processed_id*BLOCKS_PER_REQUEST > self.target_head_slot {
                    crit!(log, "Current head slot is above the target head - Coding error"); 
                    return;
                }

                // update the `to_be_downloaded_id`
                if self.to_be_downloaded_id < self.last_processed_id {
                    self.to_be_downloaded_id = self.last_processed_id;
                }

                self.completed_batch.retain(|batch| batch.id >= self.last_processed_id.saturating_sub(1));
            }
        }

        // Now begin requesting blocks from the peer pool. Ignore any peers with currently
        // pending requests
        let pending_peers = self.pending_batches.values().map(|batch| batch.current_peer).collect::<Vec<_>>();
        for peer_id in self.peer_pool.iter().filter(!peer| !pending_peers.contains(peer)) {
            // send a blocks by range request to the peer
            self.send_range_request(network, peer_id);
        };
    }

    // A peer has been added, start batch requests for this peer
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

    // Re-STATUS all the peers in this chain
    pub fn status_peers(&self, network: &mut SyncNetworkContext) {
        for peer_id in chain.peer_pool.iter() {
            network.status_peer(peer_id);
        }
    }

    fn send_range_request(&mut self, network: &mut SyncNetworkContext,  peer_id: PeerId) {
        // find the next pending batch and request it from the peer
        if let Some(batch) = self.get_next_batch(peer_id) {
            // send the batch
            self.send_batch(network, batch);
        }
    }

    fn send_batch(&mut self, network: &mut SyncNetworkContext,  batch: Batch) {

        let request = batch.to_blocks_by_range_request(); 
        let request_id = match network.blocks_by_range_request(batch.peer_id, request) {
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

    fn get_next_batch(&mut self, peer_id: PeerId) -> Option<Batch> {
        let batch_start_slot = self.start_slot + self.to_be_downloaded_id*BLOCKS_PER_REQUEST;
        if batch_start_slot > self.target_slot {
            return None;
        }
        let batch_end_slot = std::cmp::min(batch_start_slot + BLOCKS_PER_REQUEST - 1, self.target_slot);

        let batch_id = self.to_be_downloaded_id;
        // find the next batch id. The largest of the next sequential idea, of the next uncompleted
        // id
        let max_completed_id = self.completed_batches.iter().max_by_key(|batch| batch.id).unwrap_or_else(|| 0);
        self.to_be_downloaded_id = std::cmp::max(self.to_be_downloaded_id +1, max_completed_id + 1)

        Some(Batch::new(batch_id, batch_start_slot, batch_end_slot, peer_id))
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

struct RangeSync<T: EthSpec> {
    /// The beacon chain for processing
    chain: Weak<BeaconChain<T>>,
    /// A network context that provides the ability to send RPC requests/responses and handles a
    /// global request id for the syncing thread.
//    network: &'a mut SyncNetworkContext,
    /// The current state of the RangeSync
    state: SyncState,
    /// A collection of finalized chains that need to be downloaded.
    finalized_chains: Vec<SyncingChain>,
    /// A collection of head chains that need to be downloaded.
    head_chains: Vec<SyncingChain>,
    /// Known peers to the RangeSync, that need to be re-status'd once finalized chains are
    /// completed.
    awaiting_head_peers: HashSet<PeerId>,
    log: slog::Logger,
}


impl<T: EthSpec> RangeSync<T> {

    pub fn new(chain: Weak<BeaconChain<T>>, log: slog::Logger) -> Self {
        RangeSync {
            chain, 
            state: SyncState::Idle,
            finalized_chains: Vec::new(),
            head_chains: Vec::new(),
            awaiting_head_peers: HashSet::new(),
            log,
        }
    }

        pub fn add_peer(&mut self, network: &mut SyncNetworkContext, peer_id: PeerId, remote: PeerSyncInfo) {

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

                // This chain will only have a single peer, and will only become the syncing chain
                // if no other chain exists
                if self.finalized_chains.len() == 1 {
                    self.finalized_chains[0].start_syncing(local_finalized_slot);
                }
            }
        } else {
            if !self.finalized_chains.is_empty() {
                // If there are finalized chains to sync, finish these first, before syncing head
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
            // There are no other head chains that match this peers status, create a new one, and
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


    pub fn on_range_response(peer_id: PeerId, request_id: RequestId, beacon_block: Option<BeaconBlock>) {

        // Find the request. Most likely the first finalized chain (the syncing chain). If there
        // are no finalized chains, then it will be a head chain. At most, there should only be
        // `connected_peers` number of head chains, which should be relatively small and this
        // lookup should not be very expensive. However, we could add an extra index that maps the
        // request id to index of the vector to avoid O(N) searches and O(N) hash lookups.
        // Note to future sync-rewriter/profiler: Michael approves of these O(N) searches. 

        let mut update_finalized = false;
        if let Some((index, chain)) = self.finalized_chains.iter_mut().enumerate().find_map(|(index, chain)| Some(index, chain.pending_batches.get(&request_id)?)) {
            // The request was associated with a finalized chain. We do two hashmap lookups to
            // allow for code simplicity and allow the processing to occur on a `SyncingChain`
            // struct.
            // Process the response
            if chain.on_block_response(network, request_id, beacon_block) {
                // the chain is complete, re-status it's peers and remove it
                chain.status_peer();

                // flag to start syncing a new chain as the current completed chain was the
                // syncing chain
                if index == 0 {
                    update_finalized = true;
                }
                self.finalized_chains.swap_remove(index);
            }
        } else if let Some((index, chain)) = self.head_chains.iter_mut().enumerate().find_map(|(index, chain)| Some(index, chain.pending_batches.get(&request_id)?)) {
            // The request was associated with a head chain.
            // Process the completed request for the head chain.
            if chain.on_block_response(self.network, request_id, beacon_block) {
                // the chain is complete, re-status it's peers and remove it
                chain.status_peers(network);

                self.head_chains.swap_remove(index);
            }
        } else {
            // The request didn't exist in any `SyncingChain`. Could have been an old request. Log
            // and ignore
            debug!(self.log, "Range response without matching request"; "peer" => format!("{:?}", peer_id); "request_id" => request_id);
        }

        // if a finalized chain has completed, check to see if a new chain needs to start syncing
        if update_finalized {

            // remove any out-dated finalized chains, re statusing their peers.
            let local_info = match self.chain.upgrade() {
                Some(chain) => PeerSynfInfo::from(chain),
                None => {
                    warn!(self.log,
                          "Beacon chain dropped. Not starting a new sync chain";
                          "peer_id" => format!("{:?}", peer_id));
                    return;
                }
            };
            self.finalized_chains.retain(|chain| {
                if chain.target_slot <= local_info.head_slot { 
                    chain.status_peers();
                    false
                } else {true }});

            // check if there is a new finalized_chain 
            if let Some(index) = self.finalized_chains.iter().enumerate().max_by_key(|(index,chain)| chain.peer_pool.len()).map(|(index,chain)| index) {
                // new syncing chain, begin syncing
                let new_chain = self.finalized_chains.swap_remove(index);
                self.finalized_chains.insert(0, new_chain);
                let local_finalized_slot = local_info.finalized_epoch.start_slot(T::slots_per_epoch());
                self.finalized_chains[0].start_syncing(local_finalized_slot);
            } else {
                // there is no new finalized_chain, this was the last, re-status all head_peers to
                // begin a head sync
                for peer in self.awaiting_head_peers {
                    network.status_peer(peer_id);
                }
            }

        }

        }

        pub fn is_syncing(&self) -> bool {
            match self.state {
                SyncState::Finalized => true,
                SyncState::Head => true,
                SyncState::Idle => false,
            }
        }

        // if a peer disconnects, re-evaluate which chain to sync
        pub fn peer_disconnect(&mut self, peer_id: PeerId) { }

        // TODO: Write this
        pub fn inject_error(&mut self, peer_id: PeerId, request_id: RequestId) {
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





