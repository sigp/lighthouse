use crate::sync::message_processor::FUTURE_SLOT_TOLERANCE;
use crate::sync::network_context::SyncNetworkContext;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::rpc::methods::*;
use eth2_libp2p::rpc::RequestId;
use eth2_libp2p::PeerId;
use fnv::FnvHashMap;
use slog::{crit, debug, info, trace, warn, Logger};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::ops::Sub;
use std::sync::Weak;
use types::{BeaconBlock, EthSpec, Hash256, Slot};

/// Blocks are downloaded in batches from peers. This constant specifies how many blocks per batch
/// is requested. There is a timeout for each batch request. If this value is too high, we will
/// downvote peers with poor bandwidth. This can be set arbitrarily high, in which case the
/// responder will fill the response up to the max request size, assuming they have the bandwidth
/// to do so.
//TODO: Make this dynamic based on peer's bandwidth
const BLOCKS_PER_REQUEST: u64 = 50;

#[derive(PartialEq)]
pub struct Batch<T: EthSpec> {
    /// The ID of the batch, batches are ID's sequentially.
    id: u64,
    /// The requested start slot of the batch, inclusive.
    start_slot: Slot,
    /// The requested end slot of batch, exclusive.
    end_slot: Slot,
    /// The hash of the chain root to requested from the peer.
    head_root: Hash256,
    /// The peer that was originally assigned to the batch.
    _original_peer: PeerId,
    /// The peer that is currently assigned to the batch.
    current_peer: PeerId,
    /// The number of retries this batch has undergone.
    _retries: u8,
    /// The blocks that have been downloaded.
    downloaded_blocks: Vec<BeaconBlock<T>>,
}

impl<T: EthSpec> Ord for Batch<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.id.cmp(&other.id)
    }
}

impl<T: EthSpec> PartialOrd for Batch<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: EthSpec> Eq for Batch<T> {}

impl<T: EthSpec> Batch<T> {
    fn new(id: u64, start_slot: Slot, end_slot: Slot, head_root: Hash256, peer_id: PeerId) -> Self {
        Batch {
            id,
            start_slot,
            end_slot,
            head_root,
            _original_peer: peer_id.clone(),
            current_peer: peer_id,
            _retries: 0,
            downloaded_blocks: Vec::new(),
        }
    }

    fn to_blocks_by_range_request(&self) -> BlocksByRangeRequest {
        BlocksByRangeRequest {
            head_block_root: self.head_root,
            start_slot: self.start_slot.into(),
            count: std::cmp::min(
                BLOCKS_PER_REQUEST,
                self.end_slot.sub(self.start_slot).into(),
            ),
            step: 1,
        }
    }
}

pub struct SyncingChain<T: BeaconChainTypes> {
    /// The original start slot when this chain was initialised.
    pub start_slot: Slot,

    /// The target head slot.
    pub target_head_slot: Slot,

    /// The target head root.
    pub target_head_root: Hash256,

    /// The batches that are currently awaiting a response from a peer. An RPC request for these
    /// have been sent.
    pub pending_batches: FnvHashMap<RequestId, Batch<T::EthSpec>>,

    /// The batches that have been downloaded and are awaiting processing and/or validation.
    completed_batches: Vec<Batch<T::EthSpec>>,

    /// The peers that agree on the `target_head_slot` and `target_head_root` as a canonical chain
    /// and thus available to download this chain from.
    pub peer_pool: HashSet<PeerId>,

    /// The next batch_id that needs to be downloaded.
    to_be_downloaded_id: u64,

    /// The next batch id that needs to be processed.
    to_be_processed_id: u64,

    /// The last batch id that was processed.
    last_processed_id: u64,

    /// The current state of the chain.
    state: ChainSyncingState,
}

#[derive(PartialEq)]
pub enum ChainSyncingState {
    /// The chain is not being synced.
    Stopped,
    /// The chain is undergoing syncing.
    Syncing,
    /// The chain is temporarily paused whilst an error is rectified.
    Paused,
}

impl<T: BeaconChainTypes> SyncingChain<T> {
    pub fn new(
        start_slot: Slot,
        target_head_slot: Slot,
        target_head_root: Hash256,
        peer_id: PeerId,
    ) -> Self {
        let mut peer_pool = HashSet::new();
        peer_pool.insert(peer_id);

        SyncingChain {
            start_slot,
            target_head_slot,
            target_head_root,
            pending_batches: FnvHashMap::default(),
            completed_batches: Vec::new(),
            peer_pool,
            to_be_downloaded_id: 1,
            to_be_processed_id: 1,
            last_processed_id: 0,
            state: ChainSyncingState::Stopped,
        }
    }

    pub fn on_block_response(
        &mut self,
        chain: Weak<BeaconChain<T>>,
        network: &mut SyncNetworkContext,
        request_id: RequestId,
        beacon_block: Option<BeaconBlock<T::EthSpec>>,
        log: &slog::Logger,
    ) -> bool {
        // returns true if this response completes the chain

        // If this is not a stream termination, simply add the block to the request
        if let Some(block) = beacon_block {
            match self.pending_batches.get_mut(&request_id) {
                Some(batch) => batch.downloaded_blocks.push(block),
                None => {
                    // the request must exist before this function is called
                    crit!(log, "Request doesn't exist - coding error");
                }
            };
            return false;
        } else {
            // A stream termination has been sent. This batch has ended. Process a completed batch.
            let batch = match self.pending_batches.remove(&request_id) {
                Some(batch) => batch,
                None => {
                    // the request must exist before this function is called
                    crit!(log, "Request doesn't exist - coding error");
                    return false;
                }
            };
            self.process_completed_batch(chain, network, batch, log)
        }
    }

    fn process_completed_batch(
        &mut self,
        chain: Weak<BeaconChain<T>>,
        network: &mut SyncNetworkContext,
        batch: Batch<T::EthSpec>,
        log: &slog::Logger,
    ) -> bool {
        // An entire batch of blocks has been received. This functions checks to see if it can be processed,
        // remove any batches waiting to be verified and if this chain is syncing, request new
        // blocks for the peer.
        warn!(log, "Completed batch received"; "id"=>batch.id, "blocks"=>batch.downloaded_blocks.len(), "awaiting_batches" => self.completed_batches.len());

        // The peer that completed this batch, may be re-requested if this batch doesn't complete
        // the chain and there is no error in processing
        let current_peer = batch.current_peer.clone();

        // verify the range of received blocks
        // Note that the order of blocks is verified in block processing
        if let Some(last_slot) = batch.downloaded_blocks.last().map(|b| b.slot) {
            // the batch is non-empty
            if batch.start_slot > batch.downloaded_blocks[0].slot || batch.end_slot < last_slot {
                warn!(log, "BlocksByRange response returned out of range blocks"; 
                          "response_initial_slot" => batch.downloaded_blocks[0].slot, 
                          "requested_initial_slot" => batch.start_slot);
                network.downvote_peer(batch.current_peer);
                self.to_be_processed_id = batch.id; // reset the id back to here, when incrementing, it will check against completed batches
                return false;
            }
        }

        // Add this completed batch to the list of completed batches. This list will then need to
        // be checked if any batches can be processed and verified for errors or invalid responses
        // from peers. The logic is simpler to create this ordered batch list and to then process
        // the list.

        let insert_index = self
            .completed_batches
            .binary_search(&batch)
            .unwrap_or_else(|index| index);
        self.completed_batches.insert(insert_index, batch);

        // We have a list of completed batches. It is not sufficient to process batch successfully
        // to consider the batch correct. This is because batches could be erroneously empty, or
        // incomplete. Therefore, a batch is considered valid, only if the next sequential batch is
        // processed successfully. Therefore the `completed_batches` will store batches that have
        // already be processed but not verified and therefore have Id's less than
        // `self.to_be_processed_id`.

        //TODO: Run the processing of blocks in a separate thread. Build a queue of completed
        //blocks here, manage the queue and process them in another thread as they become
        //available.

        if self.state != ChainSyncingState::Paused {
            // pre-emptively request more blocks from peers whilst we process current blocks,
            self.send_range_request(network, current_peer);

            // Try and process batches sequentially in the ordered list.
            let current_process_id = self.to_be_processed_id;
            for batch in self
                .completed_batches
                .iter()
                .filter(|batch| batch.id >= current_process_id)
            {
                if batch.id == self.to_be_processed_id {
                    if batch.downloaded_blocks.is_empty() {
                        // the batch was empty, progress to the next block
                        self.to_be_processed_id += 1;
                        continue;
                    } else {
                        warn!(log, "Processing batch"; "batch_id" => batch.id);
                        match process_batch(chain.clone(), batch, log) {
                            Ok(_) => {
                                info!(log, "Blocks Processed"; "current_slot" => batch.end_slot);
                                // batch was successfully processed
                                self.last_processed_id = self.to_be_processed_id;
                                self.to_be_processed_id += 1;
                            }
                            Err(e) => {
                                warn!(log, "Block processing error"; "error"=> format!("{:?}", e));
                                // batch processing failed
                                // this could be because this batch is invalid, or a previous invalidated batch
                                // is invalid. We need to find out which and downvote the peer that has sent us
                                // an invalid batch.

                                // firstly remove any validated batches
                                self.handle_invalid_batch(chain, network);
                                break;
                            }
                        }
                    }
                } else {
                    // there are no more batches to be processed, end
                    break;
                }
            }
            // remove any validated batches
            let last_processed_id = self.last_processed_id;
            self.completed_batches
                .retain(|batch| batch.id >= last_processed_id);

            // check if the chain has completed syncing, if not, request another batch from this peer
            if self.start_slot + self.last_processed_id * BLOCKS_PER_REQUEST
                >= self.target_head_slot
            {
                // chain is completed
                true
            } else {
                // chain is not completed
                false
            }
        } else {
            false
        }
    }

    fn handle_invalid_batch(
        &mut self,
        _chain: Weak<BeaconChain<T>>,
        _network: &mut SyncNetworkContext,
    ) {
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
        self.state = ChainSyncingState::Stopped;
    }

    // Either a new chain, or an old one with a peer list
    pub fn start_syncing(
        &mut self,
        network: &mut SyncNetworkContext,
        local_finalized_slot: Slot,
        log: &slog::Logger,
    ) {
        // A local finalized slot is provided as other chains may have made
        // progress whilst this chain was Stopped or paused. If so, update the `processed_batch_id` to
        // accommodate potentially downloaded batches from other chains. Also prune any old batches
        // awaiting processing

        // Only important if the local head is more than a batch worth of blocks ahead of
        // what this chain believes is downloaded
        let batches_ahead = local_finalized_slot
            .as_u64()
            .saturating_sub(self.start_slot.as_u64() + self.last_processed_id * BLOCKS_PER_REQUEST)
            .checked_rem(BLOCKS_PER_REQUEST)
            .expect("BLOCKS_PER_REQUEST cannot be 0");

        if batches_ahead != 0 {
            // there are `batches_ahead` whole batches that have been downloaded by another
            // chain. Set the current processed_batch_id to this value.
            debug!(log, "Updating chains processed batches"; "old_completed_slot" => self.start_slot + self.last_processed_id*BLOCKS_PER_REQUEST, "new_completed_slot" => self.start_slot + (self.last_processed_id + batches_ahead)*BLOCKS_PER_REQUEST);
            self.last_processed_id += batches_ahead;

            if self.last_processed_id * BLOCKS_PER_REQUEST > self.target_head_slot.as_u64() {
                crit!(
                    log,
                    "Current head slot is above the target head - Coding error"
                );
                return;
            }

            // update the `to_be_downloaded_id`
            if self.to_be_downloaded_id < self.last_processed_id {
                self.to_be_downloaded_id = self.last_processed_id;
            }

            let last_processed_id = self.last_processed_id;
            self.completed_batches
                .retain(|batch| batch.id >= last_processed_id.saturating_sub(1));
        }

        // Now begin requesting blocks from the peer pool. Ignore any peers with currently
        // pending requests
        let pending_peers = self
            .pending_batches
            .values()
            .map(|batch| batch.current_peer.clone())
            .collect::<Vec<_>>();

        let peers = self
            .peer_pool
            .iter()
            .filter(|peer| !pending_peers.contains(peer))
            .cloned()
            .collect::<Vec<_>>();

        for peer_id in peers {
            // send a blocks by range request to the peer
            self.send_range_request(network, peer_id);
        }

        self.state = ChainSyncingState::Syncing;
    }

    // A peer has been added, start batch requests for this peer
    // this should only be called for a syncing chain
    pub fn peer_added(
        &mut self,
        network: &mut SyncNetworkContext,
        peer_id: PeerId,
        log: &slog::Logger,
    ) {
        // function should only be called on syncing chains
        if let ChainSyncingState::Stopped = self.state {
            crit!(log, "Peer added to a non-syncing chain"; "peer_id" => format!("{:?}", peer_id));
            return;
        }

        // find the next batch and request it from the peer
        self.send_range_request(network, peer_id);
    }

    // Re-STATUS all the peers in this chain
    pub fn status_peers(&self, chain: Weak<BeaconChain<T>>, network: &mut SyncNetworkContext) {
        for peer_id in self.peer_pool.iter() {
            network.status_peer(chain.clone(), peer_id.clone());
        }
    }

    fn send_range_request(&mut self, network: &mut SyncNetworkContext, peer_id: PeerId) {
        // find the next pending batch and request it from the peer
        if let Some(batch) = self.get_next_batch(peer_id) {
            // send the batch
            self.send_batch(network, batch);
        }
    }

    fn send_batch(&mut self, network: &mut SyncNetworkContext, batch: Batch<T::EthSpec>) {
        let request = batch.to_blocks_by_range_request();
        if let Ok(request_id) = network.blocks_by_range_request(batch.current_peer.clone(), request)
        {
            // add the batch to pending list
            self.pending_batches.insert(request_id, batch);
        }
    }

    fn get_next_batch(&mut self, peer_id: PeerId) -> Option<Batch<T::EthSpec>> {
        let batch_start_slot =
            self.start_slot + self.to_be_downloaded_id.saturating_sub(1) * BLOCKS_PER_REQUEST;
        if batch_start_slot > self.target_head_slot {
            return None;
        }
        let batch_end_slot = std::cmp::min(
            batch_start_slot + BLOCKS_PER_REQUEST,
            self.target_head_slot.saturating_add(1u64),
        );

        let batch_id = self.to_be_downloaded_id;
        // find the next batch id. The largest of the next sequential idea, of the next uncompleted
        // id
        let max_completed_id =
            self.completed_batches
                .iter()
                .fold(0, |max, batch| if batch.id > max { batch.id } else { max });
        self.to_be_downloaded_id =
            std::cmp::max(self.to_be_downloaded_id + 1, max_completed_id + 1);

        Some(Batch::new(
            batch_id,
            batch_start_slot,
            batch_end_slot,
            self.target_head_root,
            peer_id,
        ))
    }
}

// Helper function to process block batches which only consumes the chain and blocks to process
fn process_batch<T: BeaconChainTypes>(
    chain: Weak<BeaconChain<T>>,
    batch: &Batch<T::EthSpec>,
    log: &Logger,
) -> Result<(), String> {
    for block in &batch.downloaded_blocks {
        if let Some(chain) = chain.upgrade() {
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
