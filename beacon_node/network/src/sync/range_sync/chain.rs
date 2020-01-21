use super::batch::{Batch, BatchId, PendingBatches};
use super::batch_processing::{spawn_batch_processor, BatchProcessResult};
use crate::sync::network_context::SyncNetworkContext;
use crate::sync::SyncMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::rpc::RequestId;
use eth2_libp2p::PeerId;
use rand::prelude::*;
use slog::{crit, debug, warn};
use std::collections::HashSet;
use std::sync::{Arc, Weak};
use tokio::sync::mpsc;
use types::{BeaconBlock, Hash256, Slot};

/// Blocks are downloaded in batches from peers. This constant specifies how many blocks per batch
/// is requested. There is a timeout for each batch request. If this value is too high, we will
/// downvote peers with poor bandwidth. This can be set arbitrarily high, in which case the
/// responder will fill the response up to the max request size, assuming they have the bandwidth
/// to do so.
//TODO: Make this dynamic based on peer's bandwidth
//TODO: This is lower due to current thread design. Modify once rebuilt.
pub const BLOCKS_PER_BATCH: u64 = 50;

/// The number of times to retry a batch before the chain is considered failed and removed.
const MAX_BATCH_RETRIES: u8 = 5;

/// The maximum number of batches to queue before requesting more.
const BATCH_BUFFER_SIZE: u8 = 5;

/// A return type for functions that act on a `Chain` which informs the caller whether the chain
/// has been completed and should be removed or to be kept if further processing is
/// required.
pub enum ProcessingResult {
    KeepChain,
    RemoveChain,
}

/// A chain of blocks that need to be downloaded. Peers who claim to contain the target head
/// root are grouped into the peer pool and queried for batches when downloading the
/// chain.
pub struct SyncingChain<T: BeaconChainTypes> {
    /// The original start slot when this chain was initialised.
    pub start_slot: Slot,

    /// The target head slot.
    pub target_head_slot: Slot,

    /// The target head root.
    pub target_head_root: Hash256,

    /// The batches that are currently awaiting a response from a peer. An RPC request for these
    /// have been sent.
    pub pending_batches: PendingBatches<T::EthSpec>,

    /// The batches that have been downloaded and are awaiting processing and/or validation.
    completed_batches: Vec<Batch<T::EthSpec>>,

    /// Batches that have been processed and awaiting validation before being removed.
    processed_batches: Vec<Arc<Batch<T::EthSpec>>>,

    /// The peers that agree on the `target_head_slot` and `target_head_root` as a canonical chain
    /// and thus available to download this chain from.
    pub peer_pool: HashSet<PeerId>,

    /// The next batch_id that needs to be downloaded.
    to_be_downloaded_id: BatchId,

    /// The next batch id that needs to be processed.
    to_be_processed_id: BatchId,

    /// The last batch id that was processed.
    last_processed_id: BatchId,

    /// The current state of the chain.
    pub state: ChainSyncingState,

    /// A random id given to a batch process request. This is None if there is no ongoing batch
    /// process.
    current_processing_id: Option<u64>,

    /// A send channel to the sync manager. This is given to the batch processor thread to report
    /// back once batch processing has completed.
    sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,

    chain: Weak<BeaconChain<T>>,

    /// A reference to the sync logger.
    log: slog::Logger,
}

#[derive(PartialEq)]
pub enum ChainSyncingState {
    /// The chain is not being synced.
    Stopped,
    /// The chain is undergoing syncing.
    Syncing,
    /// The chain is temporarily paused whilst an error is rectified.
    _Paused,
}

impl<T: BeaconChainTypes> SyncingChain<T> {
    pub fn new(
        start_slot: Slot,
        target_head_slot: Slot,
        target_head_root: Hash256,
        peer_id: PeerId,
        sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
        chain: Weak<BeaconChain<T>>,
        log: slog::Logger,
    ) -> Self {
        let mut peer_pool = HashSet::new();
        peer_pool.insert(peer_id);

        SyncingChain {
            start_slot,
            target_head_slot,
            target_head_root,
            pending_batches: PendingBatches::new(),
            completed_batches: Vec::new(),
            processed_batches: Vec::new(),
            peer_pool,
            to_be_downloaded_id: BatchId(1),
            to_be_processed_id: BatchId(1),
            last_processed_id: BatchId(0),
            state: ChainSyncingState::Stopped,
            current_processing_id: None,
            sync_send,
            chain,
            log,
        }
    }

    /// A batch of blocks has been received. This function gets run on all chains and should
    /// return Some if the request id matches a pending request on this chain, or None if it does
    /// not.
    ///
    /// If the request corresponds to a pending batch, this function processes the completed
    /// batch.
    pub fn on_block_response(
        &mut self,
        network: &mut SyncNetworkContext,
        request_id: RequestId,
        beacon_block: &Option<BeaconBlock<T::EthSpec>>,
    ) -> Option<()> {
        if let Some(block) = beacon_block {
            // This is not a stream termination, simply add the block to the request
            self.pending_batches.add_block(&request_id, block.clone())
        } else {
            // A stream termination has been sent. This batch has ended. Process a completed batch.
            let batch = self.pending_batches.remove(&request_id)?;
            Some(self.handle_completed_batch(network, batch))
        }
    }

    /// A completed batch has been received, process the batch.
    /// This will return `ProcessingResult::KeepChain` if the chain has not completed or
    /// failed indicating that further batches are required.
    fn handle_completed_batch(
        &mut self,
        network: &mut SyncNetworkContext,
        batch: Batch<T::EthSpec>,
    ) {
        // An entire batch of blocks has been received. This functions checks to see if it can be processed,
        // remove any batches waiting to be verified and if this chain is syncing, request new
        // blocks for the peer.
        debug!(self.log, "Completed batch received"; "id"=> *batch.id, "blocks"=>batch.downloaded_blocks.len(), "awaiting_batches" => self.completed_batches.len());

        // verify the range of received blocks
        // Note that the order of blocks is verified in block processing
        if let Some(last_slot) = batch.downloaded_blocks.last().map(|b| b.slot) {
            // the batch is non-empty
            if batch.start_slot > batch.downloaded_blocks[0].slot || batch.end_slot < last_slot {
                warn!(self.log, "BlocksByRange response returned out of range blocks"; 
                          "response_initial_slot" => batch.downloaded_blocks[0].slot, 
                          "requested_initial_slot" => batch.start_slot);
                network.downvote_peer(batch.current_peer);
                self.to_be_processed_id = batch.id; // reset the id back to here, when incrementing, it will check against completed batches
                return;
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

        // pre-emptively request more blocks from peers whilst we process current blocks,
        self.request_batches(network);

        // Try and process any completed batches. This will spawn a new task to process any blocks
        // that are ready to be processed.
        self.process_completed_batches();
    }

    /// Tries to process any batches if there are any available and we are not currently processing
    /// other batches.
    fn process_completed_batches(&mut self) {
        // Only process one batch at a time
        if self.current_processing_id.is_some() {
            return;
        }

        // Check if the next batch is to be processed
        while !self.completed_batches.is_empty()
            && self.completed_batches[0].id == self.to_be_processed_id
        {
            let batch = self.completed_batches.remove(0);
            if batch.downloaded_blocks.is_empty() {
                // The batch was empty, consider this processed and move to the next batch
                self.processed_batches.push(Arc::new(batch));
                *self.to_be_processed_id += 1;
                continue;
            }

            // send the batch to the batch processor thread
            return self.process_batch(batch);
        }
    }

    /// Sends a batch to the batch processor.
    fn process_batch(&mut self, batch: Batch<T::EthSpec>) {
        let batch = Arc::new(batch);
        // only spawn one instance at a time
        let processing_id: u64 = rand::random();
        self.current_processing_id = Some(processing_id);
        spawn_batch_processor(
            self.chain.clone(),
            processing_id,
            batch,
            self.sync_send.clone(),
            self.log.clone(),
        );
    }

    /// The block processor has completed processing a batch. This function handles the result
    /// of the batch processor.
    pub fn on_batch_process_result(
        &mut self,
        network: &mut SyncNetworkContext,
        processing_id: u64,
        batch: Arc<Batch<T::EthSpec>>,
        result: &BatchProcessResult,
    ) -> Option<ProcessingResult> {
        if Some(processing_id) != self.current_processing_id {
            // batch process doesn't belong to this chain
            return None;
        }

        // double check batches are processed in order
        // TODO: Remove for prod
        if batch.id != self.to_be_processed_id {
            crit!(self.log, "Batch processed out of order"; "processed_batch_id" => *batch.id, "expected_id" => *self.to_be_processed_id);
        }

        self.current_processing_id = None;

        let res = match result {
            BatchProcessResult::Success => {
                *self.to_be_processed_id += 1;
                // This variable accounts for skip slots and batches that were not actually
                // processed due to having no blocks.
                self.last_processed_id = batch.id;

                // remove any validated batches
                let last_processed_id = self.last_processed_id;
                self.processed_batches
                    .retain(|batch| batch.id.0 >= last_processed_id.0);

                // add the current batch to finalized batches to be removed.
                self.processed_batches.push(batch);

                // check if the chain has completed syncing
                if self.start_slot + *self.last_processed_id * BLOCKS_PER_BATCH
                    >= self.target_head_slot
                {
                    // chain is completed
                    ProcessingResult::RemoveChain
                } else {
                    // chain is not completed

                    // attempt to request more batches
                    self.request_batches(network);

                    // attempt to process more batches
                    self.process_completed_batches();

                    // keep the chain
                    ProcessingResult::KeepChain
                }
            }
            BatchProcessResult::Failed => {
                // batch processing failed
                // this could be because this batch is invalid, or a previous invalidated batch
                // is invalid. We need to find out which and downvote the peer that has sent us
                // an invalid batch.

                // firstly remove any validated batches
                self.handle_invalid_batch(network)
            }
        };

        Some(res)
    }

    pub fn stop_syncing(&mut self) {
        self.state = ChainSyncingState::Stopped;
    }

    // Either a new chain, or an old one with a peer list
    /// This chain has been requested to start syncing.
    ///
    /// This could be new chain, or an old chain that is being resumed.
    pub fn start_syncing(&mut self, network: &mut SyncNetworkContext, local_finalized_slot: Slot) {
        // A local finalized slot is provided as other chains may have made
        // progress whilst this chain was Stopped or paused. If so, update the `processed_batch_id` to
        // accommodate potentially downloaded batches from other chains. Also prune any old batches
        // awaiting processing

        // Only important if the local head is more than a batch worth of blocks ahead of
        // what this chain believes is downloaded
        let batches_ahead = local_finalized_slot
            .as_u64()
            .saturating_sub(self.start_slot.as_u64() + *self.last_processed_id * BLOCKS_PER_BATCH)
            / BLOCKS_PER_BATCH;

        if batches_ahead != 0 {
            // there are `batches_ahead` whole batches that have been downloaded by another
            // chain. Set the current processed_batch_id to this value.
            debug!(self.log, "Updating chains processed batches"; "old_completed_slot" => self.start_slot + *self.last_processed_id*BLOCKS_PER_BATCH, "new_completed_slot" => self.start_slot + (*self.last_processed_id + batches_ahead)*BLOCKS_PER_BATCH);
            self.last_processed_id.0 += batches_ahead;

            if self.start_slot + *self.last_processed_id * BLOCKS_PER_BATCH
                > self.target_head_slot.as_u64()
            {
                crit!(
                    self.log,
                    "Current head slot is above the target head";
                    "target_head_slot" => self.target_head_slot.as_u64(),
                    "new_start" => self.start_slot + *self.last_processed_id * BLOCKS_PER_BATCH,
                );
                return;
            }

            // update the `to_be_downloaded_id`
            if self.to_be_downloaded_id.0 < self.last_processed_id.0 {
                self.to_be_downloaded_id = self.last_processed_id;
            }

            let last_processed_id = self.last_processed_id;
            self.completed_batches
                .retain(|batch| batch.id.0 > last_processed_id.0);
            self.processed_batches
                .retain(|batch| batch.id.0 >= last_processed_id.0);
        }

        // start processing batches if needed
        self.process_completed_batches();

        self.state = ChainSyncingState::Syncing;

        // begin requesting blocks from the peer pool, until all peers are exhausted.
        self.request_batches(network);
    }

    /// Add a peer to the chain.
    ///
    /// If the chain is active, this starts requesting batches from this peer.
    pub fn add_peer(&mut self, network: &mut SyncNetworkContext, peer_id: PeerId) {
        self.peer_pool.insert(peer_id.clone());
        // do not request blocks if the chain is not syncing
        if let ChainSyncingState::Stopped = self.state {
            debug!(self.log, "Peer added to a non-syncing chain"; "peer_id" => format!("{:?}", peer_id));
            return;
        }

        // find the next batch and request it from any peers if we need to
        self.request_batches(network);
    }

    /// Sends a STATUS message to all peers in the peer pool.
    pub fn status_peers(&self, network: &mut SyncNetworkContext) {
        for peer_id in self.peer_pool.iter() {
            network.status_peer(self.chain.clone(), peer_id.clone());
        }
    }

    /// An RPC error has occurred.
    ///
    /// Checks if the request_id is associated with this chain. If so, attempts to re-request the
    /// batch. If the batch has exceeded the number of retries, returns
    /// Some(`ProcessingResult::RemoveChain)`. Returns `None` if the request isn't related to
    /// this chain.
    pub fn inject_error(
        &mut self,
        network: &mut SyncNetworkContext,
        peer_id: &PeerId,
        request_id: &RequestId,
    ) -> Option<ProcessingResult> {
        if let Some(batch) = self.pending_batches.remove(&request_id) {
            warn!(self.log, "Batch failed. RPC Error"; "id" => *batch.id, "retries" => batch.retries, "peer" => format!("{:?}", peer_id));

            Some(self.failed_batch(network, batch))
        } else {
            None
        }
    }

    /// A batch has failed.
    ///
    /// Attempts to re-request from another peer in the peer pool (if possible) and returns
    /// `ProcessingResult::RemoveChain` if the number of retries on the batch exceeds
    /// `MAX_BATCH_RETRIES`.
    pub fn failed_batch(
        &mut self,
        network: &mut SyncNetworkContext,
        mut batch: Batch<T::EthSpec>,
    ) -> ProcessingResult {
        batch.retries += 1;

        // TODO: Handle partially downloaded batches. Update this when building a new batch
        // processor thread.

        if batch.retries > MAX_BATCH_RETRIES {
            // chain is unrecoverable, remove it
            ProcessingResult::RemoveChain
        } else {
            // try to re-process the request using a different peer, if possible
            let current_peer = &batch.current_peer;
            let new_peer = self
                .peer_pool
                .iter()
                .find(|peer| *peer != current_peer)
                .unwrap_or_else(|| current_peer);

            batch.current_peer = new_peer.clone();
            debug!(self.log, "Re-Requesting batch"; "start_slot" => batch.start_slot, "end_slot" => batch.end_slot, "id" => *batch.id, "peer" => format!("{:?}", batch.current_peer), "head_root"=> format!("{}", batch.head_root));
            self.send_batch(network, batch);
            ProcessingResult::KeepChain
        }
    }

    /// An invalid batch has been received that could not be processed.
    fn handle_invalid_batch(&mut self, network: &mut SyncNetworkContext) -> ProcessingResult {
        // The current batch could not be processed, indicating either the current or previous
        // batches are invalid

        // The previous batch could be
        // incomplete due to the block sizes being too large to fit in a single RPC
        // request or there could be consecutive empty batches which are not supposed to be there

        // Address these two cases individually.
        // Firstly, check if the past batch is invalid.
        //

        //TODO: Implement this logic
        // Currently just fail the chain, and drop all associated peers, removing them from the
        // peer pool, to prevent re-status
        for peer_id in self.peer_pool.drain() {
            network.downvote_peer(peer_id);
        }
        ProcessingResult::RemoveChain
    }

    /// Attempts to request the next required batches from the peer pool if the chain is syncing. It will exhaust the peer
    /// pool and left over batches until the batch buffer is reached or all peers are exhausted.
    fn request_batches(&mut self, network: &mut SyncNetworkContext) {
        if let ChainSyncingState::Syncing = self.state {
            while self.send_range_request(network) {}
        }
    }

    /// Requests the next required batch from a peer. Returns true, if there was a peer available
    /// to send a request and there are batches to request, false otherwise.
    fn send_range_request(&mut self, network: &mut SyncNetworkContext) -> bool {
        // find the next pending batch and request it from the peer
        if let Some(peer_id) = self.get_next_peer() {
            if let Some(batch) = self.get_next_batch(peer_id) {
                debug!(self.log, "Requesting batch"; "start_slot" => batch.start_slot, "end_slot" => batch.end_slot, "id" => *batch.id, "peer" => format!("{:?}", batch.current_peer), "head_root"=> format!("{}", batch.head_root));
                // send the batch
                self.send_batch(network, batch);
                return true;
            }
        }
        return false;
    }

    /// Returns a peer if there exists a peer which does not currently have a pending request.
    ///
    /// This is used to create the next request.
    fn get_next_peer(&self) -> Option<PeerId> {
        // randomize the peers for load balancing
        let mut rng = rand::thread_rng();
        let mut peers = self.peer_pool.iter().collect::<Vec<_>>();
        peers.shuffle(&mut rng);
        for peer in peers {
            if self.pending_batches.peer_is_idle(peer) {
                return Some(peer.clone());
            }
        }
        None
    }

    /// Returns the next required batch from the chain if it exists. If there are no more batches
    /// required, `None` is returned.
    fn get_next_batch(&mut self, peer_id: PeerId) -> Option<Batch<T::EthSpec>> {
        // only request batches up to the buffer size limit
        if self
            .completed_batches
            .len()
            .saturating_add(self.pending_batches.len())
            > BATCH_BUFFER_SIZE as usize
        {
            return None;
        }

        // don't request batches beyond the target head slot
        let batch_start_slot =
            self.start_slot + self.to_be_downloaded_id.saturating_sub(1) * BLOCKS_PER_BATCH;
        if batch_start_slot > self.target_head_slot {
            return None;
        }
        // truncate the batch to the target head of the chain
        let batch_end_slot = std::cmp::min(
            batch_start_slot + BLOCKS_PER_BATCH,
            self.target_head_slot.saturating_add(1u64),
        );

        let batch_id = self.to_be_downloaded_id;

        // Find the next batch id. The largest of the next sequential id, or the next uncompleted
        // id
        let max_completed_id = self
            .completed_batches
            .iter()
            .last()
            .map(|x| x.id.0)
            .unwrap_or_else(|| 0);
        // TODO: Check if this is necessary
        self.to_be_downloaded_id = BatchId(std::cmp::max(
            self.to_be_downloaded_id.0 + 1,
            max_completed_id + 1,
        ));

        Some(Batch::new(
            batch_id,
            batch_start_slot,
            batch_end_slot,
            self.target_head_root,
            peer_id,
        ))
    }

    /// Requests the provided batch from the provided peer.
    fn send_batch(&mut self, network: &mut SyncNetworkContext, batch: Batch<T::EthSpec>) {
        let request = batch.to_blocks_by_range_request();
        if let Ok(request_id) = network.blocks_by_range_request(batch.current_peer.clone(), request)
        {
            // add the batch to pending list
            self.pending_batches.insert(request_id, batch);
        }
    }
}
