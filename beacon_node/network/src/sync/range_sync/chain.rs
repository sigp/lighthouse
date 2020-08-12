use super::batch::{Batch, PendingBatches};
use crate::beacon_processor::ProcessId;
use crate::beacon_processor::WorkEvent as BeaconWorkEvent;
use crate::sync::RequestId;
use crate::sync::{network_context::SyncNetworkContext, BatchProcessResult};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::{PeerAction, PeerId};
use rand::prelude::*;
use slog::{crit, debug, error, warn};
use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{Epoch, EthSpec, Hash256, SignedBeaconBlock, Slot};

/// Blocks are downloaded in batches from peers. This constant specifies how many epochs worth of
/// blocks per batch are requested _at most_. A batch may request less blocks to account for
/// already requested slots. There is a timeout for each batch request. If this value is too high,
/// we will negatively report peers with poor bandwidth. This can be set arbitrarily high, in which case the
/// responder will fill the response up to the max request size, assuming they have the bandwidth
/// to do so.
pub const EPOCHS_PER_BATCH: u64 = 2;

/// The number of times to retry a batch before the chain is considered failed and removed.
const MAX_BATCH_RETRIES: u8 = 5;

/// The maximum number of batches to queue before requesting more.
const BATCH_BUFFER_SIZE: u8 = 5;

/// Invalid batches are attempted to be re-downloaded from other peers. If they cannot be processed
/// after `INVALID_BATCH_LOOKUP_ATTEMPTS` times, the chain is considered faulty and all peers will
/// be reported negatively.
const INVALID_BATCH_LOOKUP_ATTEMPTS: u8 = 3;

/// A return type for functions that act on a `Chain` which informs the caller whether the chain
/// has been completed and should be removed or to be kept if further processing is
/// required.
#[derive(PartialEq)]
pub enum ProcessingResult {
    KeepChain,
    RemoveChain,
}

/// A chain identifier
pub type ChainId = u64;

/// A chain of blocks that need to be downloaded. Peers who claim to contain the target head
/// root are grouped into the peer pool and queried for batches when downloading the
/// chain.
pub struct SyncingChain<T: BeaconChainTypes> {
    /// A random id used to identify this chain.
    id: ChainId,

    /// The original start slot when this chain was initialised.
    pub start_epoch: Epoch,

    /// The target head slot.
    pub target_head_slot: Slot,

    /// The target head root.
    pub target_head_root: Hash256,

    /// The batches that are currently awaiting a response from a peer. An RPC request for these
    /// has been sent.
    pub pending_batches: PendingBatches<T::EthSpec>,

    /// The batches that have been downloaded and are awaiting processing and/or validation.
    completed_batches: Vec<Batch<T::EthSpec>>,

    /// Batches that have been processed and awaiting validation before being removed.
    processed_batches: Vec<Batch<T::EthSpec>>,

    /// The peers that agree on the `target_head_slot` and `target_head_root` as a canonical chain
    /// and thus available to download this chain from.
    pub peer_pool: HashSet<PeerId>,

    /// Starting epoch of the next batch that needs to be downloaded.
    to_be_downloaded: Epoch,

    /// Starting epoch of the batch that needs to be processed next.
    /// This is incremented as the chain advances.
    processing_target: Epoch,

    /// The current state of the chain.
    pub state: ChainSyncingState,

    /// The current processing batch, if any.
    current_processing_batch: Option<Batch<T::EthSpec>>,

    /// A multi-threaded, non-blocking processor for applying messages to the beacon chain.
    beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T::EthSpec>>,

    /// A reference to the underlying beacon chain.
    chain: Arc<BeaconChain<T>>,

    /// The chain's log.
    log: slog::Logger,
}

#[derive(PartialEq)]
pub enum ChainSyncingState {
    /// The chain is not being synced.
    Stopped,
    /// The chain is undergoing syncing.
    Syncing,
}

impl<T: BeaconChainTypes> SyncingChain<T> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: u64,
        start_epoch: Epoch,
        target_head_slot: Slot,
        target_head_root: Hash256,
        peer_id: PeerId,
        beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T::EthSpec>>,
        chain: Arc<BeaconChain<T>>,
        log: slog::Logger,
    ) -> Self {
        let mut peer_pool = HashSet::new();
        peer_pool.insert(peer_id);

        SyncingChain {
            id,
            start_epoch,
            target_head_slot,
            target_head_root,
            pending_batches: PendingBatches::new(),
            completed_batches: Vec::new(),
            processed_batches: Vec::new(),
            peer_pool,
            to_be_downloaded: start_epoch,
            processing_target: start_epoch,
            state: ChainSyncingState::Stopped,
            current_processing_batch: None,
            beacon_processor_send,
            chain,
            log,
        }
    }

    /// Returns the latest slot number that has been processed.
    fn current_processed_slot(&self) -> Slot {
        // the last slot we processed was included in the previous batch, and corresponds to the
        // first slot of the current target epoch
        self.processing_target
            .start_slot(T::EthSpec::slots_per_epoch())
    }

    /// A batch of blocks has been received. This function gets run on all chains and should
    /// return Some if the request id matches a pending request on this chain, or None if it does
    /// not.
    ///
    /// If the request corresponds to a pending batch, this function processes the completed
    /// batch.
    pub fn on_block_response(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        request_id: RequestId,
        beacon_block: &Option<SignedBeaconBlock<T::EthSpec>>,
    ) -> Option<()> {
        if let Some(block) = beacon_block {
            // This is not a stream termination, simply add the block to the request
            self.pending_batches.add_block(request_id, block.clone())
        } else {
            // A stream termination has been sent. This batch has ended. Process a completed batch.
            let batch = self.pending_batches.remove(request_id)?;
            self.handle_completed_batch(network, batch);
            Some(())
        }
    }

    /// A completed batch has been received, process the batch.
    /// This will return `ProcessingResult::KeepChain` if the chain has not completed or
    /// failed indicating that further batches are required.
    fn handle_completed_batch(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch: Batch<T::EthSpec>,
    ) {
        // An entire batch of blocks has been received. This functions checks to see if it can be processed,
        // remove any batches waiting to be verified and if this chain is syncing, request new
        // blocks for the peer.
        debug!(self.log, "Completed batch received"; "epoch" => batch.start_epoch, "blocks" => &batch.downloaded_blocks.len(), "awaiting_batches" => self.completed_batches.len());

        // verify the range of received blocks
        // Note that the order of blocks is verified in block processing
        if let Some(last_slot) = batch.downloaded_blocks.last().map(|b| b.slot()) {
            // the batch is non-empty
            let first_slot = batch.downloaded_blocks[0].slot();
            if batch.start_slot() > first_slot || batch.end_slot() < last_slot {
                warn!(self.log, "BlocksByRange response returned out of range blocks";
                    "response_initial_slot" => first_slot,
                    "requested_initial_slot" => batch.start_slot());
                // this batch can't be used, so we need to request it again.
                self.failed_batch(network, batch);
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
        // Only process batches if this chain is Syncing
        if self.state != ChainSyncingState::Syncing {
            return;
        }

        // Only process one batch at a time
        if self.current_processing_batch.is_some() {
            return;
        }

        // Check if there is a batch ready to be processed
        if !self.completed_batches.is_empty()
            && self.completed_batches[0].start_epoch == self.processing_target
        {
            let batch = self.completed_batches.remove(0);

            // Note: We now send empty batches to the processor in order to trigger the block
            // processor result callback. This is done, because an empty batch could end a chain
            // and the logic for removing chains and checking completion is in the callback.

            // send the batch to the batch processor thread
            return self.process_batch(batch);
        }
    }

    /// Sends a batch to the beacon processor for async processing in a queue.
    fn process_batch(&mut self, mut batch: Batch<T::EthSpec>) {
        let blocks = std::mem::replace(&mut batch.downloaded_blocks, Vec::new());
        let process_id = ProcessId::RangeBatchId(self.id, batch.start_epoch);
        self.current_processing_batch = Some(batch);

        if let Err(e) = self
            .beacon_processor_send
            .try_send(BeaconWorkEvent::chain_segment(process_id, blocks))
        {
            error!(
                self.log,
                "Failed to send chain segment to processor";
                "msg" => "process_batch",
                "error" => format!("{:?}", e)
            );
        }
    }

    /// The block processor has completed processing a batch. This function handles the result
    /// of the batch processor.
    pub fn on_batch_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        chain_id: ChainId,
        batch_start_epoch: Epoch,
        downloaded_blocks: &mut Option<Vec<SignedBeaconBlock<T::EthSpec>>>,
        result: &BatchProcessResult,
    ) -> Option<ProcessingResult> {
        if chain_id != self.id {
            // the result does not belong to this chain
            return None;
        }
        match &self.current_processing_batch {
            Some(current_batch) if current_batch.start_epoch != batch_start_epoch => {
                debug!(self.log, "Unexpected batch result";
                    "batch_epoch" => batch_start_epoch, "expected_batch_epoch" => current_batch.start_epoch);
                return None;
            }
            None => {
                debug!(self.log, "Chain was not expecting a batch result";
                    "batch_epoch" => batch_start_epoch);
                return None;
            }
            _ => {
                // chain_id and batch_id match, continue
            }
        }

        // claim the result by consuming the option
        let downloaded_blocks = downloaded_blocks.take().or_else(|| {
            // if taken by another chain, we are no longer waiting on a result.
            self.current_processing_batch = None;
            crit!(self.log, "Processed batch taken by another chain");
            None
        })?;

        // No longer waiting on a processing result
        let mut batch = self.current_processing_batch.take().unwrap();
        // These are the blocks of this batch
        batch.downloaded_blocks = downloaded_blocks;

        // double check batches are processed in order TODO: Remove for prod
        if batch.start_epoch != self.processing_target {
            crit!(self.log, "Batch processed out of order";
                "processed_starting_epoch" => batch.start_epoch,
                "expected_epoch" => self.processing_target);
        }

        let res = match result {
            BatchProcessResult::Success => {
                self.processing_target += EPOCHS_PER_BATCH;

                // If the processed batch was not empty, we can validate previous invalidated
                // blocks including the current batch.
                if !batch.downloaded_blocks.is_empty() {
                    self.mark_processed_batches_as_valid(network, &batch);
                }

                // Add the current batch to processed batches to be verified in the future.
                self.processed_batches.push(batch);

                // check if the chain has completed syncing
                if self.current_processed_slot() >= self.target_head_slot {
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
            BatchProcessResult::Partial => {
                warn!(self.log, "Batch processing failed but at least one block was imported";
                    "batch_epoch" => batch.start_epoch, "peer" => batch.current_peer.to_string()
                );
                // At least one block was successfully verified and imported, so we can be sure all
                // previous batches are valid and we only need to download the current failed
                // batch.
                self.mark_processed_batches_as_valid(network, &batch);

                // check that we have not exceeded the re-process retry counter
                if batch.reprocess_retries > INVALID_BATCH_LOOKUP_ATTEMPTS {
                    // If a batch has exceeded the invalid batch lookup attempts limit, it means
                    // that it is likely all peers in this chain are are sending invalid batches
                    // repeatedly and are either malicious or faulty. We drop the chain and
                    // report all peers.
                    // There are some edge cases with forks that could land us in this situation.
                    // This should be unlikely, so we tolerate these errors, but not often.
                    let action = PeerAction::LowToleranceError;
                    warn!(self.log, "Batch failed to download. Dropping chain scoring peers";
                        "score_adjustment" => action.to_string(),
                        "batch_epoch"=> batch.start_epoch);
                    for peer_id in self.peer_pool.drain() {
                        network.report_peer(peer_id, action);
                    }
                    ProcessingResult::RemoveChain
                } else {
                    // Handle this invalid batch, that is within the re-process retries limit.
                    self.handle_invalid_batch(network, batch);
                    ProcessingResult::KeepChain
                }
            }
            BatchProcessResult::Failed => {
                debug!(self.log, "Batch processing failed";
                    "batch_epoch" => batch.start_epoch, "peer" => batch.current_peer.to_string(), "client" => network.client_type(&batch.current_peer).to_string());
                // The batch processing failed
                // This could be because this batch is invalid, or a previous invalidated batch
                // is invalid. We need to find out which and downvote the peer that has sent us
                // an invalid batch.

                // check that we have not exceeded the re-process retry counter
                if batch.reprocess_retries > INVALID_BATCH_LOOKUP_ATTEMPTS {
                    // If a batch has exceeded the invalid batch lookup attempts limit, it means
                    // that it is likely all peers in this chain are are sending invalid batches
                    // repeatedly and are either malicious or faulty. We drop the chain and
                    // downvote all peers.
                    let action = PeerAction::LowToleranceError;
                    warn!(self.log, "Batch failed to download. Dropping chain scoring peers";
                        "score_adjustment" => action.to_string(),
                        "batch_epoch" => batch.start_epoch);
                    for peer_id in self.peer_pool.drain() {
                        network.report_peer(peer_id, action);
                    }
                    ProcessingResult::RemoveChain
                } else {
                    // Handle this invalid batch, that is within the re-process retries limit.
                    self.handle_invalid_batch(network, batch);
                    ProcessingResult::KeepChain
                }
            }
        };

        Some(res)
    }

    /// Removes any batches awaiting validation.
    ///
    /// All blocks in `processed_batches` should be prior batches. As the `last_batch` has been
    /// processed with blocks in it, all previous batches are valid.
    ///
    /// If a previous batch has been validated and it had been re-processed, downvote
    /// the original peer.
    fn mark_processed_batches_as_valid(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        last_batch: &Batch<T::EthSpec>,
    ) {
        while !self.processed_batches.is_empty() {
            let mut processed_batch = self.processed_batches.remove(0);
            if processed_batch.start_epoch >= last_batch.start_epoch {
                crit!(self.log, "A processed batch had a greater id than the current process id";
                    "processed_start_epoch" => processed_batch.start_epoch,
                    "current_start_epoch" => last_batch.start_epoch);
            }

            // Go through passed attempts and downscore peers that returned invalid batches
            while !processed_batch.attempts.is_empty() {
                let attempt = processed_batch.attempts.remove(0);
                // The validated batch has been re-processed
                if attempt.hash != processed_batch.hash() {
                    // The re-downloaded version was different
                    if processed_batch.current_peer != attempt.peer_id {
                        // A different peer sent the correct batch, the previous peer did not
                        // We negatively score the original peer.
                        let action = PeerAction::LowToleranceError;
                        debug!(
                            self.log, "Re-processed batch validated. Scoring original peer";
                            "batch_epoch" => processed_batch.start_epoch,
                            "score_adjustment" => action.to_string(),
                            "original_peer" => format!("{}",attempt.peer_id),
                            "new_peer" => format!("{}", processed_batch.current_peer)
                        );
                        network.report_peer(attempt.peer_id, action);
                    } else {
                        // The same peer corrected it's previous mistake. There was an error, so we
                        // negative score the original peer.
                        let action = PeerAction::MidToleranceError;
                        debug!(
                            self.log, "Re-processed batch validated by the same peer.";
                            "batch_epoch" => processed_batch.start_epoch,
                            "score_adjustment" => action.to_string(),
                            "original_peer" => format!("{}",attempt.peer_id),
                            "new_peer" => format!("{}", processed_batch.current_peer)
                        );
                        network.report_peer(attempt.peer_id, action);
                    }
                }
            }
        }
    }

    /// An invalid batch has been received that could not be processed.
    ///
    /// These events occur when a peer as successfully responded with blocks, but the blocks we
    /// have received are incorrect or invalid. This indicates the peer has not performed as
    /// intended and can result in downvoting a peer.
    // TODO: Batches could have been partially downloaded due to RPC size-limit restrictions. We
    // need to add logic for partial batch downloads. Potentially, if another peer returns the same
    // batch, we try a partial download.
    fn handle_invalid_batch(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch: Batch<T::EthSpec>,
    ) {
        // The current batch could not be processed, indicating either the current or previous
        // batches are invalid

        // The previous batch could be incomplete due to the block sizes being too large to fit in
        // a single RPC request or there could be consecutive empty batches which are not supposed
        // to be there

        // The current (sub-optimal) strategy is to simply re-request all batches that could
        // potentially be faulty. If a batch returns a different result than the original and
        // results in successful processing, we downvote the original peer that sent us the batch.

        // If all batches return the same result, we try this process INVALID_BATCH_LOOKUP_ATTEMPTS
        // times before considering the entire chain invalid and downvoting all peers.

        // Find any pre-processed batches awaiting validation
        while !self.processed_batches.is_empty() {
            let past_batch = self.processed_batches.remove(0);
            self.processing_target = std::cmp::min(self.processing_target, past_batch.start_epoch);
            self.reprocess_batch(network, past_batch);
        }

        // re-process the current batch
        self.reprocess_batch(network, batch);
    }

    /// This re-downloads and marks the batch as being re-processed.
    ///
    /// If the re-downloaded batch is different to the original and can be processed, the original
    /// peer will be downvoted.
    fn reprocess_batch(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        mut batch: Batch<T::EthSpec>,
    ) {
        // marks the batch as attempting to be reprocessed by hashing the downloaded blocks
        let attempt = super::batch::Attempt {
            peer_id: batch.current_peer.clone(),
            hash: batch.hash(),
        };

        // add this attempt to the batch
        batch.attempts.push(attempt);

        // remove previously downloaded blocks
        batch.downloaded_blocks.clear();

        // increment the re-process counter
        batch.reprocess_retries += 1;

        // attempt to find another peer to download the batch from (this potentially doubles up
        // requests on a single peer)
        let current_peer = &batch.current_peer;
        let new_peer = self
            .peer_pool
            .iter()
            .find(|peer| *peer != current_peer)
            .unwrap_or_else(|| current_peer);

        batch.current_peer = new_peer.clone();

        debug!(self.log, "Re-requesting batch";
            "start_slot" => batch.start_slot(),
            "end_slot" => batch.end_slot -1, // The -1 shows inclusive blocks
            "batch_epoch" => batch.start_epoch,
            "peer" => batch.current_peer.to_string(),
            "retries" => batch.retries,
            "re-processes" =>  batch.reprocess_retries);
        self.send_batch(network, batch);
    }

    pub fn stop_syncing(&mut self) {
        self.state = ChainSyncingState::Stopped;
    }

    // Either a new chain, or an old one with a peer list
    /// This chain has been requested to start syncing.
    ///
    /// This could be new chain, or an old chain that is being resumed.
    pub fn start_syncing(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        local_finalized_epoch: Epoch,
    ) {
        // A local finalized slot is provided as other chains may have made
        // progress whilst this chain was Stopped or paused. If so, update the `processed_batch_id` to
        // accommodate potentially downloaded batches from other chains. Also prune any old batches
        // awaiting processing

        // If the local finalized epoch is ahead of our current processed chain, update the chain
        // to start from this point and re-index all subsequent batches starting from one
        // (effectively creating a new chain).

        let local_finalized_slot = local_finalized_epoch.start_slot(T::EthSpec::slots_per_epoch());
        let current_processed_slot = self.current_processed_slot();

        if local_finalized_slot > current_processed_slot {
            // Advance the chain to account for already downloaded blocks.
            self.start_epoch = local_finalized_epoch;

            debug!(self.log, "Updating chain's progress";
                "prev_completed_slot" => current_processed_slot,
                "new_completed_slot" => self.current_processed_slot());
            // Re-index batches
            self.to_be_downloaded = local_finalized_epoch;
            self.processing_target = local_finalized_epoch;

            // remove any completed or processed batches
            self.completed_batches.clear();
            self.processed_batches.clear();
        }

        self.state = ChainSyncingState::Syncing;

        // start processing batches if needed
        self.process_completed_batches();

        // begin requesting blocks from the peer pool, until all peers are exhausted.
        self.request_batches(network);
    }

    /// Add a peer to the chain.
    ///
    /// If the chain is active, this starts requesting batches from this peer.
    pub fn add_peer(&mut self, network: &mut SyncNetworkContext<T::EthSpec>, peer_id: PeerId) {
        self.peer_pool.insert(peer_id.clone());
        // do not request blocks if the chain is not syncing
        if let ChainSyncingState::Stopped = self.state {
            debug!(self.log, "Peer added to a non-syncing chain";
                "peer_id" => format!("{}", peer_id));
            return;
        }

        // find the next batch and request it from any peers if we need to
        self.request_batches(network);
    }

    /// Sends a STATUS message to all peers in the peer pool.
    pub fn status_peers(&self, network: &mut SyncNetworkContext<T::EthSpec>) {
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
        network: &mut SyncNetworkContext<T::EthSpec>,
        peer_id: &PeerId,
        request_id: RequestId,
    ) -> Option<ProcessingResult> {
        if let Some(batch) = self.pending_batches.remove(request_id) {
            debug!(self.log, "Batch failed. RPC Error";
                "batch_epoch" => batch.start_epoch,
                "retries" => batch.retries,
                "peer" => format!("{:?}", peer_id));

            Some(self.failed_batch(network, batch))
        } else {
            None
        }
    }

    /// A batch has failed. This occurs when a network timeout happens or the peer didn't respond.
    /// These events do not indicate a malicious peer, more likely simple networking issues.
    ///
    /// Attempts to re-request from another peer in the peer pool (if possible) and returns
    /// `ProcessingResult::RemoveChain` if the number of retries on the batch exceeds
    /// `MAX_BATCH_RETRIES`.
    pub fn failed_batch(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        mut batch: Batch<T::EthSpec>,
    ) -> ProcessingResult {
        batch.retries += 1;

        if batch.retries > MAX_BATCH_RETRIES || self.peer_pool.is_empty() {
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
            debug!(self.log, "Re-Requesting batch";
                "start_slot" => batch.start_slot(),
                "end_slot" => batch.end_slot -1, // The -1 shows inclusive blocks
                "batch_epoch" => batch.start_epoch,
                "peer" => batch.current_peer.to_string());
            self.send_batch(network, batch);
            ProcessingResult::KeepChain
        }
    }

    /// Attempts to request the next required batches from the peer pool if the chain is syncing. It will exhaust the peer
    /// pool and left over batches until the batch buffer is reached or all peers are exhausted.
    fn request_batches(&mut self, network: &mut SyncNetworkContext<T::EthSpec>) {
        if let ChainSyncingState::Syncing = self.state {
            while self.send_range_request(network) {}
        }
    }

    /// Requests the next required batch from a peer. Returns true, if there was a peer available
    /// to send a request and there are batches to request, false otherwise.
    fn send_range_request(&mut self, network: &mut SyncNetworkContext<T::EthSpec>) -> bool {
        // find the next pending batch and request it from the peer
        if let Some(peer_id) = self.get_next_peer() {
            if let Some(batch) = self.get_next_batch(peer_id) {
                debug!(self.log, "Requesting batch";
                    "start_slot" => batch.start_slot(),
                    "end_slot" => batch.end_slot -1, // The -1 shows inclusive blocks
                    "batch_epoch" => batch.start_epoch,
                    "peer" => format!("{}", batch.current_peer));
                // send the batch
                self.send_batch(network, batch);
                return true;
            }
        }
        false
    }

    /// Returns a peer if there exists a peer which does not currently have a pending request.
    ///
    /// This is used to create the next request.
    fn get_next_peer(&self) -> Option<PeerId> {
        // TODO: Optimize this by combining with above two functions.
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
    ///
    /// Batches are downloaded excluding the first block of the epoch assuming it has already been
    /// downloaded.
    ///
    /// For example:
    ///
    ///
    /// Epoch boundary |                                   |
    ///  ... | 30 | 31 | 32 | 33 | 34 | ... | 61 | 62 | 63 | 64 | 65 |
    ///       Batch 1       |              Batch 2              |  Batch 3
    fn get_next_batch(&mut self, peer_id: PeerId) -> Option<Batch<T::EthSpec>> {
        let slots_per_epoch = T::EthSpec::slots_per_epoch();
        let blocks_per_batch = slots_per_epoch * EPOCHS_PER_BATCH;

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
        if self.to_be_downloaded.start_slot(slots_per_epoch) > self.target_head_slot {
            return None;
        }

        // truncate the batch to the epoch containing the target head of the chain
        let batch_end_slot = std::cmp::min(
            // request either a batch containing the max number of blocks per batch
            self.to_be_downloaded.start_slot(slots_per_epoch) + blocks_per_batch + 1,
            // or a batch of one epoch of blocks, which contains the `target_head_slot`
            self.target_head_slot
                .saturating_add(slots_per_epoch)
                .epoch(slots_per_epoch)
                .start_slot(slots_per_epoch),
        );

        let batch = Some(Batch::new(self.to_be_downloaded, batch_end_slot, peer_id));
        self.to_be_downloaded += EPOCHS_PER_BATCH;
        batch
    }

    /// Requests the provided batch from the provided peer.
    fn send_batch(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch: Batch<T::EthSpec>,
    ) {
        let request = batch.to_blocks_by_range_request();

        match network.blocks_by_range_request(batch.current_peer.clone(), request) {
            Ok(request_id) => {
                // add the batch to pending list
                self.pending_batches.insert(request_id, batch);
            }
            Err(e) => {
                warn!(self.log, "Batch request failed";
                    "start_slot" => batch.start_slot(),
                    "end_slot" => batch.end_slot -1, // The -1 shows inclusive blocks
                    "start_epoch" => batch.start_epoch,
                    "peer" => batch.current_peer.to_string(),
                    "retries" => batch.retries,
                    "error" => e,
                    "re-processes" =>  batch.reprocess_retries);
                self.failed_batch(network, batch);
            }
        }
    }
}
