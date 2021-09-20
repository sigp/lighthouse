use super::batch::{BatchInfo, BatchState};
use crate::beacon_processor::ProcessId;
use crate::beacon_processor::WorkEvent as BeaconWorkEvent;
use crate::sync::{network_context::SyncNetworkContext, BatchProcessResult, RequestId};
use beacon_chain::BeaconChainTypes;
use eth2_libp2p::{PeerAction, PeerId};
use fnv::FnvHashMap;
use rand::seq::SliceRandom;
use slog::{crit, debug, o, warn};
use std::collections::{btree_map::Entry, BTreeMap, HashSet};
use std::hash::{Hash, Hasher};
use tokio::sync::mpsc::Sender;
use types::{Epoch, EthSpec, Hash256, SignedBeaconBlock, Slot};

/// Blocks are downloaded in batches from peers. This constant specifies how many epochs worth of
/// blocks per batch are requested _at most_. A batch may request less blocks to account for
/// already requested slots. There is a timeout for each batch request. If this value is too high,
/// we will negatively report peers with poor bandwidth. This can be set arbitrarily high, in which
/// case the responder will fill the response up to the max request size, assuming they have the
/// bandwidth to do so.
pub const EPOCHS_PER_BATCH: u64 = 2;

/// The maximum number of batches to queue before requesting more.
const BATCH_BUFFER_SIZE: u8 = 5;

/// A return type for functions that act on a `Chain` which informs the caller whether the chain
/// has been completed and should be removed or to be kept if further processing is
/// required.
#[must_use = "Should be checked, since a failed chain must be removed. A chain that requested
 being removed and continued is now in an inconsistent state"]
pub type ProcessingResult = Result<KeepChain, RemoveChain>;

/// Reasons for removing a chain
#[derive(Debug)]
pub enum RemoveChain {
    EmptyPeerPool,
    ChainCompleted,
    ChainFailed(BatchId),
    WrongBatchState(String),
    WrongChainState(String),
}

#[derive(Debug)]
pub struct KeepChain;

/// A chain identifier
pub type ChainId = u64;
pub type BatchId = Epoch;

/// A chain of blocks that need to be downloaded. Peers who claim to contain the target head
/// root are grouped into the peer pool and queried for batches when downloading the
/// chain.
pub struct SyncingChain<T: BeaconChainTypes> {
    /// A random id used to identify this chain.
    id: ChainId,

    /// The start of the chain segment. Any epoch previous to this one has been validated.
    pub start_epoch: Epoch,

    /// The target head slot.
    pub target_head_slot: Slot,

    /// The target head root.
    pub target_head_root: Hash256,

    /// Sorted map of batches undergoing some kind of processing.
    batches: BTreeMap<BatchId, BatchInfo<T::EthSpec>>,

    /// The peers that agree on the `target_head_slot` and `target_head_root` as a canonical chain
    /// and thus available to download this chain from, as well as the batches we are currently
    /// requesting.
    peers: FnvHashMap<PeerId, HashSet<BatchId>>,

    /// Starting epoch of the next batch that needs to be downloaded.
    to_be_downloaded: BatchId,

    /// Starting epoch of the batch that needs to be processed next.
    /// This is incremented as the chain advances.
    processing_target: BatchId,

    /// Optimistic head to sync.
    /// If a block is imported for this batch, the chain advances to this point.
    optimistic_start: Option<BatchId>,

    /// When a batch for an optimistic start is tried (either successful or not), it is stored to
    /// avoid trying it again due to chain stopping/re-starting on chain switching.
    attempted_optimistic_starts: HashSet<BatchId>,

    /// The current state of the chain.
    pub state: ChainSyncingState,

    /// The current processing batch, if any.
    current_processing_batch: Option<BatchId>,

    /// Batches validated by this chain.
    validated_batches: u64,

    /// A multi-threaded, non-blocking processor for applying messages to the beacon chain.
    beacon_processor_send: Sender<BeaconWorkEvent<T>>,

    /// The chain's log.
    log: slog::Logger,
}

#[derive(PartialEq, Debug)]
pub enum ChainSyncingState {
    /// The chain is not being synced.
    Stopped,
    /// The chain is undergoing syncing.
    Syncing,
}

impl<T: BeaconChainTypes> SyncingChain<T> {
    pub fn id(target_root: &Hash256, target_slot: &Slot) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (target_root, target_slot).hash(&mut hasher);
        hasher.finish()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        start_epoch: Epoch,
        target_head_slot: Slot,
        target_head_root: Hash256,
        peer_id: PeerId,
        beacon_processor_send: Sender<BeaconWorkEvent<T>>,
        log: &slog::Logger,
    ) -> Self {
        let mut peers = FnvHashMap::default();
        peers.insert(peer_id, Default::default());

        let id = SyncingChain::<T>::id(&target_head_root, &target_head_slot);

        SyncingChain {
            id,
            start_epoch,
            target_head_slot,
            target_head_root,
            batches: BTreeMap::new(),
            peers,
            to_be_downloaded: start_epoch,
            processing_target: start_epoch,
            optimistic_start: None,
            attempted_optimistic_starts: HashSet::default(),
            state: ChainSyncingState::Stopped,
            current_processing_batch: None,
            validated_batches: 0,
            beacon_processor_send,
            log: log.new(o!("chain" => id)),
        }
    }

    /// Check if the chain has peers from which to process batches.
    pub fn available_peers(&self) -> usize {
        self.peers.len()
    }

    /// Get the chain's id.
    pub fn get_id(&self) -> ChainId {
        self.id
    }

    /// Peers currently syncing this chain.
    pub fn peers(&self) -> impl Iterator<Item = PeerId> + '_ {
        self.peers.keys().cloned()
    }

    /// Progress in epochs made by the chain
    pub fn validated_epochs(&self) -> u64 {
        self.validated_batches * EPOCHS_PER_BATCH
    }

    /// Removes a peer from the chain.
    /// If the peer has active batches, those are considered failed and re-requested.
    pub fn remove_peer(
        &mut self,
        peer_id: &PeerId,
        network: &mut SyncNetworkContext<T::EthSpec>,
    ) -> ProcessingResult {
        if let Some(batch_ids) = self.peers.remove(peer_id) {
            // fail the batches
            for id in batch_ids {
                if let Some(batch) = self.batches.get_mut(&id) {
                    if batch.download_failed(true)? {
                        return Err(RemoveChain::ChainFailed(id));
                    }
                    self.retry_batch_download(network, id)?;
                } else {
                    debug!(self.log, "Batch not found while removing peer";
                        "peer" => %peer_id, "batch" => id)
                }
            }
        }

        if self.peers.is_empty() {
            Err(RemoveChain::EmptyPeerPool)
        } else {
            Ok(KeepChain)
        }
    }

    /// Returns the latest slot number that has been processed.
    fn current_processed_slot(&self) -> Slot {
        // the last slot we processed was included in the previous batch, and corresponds to the
        // first slot of the current target epoch
        self.processing_target
            .start_slot(T::EthSpec::slots_per_epoch())
    }

    /// A block has been received for a batch on this chain.
    /// If the block correctly completes the batch it will be processed if possible.
    pub fn on_block_response(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch_id: BatchId,
        peer_id: &PeerId,
        request_id: RequestId,
        beacon_block: Option<SignedBeaconBlock<T::EthSpec>>,
    ) -> ProcessingResult {
        // check if we have this batch
        let batch = match self.batches.get_mut(&batch_id) {
            None => {
                debug!(self.log, "Received a block for unknown batch"; "epoch" => batch_id);
                // A batch might get removed when the chain advances, so this is non fatal.
                return Ok(KeepChain);
            }
            Some(batch) => {
                // A batch could be retried without the peer failing the request (disconnecting/
                // sending an error /timeout) if the peer is removed from the chain for other
                // reasons. Check that this block belongs to the expected peer, and that the
                // request_id matches
                if !batch.is_expecting_block(peer_id, &request_id) {
                    return Ok(KeepChain);
                }
                batch
            }
        };

        if let Some(block) = beacon_block {
            // This is not a stream termination, simply add the block to the request
            batch.add_block(block)?;
            Ok(KeepChain)
        } else {
            // A stream termination has been sent. This batch has ended. Process a completed batch.
            // Remove the request from the peer's active batches
            self.peers
                .get_mut(peer_id)
                .map(|active_requests| active_requests.remove(&batch_id));

            match batch.download_completed() {
                Ok(received) => {
                    let awaiting_batches = batch_id
                        .saturating_sub(self.optimistic_start.unwrap_or(self.processing_target))
                        / EPOCHS_PER_BATCH;
                    debug!(self.log, "Completed batch received"; "epoch" => batch_id, "blocks" => received, "awaiting_batches" => awaiting_batches);

                    // pre-emptively request more blocks from peers whilst we process current blocks,
                    self.request_batches(network)?;
                    self.process_completed_batches(network)
                }
                Err(result) => {
                    let (expected_boundary, received_boundary, is_failed) = result?;
                    warn!(self.log, "Batch received out of range blocks"; "expected_boundary" => expected_boundary, "received_boundary" => received_boundary,
                        "peer_id" => %peer_id, batch);

                    if is_failed {
                        return Err(RemoveChain::ChainFailed(batch_id));
                    }
                    // this batch can't be used, so we need to request it again.
                    self.retry_batch_download(network, batch_id)
                }
            }
        }
    }

    /// Processes the batch with the given id.
    /// The batch must exist and be ready for processing
    fn process_batch(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch_id: BatchId,
    ) -> ProcessingResult {
        // Only process batches if this chain is Syncing, and only one at a time
        if self.state != ChainSyncingState::Syncing || self.current_processing_batch.is_some() {
            return Ok(KeepChain);
        }

        let batch = match self.batches.get_mut(&batch_id) {
            Some(batch) => batch,
            None => {
                return Err(RemoveChain::WrongChainState(format!(
                    "Trying to process a batch that does not exist: {}",
                    batch_id
                )));
            }
        };

        // NOTE: We send empty batches to the processor in order to trigger the block processor
        // result callback. This is done, because an empty batch could end a chain and the logic
        // for removing chains and checking completion is in the callback.

        let blocks = batch.start_processing()?;
        let process_id = ProcessId::RangeBatchId(self.id, batch_id);
        self.current_processing_batch = Some(batch_id);

        if let Err(e) = self
            .beacon_processor_send
            .try_send(BeaconWorkEvent::chain_segment(process_id, blocks))
        {
            crit!(self.log, "Failed to send chain segment to processor."; "msg" => "process_batch",
                "error" => %e, "batch" => self.processing_target);
            // This is unlikely to happen but it would stall syncing since the batch now has no
            // blocks to continue, and the chain is expecting a processing result that won't
            // arrive.  To mitigate this, (fake) fail this processing so that the batch is
            // re-downloaded.
            self.on_batch_process_result(network, batch_id, &BatchProcessResult::Failed(false))
        } else {
            Ok(KeepChain)
        }
    }

    /// Processes the next ready batch, prioritizing optimistic batches over the processing target.
    fn process_completed_batches(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
    ) -> ProcessingResult {
        // Only process batches if this chain is Syncing and only process one batch at a time
        if self.state != ChainSyncingState::Syncing || self.current_processing_batch.is_some() {
            return Ok(KeepChain);
        }

        // Find the id of the batch we are going to process.
        //
        // First try our optimistic start, if any. If this batch is ready, we process it. If the
        // batch has not already been completed, check the current chain target.
        if let Some(epoch) = self.optimistic_start {
            if let Some(batch) = self.batches.get(&epoch) {
                let state = batch.state();
                match state {
                    BatchState::AwaitingProcessing(..) => {
                        // this batch is ready
                        debug!(self.log, "Processing optimistic start"; "epoch" => epoch);
                        return self.process_batch(network, epoch);
                    }
                    BatchState::Downloading(..) => {
                        // The optimistic batch is being downloaded. We wait for this before
                        // attempting to process other batches.
                        return Ok(KeepChain);
                    }
                    BatchState::Poisoned => unreachable!("Poisoned batch"),
                    BatchState::Processing(_)
                    | BatchState::AwaitingDownload
                    | BatchState::Failed => {
                        // these are all inconsistent states:
                        // - Processing -> `self.current_processing_batch` is None
                        // - Failed -> non recoverable batch. For an optimistic batch, it should
                        //   have been removed
                        // - AwaitingDownload -> A recoverable failed batch should have been
                        //   re-requested.
                        return Err(RemoveChain::WrongChainState(format!(
                            "Optimistic batch indicates inconsistent chain state: {:?}",
                            state
                        )));
                    }
                    BatchState::AwaitingValidation(_) => {
                        // If an optimistic start is given to the chain after the corresponding
                        // batch has been requested and processed we can land here. We drop the
                        // optimistic candidate since we can't conclude whether the batch included
                        // blocks or not at this point
                        debug!(self.log, "Dropping optimistic candidate"; "batch" => epoch);
                        self.optimistic_start = None;
                    }
                }
            }
        }

        // if the optimistic target can't be processed, check the processing target
        if let Some(batch) = self.batches.get(&self.processing_target) {
            let state = batch.state();
            match state {
                BatchState::AwaitingProcessing(..) => {
                    return self.process_batch(network, self.processing_target);
                }
                BatchState::Downloading(..) => {
                    // Batch is not ready, nothing to process
                }
                BatchState::Poisoned => unreachable!("Poisoned batch"),
                BatchState::Failed | BatchState::AwaitingDownload | BatchState::Processing(_) => {
                    // these are all inconsistent states:
                    // - Failed -> non recoverable batch. Chain should have beee removed
                    // - AwaitingDownload -> A recoverable failed batch should have been
                    //   re-requested.
                    // - Processing -> `self.current_processing_batch` is None
                    return Err(RemoveChain::WrongChainState(format!(
                        "Robust target batch indicates inconsistent chain state: {:?}",
                        state
                    )));
                }
                BatchState::AwaitingValidation(_) => {
                    // we can land here if an empty optimistic batch succeeds processing and is
                    // inside the download buffer (between `self.processing_target` and
                    // `self.to_be_downloaded`). In this case, eventually the chain advances to the
                    // batch (`self.processing_target` reaches this point).
                    debug!(self.log, "Chain encountered a robust batch awaiting validation"; "batch" => self.processing_target);

                    self.processing_target += EPOCHS_PER_BATCH;
                    if self.to_be_downloaded <= self.processing_target {
                        self.to_be_downloaded = self.processing_target + EPOCHS_PER_BATCH;
                    }
                    self.request_batches(network)?;
                }
            }
        } else {
            return Err(RemoveChain::WrongChainState(format!(
                "Batch not found for current processing target {}",
                self.processing_target
            )));
        }
        Ok(KeepChain)
    }

    /// The block processor has completed processing a batch. This function handles the result
    /// of the batch processor.
    pub fn on_batch_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch_id: BatchId,
        result: &BatchProcessResult,
    ) -> ProcessingResult {
        // the first two cases are possible if the chain advances while waiting for a processing
        // result
        match &self.current_processing_batch {
            Some(processing_id) if *processing_id != batch_id => {
                debug!(self.log, "Unexpected batch result";
                    "batch_epoch" => batch_id, "expected_batch_epoch" => processing_id);
                return Ok(KeepChain);
            }
            None => {
                debug!(self.log, "Chain was not expecting a batch result";
                    "batch_epoch" => batch_id);
                return Ok(KeepChain);
            }
            _ => {
                // batch_id matches, continue
                self.current_processing_batch = None;
            }
        }

        match result {
            BatchProcessResult::Success(was_non_empty) => {
                let batch = self.batches.get_mut(&batch_id).ok_or_else(|| {
                    RemoveChain::WrongChainState(format!(
                        "Current processing batch not found: {}",
                        batch_id
                    ))
                })?;

                batch.processing_completed(true)?;
                // If the processed batch was not empty, we can validate previous unvalidated
                // blocks.
                if *was_non_empty {
                    self.advance_chain(network, batch_id);
                    // we register so that on chain switching we don't try it again
                    self.attempted_optimistic_starts.insert(batch_id);
                } else if self.optimistic_start == Some(batch_id) {
                    // check if this batch corresponds to an optimistic batch. In this case, we
                    // reject it as an optimistic candidate since the batch was empty
                    self.reject_optimistic_batch(
                        network,
                        false, /* do not re-request */
                        "batch was empty",
                    )?;
                }

                if batch_id == self.processing_target {
                    self.processing_target += EPOCHS_PER_BATCH;
                }

                // check if the chain has completed syncing
                if self.current_processed_slot() >= self.target_head_slot {
                    // chain is completed
                    Err(RemoveChain::ChainCompleted)
                } else {
                    // chain is not completed
                    // attempt to request more batches
                    self.request_batches(network)?;
                    // attempt to process more batches
                    self.process_completed_batches(network)
                }
            }
            BatchProcessResult::Failed(imported_blocks) => {
                let batch = self.batches.get_mut(&batch_id).ok_or_else(|| {
                    RemoveChain::WrongChainState(format!(
                        "Batch not found for current processing target {}",
                        batch_id
                    ))
                })?;
                let peer = batch.current_peer().cloned().ok_or_else(|| {
                    RemoveChain::WrongBatchState(format!(
                        "Processing target is in wrong state: {:?}",
                        batch.state(),
                    ))
                })?;
                debug!(self.log, "Batch processing failed"; "imported_blocks" => imported_blocks,
                    "batch_epoch" => batch_id, "peer" => %peer, "client" => %network.client_type(&peer));
                if batch.processing_completed(false)? {
                    // check that we have not exceeded the re-process retry counter
                    // If a batch has exceeded the invalid batch lookup attempts limit, it means
                    // that it is likely all peers in this chain are are sending invalid batches
                    // repeatedly and are either malicious or faulty. We drop the chain and
                    // report all peers.
                    // There are some edge cases with forks that could land us in this situation.
                    // This should be unlikely, so we tolerate these errors, but not often.
                    let action = PeerAction::LowToleranceError;
                    warn!(self.log, "Batch failed to download. Dropping chain scoring peers";
                        "score_adjustment" => %action,
                        "batch_epoch"=> batch_id);
                    for (peer, _) in self.peers.drain() {
                        network.report_peer(peer, action);
                    }
                    Err(RemoveChain::ChainFailed(batch_id))
                } else {
                    // chain can continue. Check if it can be moved forward
                    if *imported_blocks {
                        // At least one block was successfully verified and imported, so we can be sure all
                        // previous batches are valid and we only need to download the current failed
                        // batch.
                        self.advance_chain(network, batch_id);
                    }
                    // Handle this invalid batch, that is within the re-process retries limit.
                    self.handle_invalid_batch(network, batch_id)
                }
            }
        }
    }

    fn reject_optimistic_batch(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        redownload: bool,
        reason: &str,
    ) -> ProcessingResult {
        if let Some(epoch) = self.optimistic_start.take() {
            self.attempted_optimistic_starts.insert(epoch);
            // if this batch is inside the current processing range, keep it, otherwise drop
            // it. NOTE: this is done to prevent non-sequential batches coming from optimistic
            // starts from filling up the buffer size
            if epoch < self.to_be_downloaded {
                debug!(self.log, "Rejected optimistic batch left for future use"; "epoch" => %epoch, "reason" => reason);
                // this batch is now treated as any other batch, and re-requested for future use
                if redownload {
                    return self.retry_batch_download(network, epoch);
                }
            } else {
                debug!(self.log, "Rejected optimistic batch"; "epoch" => %epoch, "reason" => reason);
                self.batches.remove(&epoch);
            }
        }

        Ok(KeepChain)
    }

    /// Removes any batches previous to the given `validating_epoch` and updates the current
    /// boundaries of the chain.
    ///
    /// The `validating_epoch` must align with batch boundaries.
    ///
    /// If a previous batch has been validated and it had been re-processed, penalize the original
    /// peer.
    fn advance_chain(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        validating_epoch: Epoch,
    ) {
        // make sure this epoch produces an advancement
        if validating_epoch <= self.start_epoch {
            return;
        }

        // safety check for batch boundaries
        if validating_epoch % EPOCHS_PER_BATCH != self.start_epoch % EPOCHS_PER_BATCH {
            crit!(self.log, "Validating Epoch is not aligned");
            return;
        }

        // batches in the range [BatchId, ..) (not yet validated)
        let remaining_batches = self.batches.split_off(&validating_epoch);
        // batches less than `validating_epoch`
        let removed_batches = std::mem::replace(&mut self.batches, remaining_batches);

        for (id, batch) in removed_batches.into_iter() {
            self.validated_batches = self.validated_batches.saturating_add(1);
            // only for batches awaiting validation can we be sure the last attempt is
            // right, and thus, that any different attempt is wrong
            match batch.state() {
                BatchState::AwaitingValidation(ref processed_attempt) => {
                    for attempt in batch.attempts() {
                        // The validated batch has been re-processed
                        if attempt.hash != processed_attempt.hash {
                            // The re-downloaded version was different
                            if processed_attempt.peer_id != attempt.peer_id {
                                // A different peer sent the correct batch, the previous peer did not
                                // We negatively score the original peer.
                                let action = PeerAction::LowToleranceError;
                                debug!(self.log, "Re-processed batch validated. Scoring original peer";
                                    "batch_epoch" => id, "score_adjustment" => %action,
                                    "original_peer" => %attempt.peer_id, "new_peer" => %processed_attempt.peer_id
                                );
                                network.report_peer(attempt.peer_id, action);
                            } else {
                                // The same peer corrected it's previous mistake. There was an error, so we
                                // negative score the original peer.
                                let action = PeerAction::MidToleranceError;
                                debug!(self.log, "Re-processed batch validated by the same peer";
                                    "batch_epoch" => id, "score_adjustment" => %action,
                                    "original_peer" => %attempt.peer_id, "new_peer" => %processed_attempt.peer_id
                                );
                                network.report_peer(attempt.peer_id, action);
                            }
                        }
                    }
                }
                BatchState::Downloading(peer, ..) => {
                    // remove this batch from the peer's active requests
                    if let Some(active_batches) = self.peers.get_mut(peer) {
                        active_batches.remove(&id);
                    }
                }
                BatchState::Failed | BatchState::Poisoned | BatchState::AwaitingDownload => crit!(
                    self.log,
                    "batch indicates inconsistent chain state while advancing chain"
                ),
                BatchState::AwaitingProcessing(..) => {}
                BatchState::Processing(_) => {
                    debug!(self.log, "Advancing chain while processing a batch"; "batch" => id, batch);
                    if let Some(processing_id) = self.current_processing_batch {
                        if id <= processing_id {
                            self.current_processing_batch = None;
                        }
                    }
                }
            }
        }

        self.processing_target = self.processing_target.max(validating_epoch);
        let old_start = self.start_epoch;
        self.start_epoch = validating_epoch;
        self.to_be_downloaded = self.to_be_downloaded.max(validating_epoch);
        if self.batches.contains_key(&self.to_be_downloaded) {
            // if a chain is advanced by Range beyond the previous `self.to_be_downloaded`, we
            // won't have this batch, so we need to request it.
            self.to_be_downloaded += EPOCHS_PER_BATCH;
        }
        if let Some(epoch) = self.optimistic_start {
            if epoch <= validating_epoch {
                self.optimistic_start = None;
            }
        }
        debug!(self.log, "Chain advanced"; "previous_start" => old_start,
            "new_start" => self.start_epoch, "processing_target" => self.processing_target);
    }

    /// An invalid batch has been received that could not be processed, but that can be retried.
    ///
    /// These events occur when a peer has successfully responded with blocks, but the blocks we
    /// have received are incorrect or invalid. This indicates the peer has not performed as
    /// intended and can result in downvoting a peer.
    fn handle_invalid_batch(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch_id: BatchId,
    ) -> ProcessingResult {
        // The current batch could not be processed, indicating either the current or previous
        // batches are invalid.

        // The previous batch could be incomplete due to the block sizes being too large to fit in
        // a single RPC request or there could be consecutive empty batches which are not supposed
        // to be there

        // The current (sub-optimal) strategy is to simply re-request all batches that could
        // potentially be faulty. If a batch returns a different result than the original and
        // results in successful processing, we downvote the original peer that sent us the batch.

        if let Some(epoch) = self.optimistic_start {
            // If this batch is an optimistic batch, we reject this epoch as an optimistic
            // candidate and try to re download it
            if epoch == batch_id {
                return self.reject_optimistic_batch(network, true, "batch was invalid");
                // since this is the optimistic batch, we can't consider previous batches as
                // invalid.
            }
        }
        // this is our robust `processing_target`. All previous batches must be awaiting
        // validation
        let mut redownload_queue = Vec::new();

        for (id, batch) in self.batches.range_mut(..batch_id) {
            if batch.validation_failed()? {
                // remove the chain early
                return Err(RemoveChain::ChainFailed(batch_id));
            }
            redownload_queue.push(*id);
        }

        // no batch maxed out it process attempts, so now the chain's volatile progress must be
        // reset
        self.processing_target = self.start_epoch;

        for id in redownload_queue {
            self.retry_batch_download(network, id)?;
        }
        // finally, re-request the failed batch.
        self.retry_batch_download(network, batch_id)
    }

    pub fn stop_syncing(&mut self) {
        self.state = ChainSyncingState::Stopped;
    }

    /// Either a new chain, or an old one with a peer list
    /// This chain has been requested to start syncing.
    ///
    /// This could be new chain, or an old chain that is being resumed.
    pub fn start_syncing(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        local_finalized_epoch: Epoch,
        optimistic_start_epoch: Epoch,
    ) -> ProcessingResult {
        // to avoid dropping local progress, we advance the chain wrt its batch boundaries. This
        let align = |epoch| {
            // start_epoch + (number of batches in between)*length_of_batch
            self.start_epoch + ((epoch - self.start_epoch) / EPOCHS_PER_BATCH) * EPOCHS_PER_BATCH
        };
        // get the *aligned* epoch that produces a batch containing the `local_finalized_epoch`
        let validating_epoch = align(local_finalized_epoch);
        // align the optimistic_start too.
        let optimistic_epoch = align(optimistic_start_epoch);

        // advance the chain to the new validating epoch
        self.advance_chain(network, validating_epoch);
        if self.optimistic_start.is_none()
            && optimistic_epoch > self.processing_target
            && !self.attempted_optimistic_starts.contains(&optimistic_epoch)
        {
            self.optimistic_start = Some(optimistic_epoch);
        }

        // update the state
        self.state = ChainSyncingState::Syncing;

        // begin requesting blocks from the peer pool, until all peers are exhausted.
        self.request_batches(network)?;

        // start processing batches if needed
        self.process_completed_batches(network)
    }

    /// Add a peer to the chain.
    ///
    /// If the chain is active, this starts requesting batches from this peer.
    pub fn add_peer(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        peer_id: PeerId,
    ) -> ProcessingResult {
        // add the peer without overwriting its active requests
        if self.peers.entry(peer_id).or_default().is_empty() {
            // Either new or not, this peer is idle, try to request more batches
            self.request_batches(network)
        } else {
            Ok(KeepChain)
        }
    }

    /// An RPC error has occurred.
    ///
    /// If the batch exists it is re-requested.
    pub fn inject_error(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch_id: BatchId,
        peer_id: &PeerId,
        request_id: RequestId,
    ) -> ProcessingResult {
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            // A batch could be retried without the peer failing the request (disconnecting/
            // sending an error /timeout) if the peer is removed from the chain for other
            // reasons. Check that this block belongs to the expected peer
            if !batch.is_expecting_block(peer_id, &request_id) {
                return Ok(KeepChain);
            }
            debug!(self.log, "Batch failed. RPC Error"; "batch_epoch" => batch_id);
            if let Some(active_requests) = self.peers.get_mut(peer_id) {
                active_requests.remove(&batch_id);
            }
            if batch.download_failed(true)? {
                return Err(RemoveChain::ChainFailed(batch_id));
            }
            self.retry_batch_download(network, batch_id)
        } else {
            // this could be an error for an old batch, removed when the chain advances
            Ok(KeepChain)
        }
    }

    /// Sends and registers the request of a batch awaiting download.
    pub fn retry_batch_download(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch_id: BatchId,
    ) -> ProcessingResult {
        let batch = match self.batches.get_mut(&batch_id) {
            Some(batch) => batch,
            None => return Ok(KeepChain),
        };

        // Find a peer to request the batch
        let failed_peers = batch.failed_peers();

        let new_peer = {
            let mut priorized_peers = self
                .peers
                .iter()
                .map(|(peer, requests)| (failed_peers.contains(peer), requests.len(), *peer))
                .collect::<Vec<_>>();
            // Sort peers prioritizing unrelated peers with less active requests.
            priorized_peers.sort_unstable();
            priorized_peers.get(0).map(|&(_, _, peer)| peer)
        };

        if let Some(peer) = new_peer {
            self.send_batch(network, batch_id, peer)
        } else {
            // If we are here the chain has no more peers
            Err(RemoveChain::EmptyPeerPool)
        }
    }

    /// Requests the batch assigned to the given id from a given peer.
    pub fn send_batch(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch_id: BatchId,
        peer: PeerId,
    ) -> ProcessingResult {
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            let request = batch.to_blocks_by_range_request();
            match network.blocks_by_range_request(peer, request, self.id, batch_id) {
                Ok(request_id) => {
                    // inform the batch about the new request
                    batch.start_downloading_from_peer(peer, request_id)?;
                    if self
                        .optimistic_start
                        .map(|epoch| epoch == batch_id)
                        .unwrap_or(false)
                    {
                        debug!(self.log, "Requesting optimistic batch"; "epoch" => batch_id, &batch);
                    } else {
                        debug!(self.log, "Requesting batch"; "epoch" => batch_id, &batch);
                    }
                    // register the batch for this peer
                    return self
                        .peers
                        .get_mut(&peer)
                        .map(|requests| {
                            requests.insert(batch_id);
                            Ok(KeepChain)
                        })
                        .unwrap_or_else(|| {
                            Err(RemoveChain::WrongChainState(format!(
                                "Sending batch to a peer that is not in the chain: {}",
                                peer
                            )))
                        });
                }
                Err(e) => {
                    // NOTE: under normal conditions this shouldn't happen but we handle it anyway
                    warn!(self.log, "Could not send batch request";
                        "batch_id" => batch_id, "error" => e, &batch);
                    // register the failed download and check if the batch can be retried
                    batch.start_downloading_from_peer(peer, 1)?; // fake request_id is not relevant
                    self.peers
                        .get_mut(&peer)
                        .map(|request| request.remove(&batch_id));
                    if batch.download_failed(true)? {
                        return Err(RemoveChain::ChainFailed(batch_id));
                    } else {
                        return self.retry_batch_download(network, batch_id);
                    }
                }
            }
        }

        Ok(KeepChain)
    }

    /// Returns true if this chain is currently syncing.
    pub fn is_syncing(&self) -> bool {
        match self.state {
            ChainSyncingState::Syncing => true,
            ChainSyncingState::Stopped => false,
        }
    }

    /// Attempts to request the next required batches from the peer pool if the chain is syncing. It will exhaust the peer
    /// pool and left over batches until the batch buffer is reached or all peers are exhausted.
    fn request_batches(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
    ) -> ProcessingResult {
        if !matches!(self.state, ChainSyncingState::Syncing) {
            return Ok(KeepChain);
        }

        // find the next pending batch and request it from the peer

        // randomize the peers for load balancing
        let mut rng = rand::thread_rng();
        let mut idle_peers = self
            .peers
            .iter()
            .filter_map(|(peer, requests)| {
                if requests.is_empty() {
                    Some(*peer)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();
        idle_peers.shuffle(&mut rng);

        // check if we have the batch for our optimistic start. If not, request it first.
        // We wait for this batch before requesting any other batches.
        if let Some(epoch) = self.optimistic_start {
            if let Entry::Vacant(entry) = self.batches.entry(epoch) {
                if let Some(peer) = idle_peers.pop() {
                    let optimistic_batch = BatchInfo::new(&epoch, EPOCHS_PER_BATCH);
                    entry.insert(optimistic_batch);
                    self.send_batch(network, epoch, peer)?;
                }
            }
            return Ok(KeepChain);
        }

        while let Some(peer) = idle_peers.pop() {
            if let Some(batch_id) = self.include_next_batch() {
                // send the batch
                self.send_batch(network, batch_id, peer)?;
            } else {
                // No more batches, simply stop
                return Ok(KeepChain);
            }
        }

        Ok(KeepChain)
    }

    /// Creates the next required batch from the chain. If there are no more batches required,
    /// `false` is returned.
    fn include_next_batch(&mut self) -> Option<BatchId> {
        // don't request batches beyond the target head slot
        if self
            .to_be_downloaded
            .start_slot(T::EthSpec::slots_per_epoch())
            >= self.target_head_slot
        {
            return None;
        }
        // only request batches up to the buffer size limit
        // NOTE: we don't count batches in the AwaitingValidation state, to prevent stalling sync
        // if the current processing window is contained in a long range of skip slots.
        let in_buffer = |batch: &BatchInfo<T::EthSpec>| {
            matches!(
                batch.state(),
                BatchState::Downloading(..) | BatchState::AwaitingProcessing(..)
            )
        };
        if self
            .batches
            .iter()
            .filter(|&(_epoch, batch)| in_buffer(batch))
            .count()
            > BATCH_BUFFER_SIZE as usize
        {
            return None;
        }

        let batch_id = self.to_be_downloaded;
        // this batch could have been included already being an optimistic batch
        match self.batches.entry(batch_id) {
            Entry::Occupied(_) => {
                // this batch doesn't need downloading, let this same function decide the next batch
                self.to_be_downloaded += EPOCHS_PER_BATCH;
                self.include_next_batch()
            }
            Entry::Vacant(entry) => {
                entry.insert(BatchInfo::new(&batch_id, EPOCHS_PER_BATCH));
                self.to_be_downloaded += EPOCHS_PER_BATCH;
                Some(batch_id)
            }
        }
    }
}

impl<T: BeaconChainTypes> slog::KV for &mut SyncingChain<T> {
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        slog::KV::serialize(*self, record, serializer)
    }
}

impl<T: BeaconChainTypes> slog::KV for SyncingChain<T> {
    fn serialize(
        &self,
        record: &slog::Record,
        serializer: &mut dyn slog::Serializer,
    ) -> slog::Result {
        use slog::Value;
        serializer.emit_u64("id", self.id)?;
        Value::serialize(&self.start_epoch, record, "from", serializer)?;
        Value::serialize(
            &self.target_head_slot.epoch(T::EthSpec::slots_per_epoch()),
            record,
            "to",
            serializer,
        )?;
        serializer.emit_arguments("end_root", &format_args!("{}", self.target_head_root))?;
        Value::serialize(
            &self.processing_target,
            record,
            "current_target",
            serializer,
        )?;
        serializer.emit_usize("batches", self.batches.len())?;
        serializer.emit_usize("peers", self.peers.len())?;
        serializer.emit_u64("validated_batches", self.validated_batches)?;
        serializer.emit_arguments("state", &format_args!("{:?}", self.state))?;
        slog::Result::Ok(())
    }
}

use super::batch::WrongState as WrongBatchState;
impl From<WrongBatchState> for RemoveChain {
    fn from(err: WrongBatchState) -> Self {
        RemoveChain::WrongBatchState(err.0)
    }
}

impl RemoveChain {
    pub fn is_critical(&self) -> bool {
        matches!(
            self,
            RemoveChain::WrongBatchState(..) | RemoveChain::WrongChainState(..)
        )
    }
}
