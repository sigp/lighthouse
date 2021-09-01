//! This module contains the logic for Lighthouse's backfill sync.
//!
//! This kind of sync occurs when a trusted state root is provided to the client. The client
//! will perform a [`RangeSync`] to the latest head from the trusted state root, such that the
//! client can perform its duties right away. Once completed, a backfill sync occurs, where all old
//! blocks (from genesis) are downloaded in order to keep a consistent history.
//!
//! If a batch fails, the backfill sync cannot progress. In this scenario, we mark the backfill
//! sync as failed, log an error and attempt to retry once a new peer joins the node.

use super::RequestId;
use crate::beacon_processor::{ProcessId, WorkEvent as BeaconWorkEvent};
use crate::sync::manager::BatchProcessResult;
use crate::sync::network_context::SyncNetworkContext;
use crate::sync::range_sync::{BatchConfig, BatchId, BatchInfo, BatchState};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_libp2p::types::NetworkGlobals;
use eth2_libp2p::{PeerAction, PeerId};
use slog::{crit, debug, error, warn};
use std::collections::{
    hash_map::{Entry, HashMap},
    BTreeMap, HashSet,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use types::{Epoch, EthSpec, Hash256, SignedBeaconBlock};

/// Blocks are downloaded in batches from peers. This constant specifies how many epochs worth of
/// blocks per batch are requested _at most_. A batch may request less blocks to account for
/// already requested slots. There is a timeout for each batch request. If this value is too high,
/// we will negatively report peers with poor bandwidth. This can be set arbitrarily high, in which
/// case the responder will fill the response up to the max request size, assuming they have the
/// bandwidth to do so.
pub const BACKFILL_EPOCHS_PER_BATCH: u64 = 2;

/// The maximum number of batches to queue before requesting more.
const BACKFILL_BATCH_BUFFER_SIZE: u8 = 5;

/// The number of times to retry a batch before it is considered failed.
const MAX_BATCH_DOWNLOAD_ATTEMPTS: u8 = 10;

/// Invalid batches are attempted to be re-downloaded from other peers. If a batch cannot be processed
/// after `MAX_BATCH_PROCESSING_ATTEMPTS` times, it is considered faulty.
const MAX_BATCH_PROCESSING_ATTEMPTS: u8 = 10;

/// Custom configuration for the batch object.
struct BackFillBatchConfig {}

impl BatchConfig for BackFillBatchConfig {
    fn max_batch_download_attempts() -> u8 {
        MAX_BATCH_DOWNLOAD_ATTEMPTS
    }
    fn max_batch_processing_attempts() -> u8 {
        MAX_BATCH_PROCESSING_ATTEMPTS
    }
}

/// Return type when attempting to start the backfill sync process.
pub enum SyncStart {
    /// The chain started syncing.
    Syncing {
        /// The number of slots that have been processed so far.
        completed: usize,
        /// The number of slots still to be processed.
        remaining: usize,
    },
    /// The chain didn't start syncing.
    NotSyncing,
}

/// A standard result from calling public functions on [`BackFillSync`].
pub enum ProcessingResult {
    /// The call was successful.
    Successful,
    /// The call resulted in completing the backfill sync.
    SyncCompleted,
}

pub struct BackFillSync<T: BeaconChainTypes> {
    /// The current state of the backfill sync.
    state: BackFillState,

    /// Keeps track of the current progress of the backfill.
    /// This only gets refreshed from the beacon chain if we enter a failed state.
    current_start: BatchId,

    /// Starting epoch of the next batch that needs to be downloaded.
    to_be_downloaded: BatchId,

    /// Keeps track if we have requested the final batch.
    last_batch_downloaded: bool,

    /// Sorted map of batches undergoing some kind of processing.
    batches: BTreeMap<BatchId, BatchInfo<T::EthSpec, BackFillBatchConfig>>,

    /// List of peers we are currently awaiting a response for.
    active_requests: HashMap<PeerId, HashSet<BatchId>>,

    /// The current processing batch, if any.
    current_processing_batch: Option<BatchId>,

    /// Batches validated by this chain.
    validated_batches: u64,

    /// Reference to the beacon chain to obtain initial starting points for the backfill sync.
    beacon_chain: Arc<BeaconChain<T>>,

    /// Reference to the network globals in order to obtain valid peers to backfill blocks from
    /// (i.e synced peers).
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,

    /// A multi-threaded, non-blocking processor for processing batches in the beacon chain.
    beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T>>,

    /// A logger for backfill sync.
    log: slog::Logger,
}

#[derive(PartialEq, Debug)]
/// The state of the backfill sync.
pub enum BackFillState {
    /// The sync is partially completed and currently paused.
    Paused,
    /// We are currently backfilling.
    Syncing,
    /// A backfill sync has completed.
    Completed,
    /// A backfill sync is not required.
    NotRequired,
    /// Too many failed attempts at backfilling. Consider it failed.
    Failed,
}

impl<T: BeaconChainTypes> BackFillSync<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
        beacon_processor_send: mpsc::Sender<BeaconWorkEvent<T>>,
        log: slog::Logger,
    ) -> Self {
        // Determine if backfill is enabled or not.
        // Get the anchor info, if this returns None, then backfill is not required for this
        // running instance.
        // If, for some reason a backfill has already been completed (or we've used a trusted
        // genesis root, then backfill has been completed.

        let (state, current_start) = if let Some(anchor_info) = beacon_chain.store.get_anchor_info()
        {
            if anchor_info.oldest_block_parent == Hash256::zero() {
                (BackFillState::Completed, Epoch::new(0))
            } else {
                (
                    BackFillState::Paused,
                    anchor_info
                        .oldest_block_slot
                        .epoch(T::EthSpec::slots_per_epoch()),
                )
            }
        } else {
            (BackFillState::NotRequired, Epoch::new(0))
        };

        BackFillSync {
            state,
            batches: BTreeMap::new(),
            active_requests: HashMap::new(),
            current_start,
            last_batch_downloaded: false,
            to_be_downloaded: current_start,
            network_globals,
            current_processing_batch: None,
            validated_batches: 0,
            beacon_chain,
            beacon_processor_send,
            log,
        }
    }

    /// Pauses the backfill sync if it's currently syncing.
    pub fn pause(&mut self) {
        match self.state {
            BackFillState::Syncing => {
                debug!(self.log, "Backfill sync paused"; "processed_epochs" => self.validated_batches, "to_be_processed" => self.current_start);
                self.state = BackFillState::Paused;
            }
            _ => {} // All other states we ignore
        }
    }

    /// Starts or resumes syncing.
    ///
    /// If resuming is successful, reports back the current syncing metrics.
    pub fn start(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
    ) -> Result<SyncStart, String> {
        match self.state {
            BackFillState::Syncing => {
                warn!(self.log, "Backfill requested but already syncing");
            }
            BackFillState::Paused => {
                debug!(self.log, "Resuming backfill sync"; "start_epoch" => self.current_start, "awaiting_batches" => self.batches.len());
                self.state = BackFillState::Syncing;
                // begin requesting blocks from the peer pool, until all peers are exhausted.
                self.request_batches(network)?;
                // TODO: Change Sync state

                // start processing batches if needed
                self.process_completed_batches(network);
            }
            BackFillState::Failed => {
                // Attempt to recover from a failed sync. All local variables should be reset and
                // cleared already for a fresh start.

                self.state = BackFillState::Syncing;

                // Obtain a new start slot, from the beacon chain.
                self.reset_start_epoch()?;

                debug!(self.log, "Resuming a failed backfill sync"; "start_epoch" => self.current_start);

                // begin requesting blocks from the peer pool, until all peers are exhausted.
                if let Err(e) = self.request_batches(network)? {
                    // TODO: Change Sync state
                }
            }
            BackFillState::Completed | BackFillState::NotRequired => {
                return Ok(SyncStart::NotSyncing)
            }
        }

        Ok(SyncStart::Syncing {
            completed: (self.validated_batches
                * BACKFILL_EPOCHS_PER_BATCH
                * T::EthSpec::slots_per_epoch()) as usize,
            remaining: self
                .current_start
                .start_slot(T::EthSpec::slots_per_epoch())
                .as_usize(),
        })
    }

    /// A peer has disconnected.
    /// If the peer has active batches, those are considered failed and re-requested.
    pub fn peer_disconnected(
        &mut self,
        peer_id: &PeerId,
        network: &mut SyncNetworkContext<T::EthSpec>,
    ) {
        if let Some(batch_ids) = self.active_requests.remove(peer_id) {
            // fail the batches
            for id in batch_ids {
                if let Some(batch) = self.batches.get_mut(&id) {
                    if batch.download_failed()? {
                        return Err(RemoveChain::ChainFailed(id));
                    }
                    self.retry_batch_download(network, id)?;
                } else {
                    debug!(self.log, "Batch not found while removing peer";
                        "peer" => %peer_id, "batch" => id)
                }
            }
        }

        // If we have no more peers, consider the state paused.
        if self.network_globals.synced_peers().next().is_none() {
            self.state = BackFillState::Paused
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
                return Ok(());
            }
            debug!(self.log, "Batch failed. RPC Error"; "batch_epoch" => batch_id);
            if let Some(active_requests) = self.active_requests.get_mut(peer_id) {
                active_requests.remove(&batch_id);
            }
            if batch.download_failed()? {
                return Err(RemoveChain::ChainFailed(batch_id));
            }
            self.retry_batch_download(network, batch_id)
        } else {
            // this could be an error for an old batch, removed when the chain advances
            Ok(())
        }
    }

    /// A block has been received for a batch relating to this backfilling chain.
    /// If the block correctly completes the batch it will be processed if possible.
    /// If this returns an error, the backfill sync has failed and will be restarted once new peers
    /// join the system.
    /// The sync manager should update the global sync state on failure.
    #[must_use = "A failure here indicates the backfill sync has failed and the global sync state should be updated"]
    pub fn on_block_response(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch_id: BatchId,
        peer_id: &PeerId,
        request_id: RequestId,
        beacon_block: Option<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<(), String> {
        // check if we have this batch
        let batch = match self.batches.get_mut(&batch_id) {
            None => {
                debug!(self.log, "Received a block for unknown batch"; "epoch" => batch_id);
                // A batch might get removed when the chain advances, so this is non fatal.
                return self.state;
            }
            Some(batch) => {
                // A batch could be retried without the peer failing the request (disconnecting/
                // sending an error /timeout) if the peer is removed from the chain for other
                // reasons. Check that this block belongs to the expected peer, and that the
                // request_id matches
                if !batch.is_expecting_block(peer_id, &request_id) {
                    return self.state;
                }
                batch
            }
        };

        if let Some(block) = beacon_block {
            // This is not a stream termination, simply add the block to the request
            batch.add_block(block)?;
            Ok(())
        } else {
            // A stream termination has been sent. This batch has ended. Process a completed batch.
            // Remove the request from the peer's active batches
            self.active_requests
                .get_mut(peer_id)
                .map(|active_requests| active_requests.remove(&batch_id));

            match batch.download_completed() {
                Ok(received) => {
                    // TODO: Report the total awaiting, not just for this batch.
                    let awaiting_batches =
                        batch_id.saturating_sub(self.processing_target) / BACKFILL_EPOCHS_PER_BATCH;
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
                        error!(self.log, "Backfill failed"; "epoch" => batch_id, "blocks" => received, "awaiting_batches" =>  awaiting_batches);
                        return Err("Batch failed");
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
    ) -> Result<(), String> {
        // Only process batches if this chain is Syncing, and only one at a time
        if self.state != BackFillState::Syncing || self.current_processing_batch.is_some() {
            return Ok(());
        }

        let batch = match self.batches.get_mut(&batch_id) {
            Some(batch) => batch,
            None => {
                return Err(
                    "Trying to process a batch that does not exist: {}",
                    batch_id,
                );
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
            .try_send(BeaconWorkEvent::backfill_segment(process_id, blocks))
        {
            crit!(self.log, "Failed to send backfill segment to processor."; "msg" => "process_batch",
                "error" => %e, "batch" => self.processing_target);
            // This is unlikely to happen but it would stall syncing since the batch now has no
            // blocks to continue, and the chain is expecting a processing result that won't
            // arrive.  To mitigate this, (fake) fail this processing so that the batch is
            // re-downloaded.
            self.on_batch_process_result(network, batch_id, &BatchProcessResult::Failed(false))
        } else {
            Ok(())
        }
    }

    /// The block processor has completed processing a batch. This function handles the result
    /// of the batch processor.
    /// If an error is returned the BackFill sync has failed.
    #[must_use = "A failure here indicates the backfill sync has failed and the global sync state should be updated"]
    fn on_batch_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch_id: BatchId,
        result: &BatchProcessResult,
    ) -> Result<OkResult, String> {
        // The first two cases are possible in regular sync, should not occur in backfill, but we
        // keep this logic for handling potential processing race conditions.
        // result
        match &self.current_processing_batch {
            Some(processing_id) if *processing_id != batch_id => {
                debug!(self.log, "Unexpected batch result";
                    "batch_epoch" => batch_id, "expected_batch_epoch" => processing_id);
                return Ok(OkResult::Successful);
            }
            None => {
                debug!(self.log, "Chain was not expecting a batch result";
                    "batch_epoch" => batch_id);
                return Ok(OkResult::Successful);
            }
            _ => {
                // batch_id matches, continue
                self.current_processing_batch = None;
            }
        }

        match result {
            BatchProcessResult::Success(was_non_empty) => {
                let batch = self.batches.get_mut(&batch_id).ok_or_else(|| {
                    return self
                        .fail_chain(format!("Current processing batch not found: {}", batch_id));
                })?;

                if let Err(e) = batch.processing_completed(true) {
                    return self
                        .fail_chain(format!("Invalid batch processing state: {}", batch_id));
                }
                // If the processed batch was not empty, we can validate previous unvalidated
                // blocks.
                if *was_non_empty {
                    self.advance_chain(network, batch_id);
                }

                if batch_id == self.processing_target {
                    self.processing_target -= BACKFILL_EPOCHS_PER_BATCH;
                }

                // check if the chain has completed syncing
                if self.check_completed() {
                    // chain is completed
                    Ok(OkResult::SyncCompleted)
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
                    format!("Batch not found for current processing target {}", batch_id)
                })?;
                let peer = batch.current_peer().cloned().ok_or_else(|| {
                    format!("Processing target is in wrong state: {:?}", batch.state(),)
                })?;
                debug!(self.log, "Batch processing failed"; "imported_blocks" => imported_blocks,
                    "batch_epoch" => batch_id, "peer" => %peer, "client" => %network.client_type(&peer));
                match batch.processing_completed(false) {
                    Err(e) => {
                        // Batch was in the wrong state
                        return self
                            .fail_chain(format!("Batch failed to process: {} : {}", batch_id, e));
                    }
                    Ok(true) => {
                        // check that we have not exceeded the re-process retry counter
                        // If a batch has exceeded the invalid batch lookup attempts limit, it means
                        // that it is likely all peers are sending invalid batches
                        // repeatedly and are either malicious or faulty. We stop the backfill sync and
                        // report all peers.
                        let action = PeerAction::LowToleranceError;
                        warn!(self.log, "Backfill batch failed to download. Penalizing peers";
                        "score_adjustment" => %action,
                        "batch_epoch"=> batch_id);
                        for (peer, _) in self.peers.drain() {
                            network.report_peer(peer, action);
                        }
                        return Err(format!(
                            "Batch {} failed exceeded maximum retries.",
                            batch_id
                        ));
                    }

                    Ok(false) => {
                        // chain can continue. Check if it can be progressed
                        if *imported_blocks {
                            // At least one block was successfully verified and imported, then we can be sure all
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
    }

    /// Processes the next ready batch.
    fn process_completed_batches(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
    ) -> Result<(), String> {
        // Only process batches if this chain is Syncing and only process one batch at a time
        if self.state != BackFillState::Syncing || self.current_processing_batch.is_some() {
            return Ok(());
        }

        // Find the id of the batch we are going to process.
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
                    return Err(format!(
                        "Robust target batch indicates inconsistent chain state: {:?}",
                        state
                    ));
                }
                BatchState::AwaitingValidation(_) => {
                    // TODO: I don't think this state is possible, log a CRIT just incase.
                    // If this is not observered, add it to the failed state branch above.
                    crit!(self.log, "Chain encountered a robust batch awaiting validation"; "batch" => self.processing_target);

                    self.processing_target += BACKFILL_EPOCHS_PER_BATCH;
                    if self.to_be_downloaded <= self.processing_target {
                        self.to_be_downloaded = self.processing_target + BACKFILL_EPOCHS_PER_BATCH;
                    }
                    self.request_batches(network)?;
                }
            }
        } else {
            return Err(format!(
                "Batch not found for current processing target {}",
                self.processing_target
            ));
        }
        Ok(())
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
        if validating_epoch >= self.get_current_required_batch() {
            return;
        }

        // batches in the range [BatchId, ..) (validated, higher batches are processed)
        let removed_batches = self.batches.split_off(&validating_epoch);

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
                    if let Some(active_requests) = self.active_requests.get_mut(peer) {
                        active_requests.remove(&id);
                    }
                }
                BatchState::Failed | BatchState::Poisoned | BatchState::AwaitingDownload => {
                    crit!(
                        self.log,
                        "batch indicates inconsistent chain state while advancing chain"
                    )
                }
                BatchState::AwaitingProcessing(..) => {}
                BatchState::Processing(_) => {
                    debug!(self.log, "Advancing chain while processing a batch"; "batch" => id, batch);
                    if let Some(processing_id) = self.current_processing_batch {
                        if id >= processing_id {
                            self.current_processing_batch = None;
                        }
                    }
                }
            }
        }

        self.processing_target = self.processing_target.min(validating_epoch);
        self.current_start = validating_epoch;
        self.to_be_downloaded = self.to_be_downloaded.min(validating_epoch);
        if self.batches.contains_key(&self.to_be_downloaded) {
            // if a chain is advanced by Range beyond the previous `self.to_be_downloaded`, we
            // won't have this batch, so we need to request it.
            self.to_be_downloaded -= BACKFILL_EPOCHS_PER_BATCH;
        }
        debug!(self.log, "Backfill advanced"; "validated_epoch" => validated_epoch, "processing_target" => self.processing_target);
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
    ) -> Result<OkResult, BackSyncFailed> {
        // The current batch could not be processed, indicating either the current or previous
        // batches are invalid.

        // The previous batch could be incomplete due to the block sizes being too large to fit in
        // a single RPC request or there could be consecutive empty batches which are not supposed
        // to be there

        // The current (sub-optimal) strategy is to simply re-request all batches that could
        // potentially be faulty. If a batch returns a different result than the original and
        // results in successful processing, we downvote the original peer that sent us the batch.

        // this is our robust `processing_target`. All previous batches must be awaiting
        // validation
        let mut redownload_queue = Vec::new();

        for (id, batch) in self.batches.range_mut(..batch_id) {
            match batch.validation_failed() {
                Err(e) => {
                    return self
                        .fail_chain(format!("Invalid batch validation: {} : {}", batch_id, e));
                }
                Ok(true) => {
                    // Batch has failed
                    return self.fail_chain(format!("Batch failed: {} : {}", batch_id, e));
                }
                Ok(false) => {
                    redownload_queue.push(*id);
                }
            }
        }

        // no batch maxed out it process attempts, so now the chain's volatile progress must be
        // reset
        self.processing_target = self.current_start;

        for id in redownload_queue {
            self.retry_batch_download(network, id)?;
        }
        // finally, re-request the failed batch.
        self.retry_batch_download(network, batch_id)
    }

    /// Sends and registers the request of a batch awaiting download.
    fn retry_batch_download(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
        batch_id: BatchId,
    ) -> ProcessingResult {
        let batch = match self.batches.get_mut(&batch_id) {
            Some(batch) => batch,
            None => return Ok(()),
        };

        // Find a peer to request the batch
        let failed_peers = batch.failed_peers();

        let new_peer = {
            let mut priorized_peers = self
                .network_globals
                .peers()
                .read()
                .synced_peers()
                .map(|(peer, requests)| (failed_peers.contains(peer), requests.len(), *peer))
                .collect::<Vec<_>>();
            // Sort peers prioritizing unrelated peers with less active requests.
            priorized_peers.sort_unstable();
            priorized_peers.get(0).map(|&(_, _, peer)| peer)
        };

        if let Some(peer) = new_peer {
            self.send_batch(network, batch_id, peer)
        } else {
            // If we are here the chain has no more synced peers
            self.state = BackFilState::Paused;
            Err(ChainPaused)
        }
    }

    /// Requests the batch assigned to the given id from a given peer.
    fn send_batch(
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
                    debug!(self.log, "Requesting batch"; "epoch" => batch_id, &batch);

                    // register the batch for this peer
                    self.active_requests
                        .entry(peer)
                        .or_default()
                        .insert(batch_id);
                    return Ok(());
                }
                Err(e) => {
                    // NOTE: under normal conditions this shouldn't happen but we handle it anyway
                    warn!(self.log, "Could not send batch request";
                        "batch_id" => batch_id, "error" => e, &batch);
                    // register the failed download and check if the batch can be retried
                    batch.start_downloading_from_peer(peer, 1)?; // fake request_id is not relevant
                    self.active_requests
                        .get_mut(&peer)
                        .map(|request| request.remove(&batch_id));
                    if batch.download_failed()? {
                        return Err(ChainFailed(batch_id));
                    } else {
                        return self.retry_batch_download(network, batch_id);
                    }
                }
            }
        }

        Ok(())
    }

    /// Attempts to request the next required batches from the peer pool if the chain is syncing. It will exhaust the peer
    /// pool and left over batches until the batch buffer is reached or all peers are exhausted.
    fn request_batches(
        &mut self,
        network: &mut SyncNetworkContext<T::EthSpec>,
    ) -> ProcessingResult {
        if !matches!(self.state, ChainSyncingState::Syncing) {
            return Ok(());
        }

        // find the next pending batch and request it from the peer

        // randomize the peers for load balancing
        let mut rng = rand::thread_rng();
        let mut idle_peers = self
            .network_globals
            .peers
            .read()
            .synced_peers()
            .filter(|peer_id| {
                self.active_requests
                    .get(peer_id)
                    .map(|requests| requests.is_empty())
                    .unwrap_or(true)
            })
            .collect::<Vec<_>>();

        idle_peers.shuffle(&mut rng);

        while let Some(peer) = idle_peers.pop() {
            if let Some(batch_id) = self.include_next_batch() {
                // send the batch
                self.send_batch(network, batch_id, peer)?;
            } else {
                // No more batches, simply stop
                return Ok(());
            }
        }
        Ok(())
    }

    /// Creates the next required batch from the chain. If there are no more batches required,
    /// `false` is returned.
    fn include_next_batch(&mut self) -> Option<BatchId> {
        // don't request batches beyond genesis;
        if self.last_batch_downloaded {
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
            > BACKFILL_BATCH_BUFFER_SIZE as usize
        {
            return None;
        }

        let batch_id = self.to_be_downloaded;
        // this batch could have been included already being an optimistic batch
        match self.batches.entry(batch_id) {
            Entry::Occupied(_) => {
                // this batch doesn't need downloading, let this same function decide the next batch
                if batch_id == 0 {
                    self.last_batch_downloaded = true;
                }

                self.to_be_downloaded = self
                    .to_be_downloaded
                    .saturating_sub(BACKFILL_EPOCHS_PER_BATCH);
                self.include_next_batch()
            }
            Entry::Vacant(entry) => {
                entry.insert(BatchInfo::new(&batch_id, BACKFILL_EPOCHS_PER_BATCH));
                if batch_id == 0 {
                    self.last_batch_downloaded = true;
                }
                self.to_be_downloaded =
                    self_to_be_downloaded.saturating_sub(BACKFILL_EPOCHS_PER_BATCH);
                Some(batch_id)
            }
        }
    }

    /// Resets the start epoch based on the beacon chain.
    ///
    /// This errors if the beacon chain indicates that backfill sync has already completed or is
    /// not required.
    fn reset_start_epoch(&mut self) -> Result<(), String> {
        if let Some(anchor_info) = self.beacon_chain.store.get_anchor_info() {
            if anchor_info.oldest_block_parent == Hash256::zero() {
                return Err(String::from("Backfill chain already completed"));
            } else {
                self.current_start = anchor_info
                    .oldest_block_slot
                    .epoch(T::EthSpec::slots_per_epoch());
                return Ok(());
            }
        } else {
            return Err("Backfill is not required");
        }
    }
}
