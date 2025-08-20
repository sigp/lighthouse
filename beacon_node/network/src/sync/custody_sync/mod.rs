use std::{
    collections::{BTreeMap, HashSet, btree_map::Entry},
    sync::Arc,
};

use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::{
    NetworkGlobals, PeerAction, PeerId, service::api_types::CustodySyncBatchRequestId,
    types::CustodyBackFillState,
};
use logging::crit;
use tracing::{debug, error, info, warn};

use types::{ColumnIndex, DataColumnSidecarList, Epoch, EthSpec, Slot};

use crate::sync::{
    backfill_sync::{ProcessResult, SyncStart},
    custody_sync::batch::{CustodyBatchInfo, CustodyBatchState},
    manager::CustodyBatchProcessResult,
    network_context::{RpcResponseError, SyncNetworkContext},
    range_sync::{BatchId, BatchOperationOutcome, BatchProcessingResult},
};

/// The maximum number of batches to queue before requesting more.
const BACKFILL_BATCH_BUFFER_SIZE: u8 = 20;

mod batch;

/// Columns are downloaded in batches from peers. This constant specifies how many epochs worth of
/// blocks per batch are requested _at most_. A batch may request less blocks to account for
/// already requested slots. There is a timeout for each batch request. If this value is too high,
/// we will negatively report peers with poor bandwidth. This can be set arbitrarily high, in which
/// case the responder will fill the response up to the max request size, assuming they have the
/// bandwidth to do so.
pub const CUSTODY_BACKFILL_EPOCHS_PER_BATCH: u64 = 1;

/// The ways a custody backfill sync can fail.
// The info in the enum variants is displayed in logging, clippy thinks it's dead code.
#[derive(Debug)]
pub enum CustodyBackfillError {
    /// A batch failed to be downloaded.
    BatchDownloadFailed(#[allow(dead_code)] BatchId),
    // /// A batch could not be processed.
    BatchProcessingFailed(#[allow(dead_code)] BatchId),
    /// A batch entered an invalid state.
    BatchInvalidState(#[allow(dead_code)] BatchId, #[allow(dead_code)] String),
    /// The sync algorithm entered an invalid state.
    InvalidSyncState(#[allow(dead_code)] String),
    // /// The chain became paused.
    Paused,
}

pub struct CustodySync<T: BeaconChainTypes> {
    /// Keeps track of the current progress of the custody backfill.
    /// This only gets refreshed from the beacon chain if we enter a failed state.
    current_start: BatchId,

    /// Starting epoch of the batch that needs to be processed next.
    /// This is incremented as the chain advances.
    processing_target: BatchId,

    /// The columns we're targeting for download.
    columns: HashSet<ColumnIndex>,

    /// Starting epoch of the next batch that needs to be downloaded.
    to_be_downloaded: BatchId,

    /// Keeps track if we have requested the final batch.
    last_batch_downloaded: bool,

    /// Sorted map of batches undergoing some kind of processing.
    batches: BTreeMap<BatchId, CustodyBatchInfo<T::EthSpec>>,

    /// The current processing batch, if any.
    current_processing_batch: Option<BatchId>,

    /// Batches validated by this chain.
    validated_batches: u64,

    /// We keep track of peers that are participating in the backfill sync. Unlike RangeSync,
    /// BackFillSync uses all synced peers to download the chain from. If BackFillSync fails, we don't
    /// want to penalize all our synced peers, so we use this variable to keep track of peers that
    /// have participated and only penalize these peers if backfill sync fails.
    participating_peers: HashSet<PeerId>,

    /// When a backfill sync fails, we keep track of whether a new fully synced peer has joined.
    /// This signifies that we are able to attempt to restart a failed chain.
    restart_failed_sync: bool,

    /// Reference to the beacon chain to obtain initial starting points for the backfill sync.
    beacon_chain: Arc<BeaconChain<T>>,

    /// Reference to the network globals in order to obtain valid peers to backfill blocks from
    /// (i.e synced peers).
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
}

impl<T: BeaconChainTypes> CustodySync<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    ) -> Self {
        Self {
            current_start: Epoch::new(0),
            processing_target: Epoch::new(0),
            columns: HashSet::new(),
            to_be_downloaded: Epoch::new(0),
            last_batch_downloaded: false,
            batches: BTreeMap::new(),
            current_processing_batch: None,
            validated_batches: 0,
            participating_peers: HashSet::new(),
            restart_failed_sync: false,
            beacon_chain,
            network_globals,
        }
    }

    /// Pauses the custody sync if it's currently syncing.
    pub fn pause(&mut self) {
        if let CustodyBackFillState::Syncing = self.state() {
            debug!(processed_epochs = %self.validated_batches, to_be_processed = %self.current_start,"Custody backfill sync paused");
            self.set_state(CustodyBackFillState::Paused);
        }
    }

    /// Starts syncing.
    #[must_use = "A failure here indicates the backfill sync has failed and the global sync state should be updated"]
    pub fn start(
        &mut self,
        column_indices: HashSet<ColumnIndex>,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<SyncStart, CustodyBackfillError> {
        match self.state() {
            CustodyBackFillState::Syncing => {
                if self.check_completed() {
                    self.set_state(CustodyBackFillState::Completed);
                    return Ok(SyncStart::NotSyncing);
                }
            } // already syncing ignore.
            CustodyBackFillState::Paused => {
                if self.check_completed() {
                    self.set_state(CustodyBackFillState::Completed);
                    return Ok(SyncStart::NotSyncing);
                }
                self.columns = column_indices;
                self.set_start_epoch()?;
                if self
                    .network_globals
                    .peers
                    .read()
                    .synced_peers()
                    .next()
                    .is_some()
                {
                    // If there are peers to resume with, begin the resume.
                    self.set_state(CustodyBackFillState::Syncing);
                    // Resume any previously failed batches.
                    self.resume_batches(network)?;
                    // begin requesting blocks from the peer pool, until all peers are exhausted.
                    self.request_batches(network)?;

                    // start processing batches if needed
                    self.process_completed_batches(network)?;
                } else {
                    return Ok(SyncStart::NotSyncing);
                }
            }
            CustodyBackFillState::Failed => {
                // Attempt to recover from a failed sync. All local variables should be reset and
                // cleared already for a fresh start.
                // We only attempt to restart a failed backfill sync if a new synced peer has been
                // added.
                // if !self.restart_failed_sync {
                //    return Ok(SyncStart::NotSyncing);
                // }

                self.set_state(CustodyBackFillState::Syncing);

                debug!(start_epoch = %self.current_start, "Resuming a failed backfill sync");

                // begin requesting data columns from the peer pool, until all peers are exhausted.
                self.request_batches(network)?;
            }
            // TODO(custody-sync) Completed looks alot like Paused
            CustodyBackFillState::Completed => {
                if !self.check_completed() {
                    self.columns = column_indices;
                    self.set_start_epoch()?;
                    if self
                        .network_globals
                        .peers
                        .read()
                        .synced_peers()
                        .next()
                        .is_some()
                    {
                        // If there are peers to resume with, begin the resume.
                        self.set_state(CustodyBackFillState::Syncing);
                        // Resume any previously failed batches.
                        self.resume_batches(network)?;
                        // begin requesting blocks from the peer pool, until all peers are exhausted.
                        self.request_batches(network)?;

                        // start processing batches if needed
                        self.process_completed_batches(network)?;
                    } else {
                        return Ok(SyncStart::NotSyncing);
                    }
                }
                return Ok(SyncStart::NotSyncing);
            }
            CustodyBackFillState::Pending { .. } => return Ok(SyncStart::NotSyncing),
        }
        Ok(SyncStart::Syncing {
            completed: (self.validated_batches
                * CUSTODY_BACKFILL_EPOCHS_PER_BATCH
                * T::EthSpec::slots_per_epoch()) as usize,
            remaining: self
                .current_start
                .start_slot(T::EthSpec::slots_per_epoch())
                .saturating_sub(self.beacon_chain.genesis_backfill_slot)
                .as_usize(),
        })
    }

    fn set_start_epoch(&mut self) -> Result<(), CustodyBackfillError> {
        let earliest_data_column_slot = self
            .beacon_chain
            .store
            .get_data_column_custody_info()
            .unwrap_or(None)
            .and_then(|info| info.earliest_data_column_slot)
            .unwrap_or(Slot::new(0));

        self.current_start = earliest_data_column_slot.epoch(T::EthSpec::slots_per_epoch());
        self.processing_target = self.current_start;
        self.to_be_downloaded = self.current_start;
        Ok(())
    }

    /// Attempts to request the next required batches from the peer pool. It will exhaust the peer
    /// pool and left over batches until the batch buffer is reached or all peers are exhausted.
    fn request_batches(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<(), CustodyBackfillError> {
        if !matches!(self.state(), CustodyBackFillState::Syncing) {
            return Ok(());
        }

        // find the next pending batch and request it from the peer
        // Note: for this function to not infinite loop we must:
        // - If `include_next_batch` returns Some we MUST increase the count of batches that are
        //   accounted in the `BACKFILL_BATCH_BUFFER_SIZE` limit in the `matches!` statement of
        //   that function.
        while let Some(batch_id) = self.include_next_batch() {
            // send the batch
            self.send_batch(network, batch_id)?;
        }

        // No more batches, simply stop
        Ok(())
    }

    /// When resuming a chain, this function searches for batches that need to be re-downloaded and
    /// transitions their state to redownload the batch.
    fn resume_batches(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<(), CustodyBackfillError> {
        let batch_ids_to_retry = self
            .batches
            .iter()
            .filter_map(|(batch_id, batch)| {
                // In principle there should only ever be on of these, and we could terminate the
                // loop early, however the processing is negligible and we continue the search
                // for robustness to handle potential future modification
                if matches!(batch.state(), CustodyBatchState::AwaitingDownload) {
                    Some(*batch_id)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for batch_id in batch_ids_to_retry {
            self.send_batch(network, batch_id)?;
        }
        Ok(())
    }

    /// Creates the next required batch from the chain. If there are no more batches required,
    /// `None` is returned.
    fn include_next_batch(&mut self) -> Option<BatchId> {
        // Don't request batches before the Fulu fork epoch
        if let Some(fulu_fork_epoch) = self.beacon_chain.spec.fulu_fork_epoch {
            if self.to_be_downloaded < fulu_fork_epoch {
                return None;
            }
        }

        // Don't request batches beyond the DA window
        if self.last_batch_downloaded {
            return None;
        }

        // Only request batches up to the buffer size limit
        // NOTE: we don't count batches in the AwaitingValidation state, to prevent stalling sync
        // if the current processing window is contained in a long range of skip slots.
        let in_buffer = |batch: &CustodyBatchInfo<T::EthSpec>| {
            matches!(
                batch.state(),
                CustodyBatchState::Downloading(..) | CustodyBatchState::AwaitingProcessing(..)
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
                if self.would_complete(batch_id) {
                    self.last_batch_downloaded = true;
                }

                self.to_be_downloaded = self
                    .to_be_downloaded
                    .saturating_sub(CUSTODY_BACKFILL_EPOCHS_PER_BATCH);
                self.include_next_batch()
            }
            Entry::Vacant(entry) => {
                entry.insert(CustodyBatchInfo::new(
                    &batch_id,
                    CUSTODY_BACKFILL_EPOCHS_PER_BATCH,
                    self.columns.clone(),
                ));
                if self.would_complete(batch_id) {
                    self.last_batch_downloaded = true;
                }
                self.to_be_downloaded = self
                    .to_be_downloaded
                    .saturating_sub(CUSTODY_BACKFILL_EPOCHS_PER_BATCH);
                Some(batch_id)
            }
        }
    }

    /// Processes the batch with the given id.
    /// The batch must exist and be ready for processing
    fn process_batch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
    ) -> Result<ProcessResult, CustodyBackfillError> {
        if self.state() != CustodyBackFillState::Syncing || self.current_processing_batch.is_some()
        {
            return Ok(ProcessResult::Successful);
        }

        let Some(batch) = self.batches.get_mut(&batch_id) else {
            return self
                .fail_sync(CustodyBackfillError::InvalidSyncState(format!(
                    "Trying to process a batch that does not exist: {}",
                    batch_id
                )))
                .map(|_| ProcessResult::Successful);
        };

        // NOTE: We send empty batches to the processor in order to trigger the processor
        // result callback. This is done, because an empty batch could end a bad batch and catching those
        // bad batch states is handled in `start_processing`.
        let (data_columns, _) = match batch.start_processing() {
            Err(e) => {
                return self
                    .fail_sync(CustodyBackfillError::BatchInvalidState(batch_id, e.0))
                    .map(|_| ProcessResult::Successful);
            }
            Ok(v) => v,
        };

        self.current_processing_batch = Some(batch_id);

        if let Err(e) = network
            .beacon_processor()
            .send_data_columns(batch_id, data_columns)
        {
            crit!(
                msg = "process_batch",
                error = %e,
                batch = ?self.processing_target,
                "Failed to send data columns to processor."
            );
            // This is unlikely to happen but it would stall syncing since the batch now has no
            // data columns to continue, and the chain is expecting a processing result that won't
            // arrive. To mitigate this, (fake) fail this processing so that the batch is
            // re-downloaded.
            self.on_batch_process_result(
                network,
                batch_id,
                &CustodyBatchProcessResult::NonFaultyFailure { batch_id },
            )
        } else {
            Ok(ProcessResult::Successful)
        }
    }

    /// a data column has been received for a batch.
    /// If the column correctly completes the batch it will be processed if possible.
    /// If this returns an error, the custody sync has failed and will be restarted once new peers
    /// join the system.
    /// The sync manager should update the global sync state on failure.
    #[must_use = "A failure here indicates the backfill sync has failed and the global sync state should be updated"]
    pub fn on_data_column_response(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        custody_sync_request_id: CustodySyncBatchRequestId,
        peer_id: &PeerId,
        data_columns: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<ProcessResult, CustodyBackfillError> {
        // check if we have this batch
        let Some(batch) = self.batches.get_mut(&custody_sync_request_id.epoch) else {
            if !matches!(self.state(), CustodyBackFillState::Failed) {
                // A batch might get removed when custody sync advances, so this is non fatal.
                debug!(epoch = %custody_sync_request_id.epoch, "Received a column for unknown batch");
            }
            return Ok(ProcessResult::Successful);
        };

        // A batch could be retried without the peer failing the request (disconnecting/
        // sending an error /timeout) if the peer is removed for other
        // reasons. Check that this column belongs to the expected peer, and that the
        // request_id matches
        if !batch.is_expecting_data_column(&custody_sync_request_id.id) {
            return Ok(ProcessResult::Successful);
        }

        match batch.download_completed(data_columns, *peer_id) {
            Ok(received) => {
                let awaiting_batches = self
                    .processing_target
                    .saturating_sub(custody_sync_request_id.epoch)
                    / CUSTODY_BACKFILL_EPOCHS_PER_BATCH;
                debug!(
                    epoch = %custody_sync_request_id.epoch,
                    blocks = received,
                    %awaiting_batches,
                    "Completed batch received"
                );

                // pre-emptively request more blocks from peers whilst we process current blocks,
                self.request_batches(network)?;
                self.process_completed_batches(network)
            }
            Err(e) => {
                self.fail_sync(CustodyBackfillError::BatchInvalidState(
                    custody_sync_request_id.epoch,
                    e.0,
                ))?;
                Ok(ProcessResult::Successful)
            }
        }
    }

    /// The beacon processor has completed processing a batch. This function handles the result
    /// of the batch processor.
    /// If an error is returned the BackFill sync has failed.
    #[must_use = "A failure here indicates the custody backfill sync has failed and the global sync state should be updated"]
    pub fn on_batch_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
        result: &CustodyBatchProcessResult,
    ) -> Result<ProcessResult, CustodyBackfillError> {
        // The first two cases are possible in regular sync, should not occur in backfill, but we
        // keep this logic for handling potential processing race conditions.
        // result
        let batch = match &self.current_processing_batch {
            Some(processing_id) if *processing_id != batch_id => {
                debug!(
                    batch_epoch = %batch_id.as_u64(),
                    expected_batch_epoch = processing_id.as_u64(),
                    "Unexpected batch result"
                );
                return Ok(ProcessResult::Successful);
            }
            None => {
                debug!(%batch_id, "Chain was not expecting a batch result");
                return Ok(ProcessResult::Successful);
            }
            _ => {
                // batch_id matches, continue
                self.current_processing_batch = None;

                match self.batches.get_mut(&batch_id) {
                    Some(batch) => batch,
                    None => {
                        // This is an error. Fail the sync algorithm.
                        return self
                            .fail_sync(CustodyBackfillError::InvalidSyncState(format!(
                                "Current processing batch not found: {}",
                                batch_id
                            )))
                            .map(|_| ProcessResult::Successful);
                    }
                }
            }
        };

        let Some(peer) = batch.processing_peer() else {
            self.fail_sync(CustodyBackfillError::BatchInvalidState(
                batch_id,
                String::from("Peer does not exist"),
            ))?;
            return Ok(ProcessResult::Successful);
        };

        debug!(
            ?result,
            %batch,
            batch_epoch = %batch_id,
            %peer,
            client = %network.client_type(peer),
            "Custody backfill batch processed"
        );

        match result {
            CustodyBatchProcessResult::Success {
                imported_columns, ..
            } => {
                if let Err(e) = batch.processing_completed(BatchProcessingResult::Success) {
                    self.fail_sync(CustodyBackfillError::BatchInvalidState(batch_id, e.0))?;
                }
                // If the processed batch was not empty, we can validate previous un-validated
                // columns.
                if *imported_columns > 0 {
                    self.advance_custody_sync(network, batch_id);
                }

                // TODO(custody-sync)
                let fulu_fork_epoch = self.beacon_chain.spec.fulu_fork_epoch.unwrap();

                if batch_id == self.processing_target {
                    // Advance processing target if we're above the Fulu fork epoch
                    if self.processing_target > fulu_fork_epoch {
                        self.processing_target = self
                            .processing_target
                            .saturating_sub(CUSTODY_BACKFILL_EPOCHS_PER_BATCH);
                    }
                }

                // check if custody sync has completed syncing up to the DA window
                if self.check_completed() {
                    // chain is completed
                    info!(
                        slots_processed = self.validated_batches * T::EthSpec::slots_per_epoch(),
                        "Custody sync completed"
                    );
                    self.set_state(CustodyBackFillState::Completed);
                    Ok(ProcessResult::SyncCompleted)
                } else {
                    // custody sync is not completed
                    // attempt to request more batches
                    self.request_batches(network)?;
                    // attempt to process more batches
                    self.process_completed_batches(network)
                }
            }
            CustodyBatchProcessResult::FaultyFailure {
                imported_columns,
                penalty,
                batch_id,
            } => {
                match batch.processing_completed(BatchProcessingResult::FaultyFailure) {
                    Err(e) => {
                        // Batch was in the wrong state
                        self.fail_sync(CustodyBackfillError::BatchInvalidState(*batch_id, e.0))
                            .map(|_| ProcessResult::Successful)
                    }
                    Ok(BatchOperationOutcome::Failed { blacklist: _ }) => {
                        // check that we have not exceeded the re-process retry counter
                        // If a batch has exceeded the invalid batch lookup attempts limit, it means
                        // that it is likely all peers are sending invalid batches
                        // repeatedly and are either malicious or faulty. We stop the backfill sync and
                        // report all synced peers that have participated.
                        warn!(
                            score_adjustment = %penalty,
                            batch_epoch = %batch_id,
                            "Backfill batch failed to download. Penalizing peers"
                        );

                        for peer in self.participating_peers.drain() {
                            // TODO(das): `participating_peers` only includes block peers. Should we
                            // penalize the custody column peers too?
                            network.report_peer(peer, *penalty, "backfill_batch_failed");
                        }
                        self.fail_sync(CustodyBackfillError::BatchProcessingFailed(*batch_id))
                            .map(|_| ProcessResult::Successful)
                    }

                    Ok(BatchOperationOutcome::Continue) => {
                        // custody backfill can continue. Check if it can be progressed
                        if *imported_columns > 0 {
                            // TODO(custody-sync) is this actually true?
                            // At least one column was successfully verified and imported, then we can be sure all
                            // previous batches are valid and we only need to download the current failed
                            // batch.
                            self.advance_custody_sync(network, *batch_id);
                        }
                        // Handle this invalid batch, that is within the re-process retries limit.
                        self.handle_invalid_batch(network, *batch_id)
                            .map(|_| ProcessResult::Successful)
                    }
                }
            }
            CustodyBatchProcessResult::NonFaultyFailure { .. } => {
                if let Err(e) = batch.processing_completed(BatchProcessingResult::NonFaultyFailure)
                {
                    self.fail_sync(CustodyBackfillError::BatchInvalidState(batch_id, e.0))?;
                }
                self.send_batch(network, batch_id)?;
                Ok(ProcessResult::Successful)
            }
        }
    }

    /// Processes the next ready batch.
    fn process_completed_batches(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<ProcessResult, CustodyBackfillError> {
        // Only process batches if backfill is syncing and only process one batch at a time
        if self.state() != CustodyBackFillState::Syncing || self.current_processing_batch.is_some()
        {
            return Ok(ProcessResult::Successful);
        }

        // Don't try to process batches before the Fulu fork epoch since data columns don't exist
        if let Some(fulu_fork_epoch) = self.beacon_chain.spec.fulu_fork_epoch {
            if self.processing_target < fulu_fork_epoch {
                return Ok(ProcessResult::Successful);
            }
        }

        // Find the id of the batch we are going to process.
        if let Some(batch) = self.batches.get(&self.processing_target) {
            let state = batch.state();
            match state {
                CustodyBatchState::AwaitingProcessing(..) => {
                    return self.process_batch(network, self.processing_target);
                }
                CustodyBatchState::Downloading(..) => {
                    // Batch is not ready, nothing to process
                }
                CustodyBatchState::Poisoned => unreachable!("Poisoned batch"),
                CustodyBatchState::Failed
                | CustodyBatchState::AwaitingDownload
                | CustodyBatchState::Processing(_) => {
                    // these are all inconsistent states:
                    // - Failed -> non recoverable batch. Chain should have been removed
                    // - AwaitingDownload -> A recoverable failed batch should have been
                    //   re-requested.
                    // - Processing -> `self.current_processing_batch` is None
                    self.fail_sync(CustodyBackfillError::InvalidSyncState(String::from(
                        "Invalid expected batch state",
                    )))?;
                    return Ok(ProcessResult::Successful);
                }
                CustodyBatchState::AwaitingValidation(_) => {
                    // TODO(custody-sync) this is possible when running custody sync a second time
                    // TODO: I don't think this state is possible, log a CRIT just in case.
                    // If this is not observed, add it to the failed state branch above.
                    crit!(
                        batch = ?self.processing_target,
                        "Custody Sync encountered a robust batch awaiting validation"
                    );

                    self.processing_target -= CUSTODY_BACKFILL_EPOCHS_PER_BATCH;
                    if self.to_be_downloaded >= self.processing_target {
                        self.to_be_downloaded =
                            self.processing_target - CUSTODY_BACKFILL_EPOCHS_PER_BATCH;
                    }
                    self.request_batches(network)?;
                }
            }
        } else {
            self.fail_sync(CustodyBackfillError::InvalidSyncState(format!(
                "Batch not found for current processing target {}",
                self.processing_target
            )))?;
            return Ok(ProcessResult::Successful);
        }
        Ok(ProcessResult::Successful)
    }

    /// Removes any batches previous to the given `validating_epoch`
    ///
    /// The `validating_epoch` must align with batch boundaries.
    ///
    /// If a previous batch has been validated and it had been re-processed, penalize the original
    /// peer.
    fn advance_custody_sync(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        validating_epoch: Epoch,
    ) {
        // make sure this epoch produces an advancement
        if validating_epoch >= self.current_start {
            return;
        }

        // We can now validate higher batches that the current batch. Here we remove all
        // batches that are higher than the current batch. We add on an extra
        // `BACKFILL_EPOCHS_PER_BATCH` as `split_off` is inclusive.
        let removed_batches = self
            .batches
            .split_off(&(validating_epoch + CUSTODY_BACKFILL_EPOCHS_PER_BATCH));

        for (id, batch) in removed_batches.into_iter() {
            self.validated_batches = self.validated_batches.saturating_add(1);
            // only for batches awaiting validation can we be sure the last attempt is
            // right, and thus, that any different attempt is wrong
            match batch.state() {
                CustodyBatchState::AwaitingValidation(processed_attempt) => {
                    for attempt in batch.attempts() {
                        // The validated batch has been re-processed
                        if attempt.hash != processed_attempt.hash {
                            // The re-downloaded version was different.
                            if processed_attempt.peer_id != attempt.peer_id {
                                // A different peer sent the correct batch, the previous peer did not
                                // We negatively score the original peer.
                                let action = PeerAction::LowToleranceError;
                                debug!(
                                    batch_epoch = ?id,
                                    score_adjustment = %action,
                                    original_peer = %attempt.peer_id,
                                    new_peer = %processed_attempt.peer_id,
                                    "Re-processed batch validated. Scoring original peer"
                                );
                                network.report_peer(
                                    attempt.peer_id,
                                    action,
                                    "custody_backfill_reprocessed_original_peer",
                                );
                            } else {
                                // The same peer corrected it's previous mistake. There was an error, so we
                                // negative score the original peer.
                                let action = PeerAction::MidToleranceError;
                                debug!(
                                    batch_epoch = ?id,
                                    score_adjustment = %action,
                                    original_peer = %attempt.peer_id,
                                    new_peer = %processed_attempt.peer_id,
                                    "Re-processed batch validated by the same peer"
                                );
                                network.report_peer(
                                    attempt.peer_id,
                                    action,
                                    "custody_backfill_reprocessed_same_peer",
                                );
                            }
                        }
                    }
                }
                CustodyBatchState::Downloading(..) => {}
                CustodyBatchState::Failed
                | CustodyBatchState::Poisoned
                | CustodyBatchState::AwaitingDownload => {
                    crit!("batch indicates inconsistent data columns while advancing custody sync")
                }
                CustodyBatchState::AwaitingProcessing(..) => {}
                CustodyBatchState::Processing(_) => {
                    debug!(batch = %id, %batch, "Advancing custody sync while processing a batch");
                    if let Some(processing_id) = self.current_processing_batch
                        && id >= processing_id
                    {
                        self.current_processing_batch = None;
                    }
                }
            }
        }

        self.processing_target = self.processing_target.min(validating_epoch);
        self.current_start = self.current_start.min(validating_epoch);
        self.to_be_downloaded = self.to_be_downloaded.min(validating_epoch);

        if self.batches.contains_key(&self.to_be_downloaded) {
            // if custody sync is advanced by Range beyond the previous `self.to_be_downloaded`, we
            // won't have this batch, so we need to request it.
            self.to_be_downloaded -= CUSTODY_BACKFILL_EPOCHS_PER_BATCH;
        }
        debug!(?validating_epoch, processing_target = ?self.processing_target, "Custody backfill advanced");
    }

    /// An invalid batch has been received that could not be processed, but that can be retried.
    ///
    /// These events occur when a peer has successfully responded with columns, but the columns
    /// received are incorrect or invalid. This indicates the peer has not performed as
    /// intended and can result in down voting a peer.
    fn handle_invalid_batch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
    ) -> Result<(), CustodyBackfillError> {
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

        for (id, batch) in self.batches.iter_mut().filter(|&(&id, _)| id > batch_id) {
            match batch
                .validation_failed()
                .map_err(|e| CustodyBackfillError::BatchInvalidState(batch_id, e.0))?
            {
                BatchOperationOutcome::Failed { blacklist: _ } => {
                    // Batch has failed and cannot be re downloaded.
                    return self.fail_sync(CustodyBackfillError::BatchProcessingFailed(batch_id));
                }
                BatchOperationOutcome::Continue => {
                    redownload_queue.push(*id);
                }
            }
        }

        // no batch maxed out it process attempts, so now the chain's volatile progress must be
        // reset
        self.processing_target = self.current_start;

        for id in redownload_queue {
            self.send_batch(network, id)?;
        }
        // finally, re-request the failed batch.
        self.send_batch(network, batch_id)
    }

    /// Checks with the beacon chain if custody sync has completed.
    /// TODO(custody-sync) clean up this implementation
    fn check_completed(&mut self) -> bool {
        if self.would_complete(self.current_start) {
            // Check that the data column custody info `earliest_available_slot`
            // is less than or equal to the current DA boundary
            let earliest_data_column_slot = self
                .beacon_chain
                .store
                .get_data_column_custody_info()
                .unwrap_or(None)
                .and_then(|info| info.earliest_data_column_slot);

            if let Some(earliest_data_column_slot) = earliest_data_column_slot {
                let mut column_da_boundary = self
                    .beacon_chain
                    .data_availability_boundary()
                    .unwrap_or(Epoch::new(u64::MAX));

                let fulu_fork_epoch = self.beacon_chain.spec.fulu_fork_epoch;

                let Some(fulu_fork_epoch) = fulu_fork_epoch else {
                    return true;
                };

                if fulu_fork_epoch > column_da_boundary {
                    column_da_boundary = fulu_fork_epoch;
                }

                return earliest_data_column_slot.epoch(T::EthSpec::slots_per_epoch())
                    <= column_da_boundary;
            }

            return false;
        }
        false
    }

    /// Checks if custody backfill would complete by syncing to `start_epoch`.
    /// TODO(custody-sync) clean up this implementation
    fn would_complete(&self, start_epoch: Epoch) -> bool {
        if let Some(fulu_fork_epoch) = self.beacon_chain.spec.fulu_fork_epoch {
            return start_epoch <= fulu_fork_epoch;
        }
        start_epoch
            <= self
                .beacon_chain
                .data_availability_boundary()
                .unwrap_or(Epoch::new(u64::MAX))
    }

    /// Requests the batch assigned to the given id from a given peer.
    fn send_batch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
    ) -> Result<(), CustodyBackfillError> {
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            let synced_peers = self
                .network_globals
                .peers
                .read()
                .synced_peers()
                .cloned()
                .collect::<HashSet<_>>();

            let request = batch.to_data_columns_by_range_request();
            let failed_peers = batch.failed_peers();

            match network.custody_sync_data_columns_batch_request(
                request,
                batch_id,
                &synced_peers,
                &failed_peers,
            ) {
                Ok(request_id) => {
                    // inform the batch about the new request
                    if let Err(e) = batch.start_downloading(request_id) {
                        return self
                            .fail_sync(CustodyBackfillError::BatchInvalidState(batch_id, e.0));
                    }
                    debug!(epoch = %batch_id, %batch, "Requesting batch");

                    return Ok(());
                }
                Err(e) => match e {
                    crate::sync::network_context::RpcRequestSendError::NoPeer(no_peer) => {
                        // If we are here we have no more synced peers
                        info!(
                            "reason" = format!("insufficient_synced_peers({no_peer:?})"),
                            "Custody sync paused"
                        );
                        self.set_state(CustodyBackFillState::Paused);
                        return Err(CustodyBackfillError::Paused);
                    }
                    crate::sync::network_context::RpcRequestSendError::InternalError(e) => {
                        // NOTE: under normal conditions this shouldn't happen but we handle it anyway
                        warn!(%batch_id, error = ?e, %batch,"Could not send batch request");
                        // register the failed download and check if the batch can be retried
                        if let Err(e) = batch.start_downloading(1) {
                            return self
                                .fail_sync(CustodyBackfillError::BatchInvalidState(batch_id, e.0));
                        }

                        match batch.download_failed(None) {
                            Err(e) => self.fail_sync(CustodyBackfillError::BatchInvalidState(
                                batch_id, e.0,
                            ))?,
                            Ok(BatchOperationOutcome::Failed { blacklist: _ }) => {
                                self.fail_sync(CustodyBackfillError::BatchDownloadFailed(batch_id))?
                            }
                            Ok(BatchOperationOutcome::Continue) => {
                                return self.send_batch(network, batch_id);
                            }
                        }
                    }
                },
            }
        }

        Ok(())
    }

    /// The syncing process has failed.
    ///
    /// This resets past variables, to allow for a fresh start when resuming.
    fn fail_sync(&mut self, error: CustodyBackfillError) -> Result<(), CustodyBackfillError> {
        // Some errors shouldn't cause failure.
        if matches!(error, CustodyBackfillError::Paused) {
            return Ok(());
        }

        // Set the state
        self.set_state(CustodyBackFillState::Failed);
        // Remove all batches and active requests and participating peers.
        self.batches.clear();
        self.participating_peers.clear();
        self.restart_failed_sync = false;

        // Reset all downloading and processing targets
        self.processing_target = self.current_start;
        self.to_be_downloaded = self.current_start;
        self.last_batch_downloaded = false;
        self.current_processing_batch = None;

        // NOTE: Lets keep validated_batches for posterity

        // Emit the log here
        error!(?error, "Backfill sync failed");

        // Return the error, kinda weird pattern, but I want to use
        // `self.fail_chain(_)?` in other parts of the code.
        Err(error)
    }

    /// A peer has disconnected.
    /// If the peer has active batches, those are considered failed and re-requested.
    #[must_use = "A failure here indicates custody sync has failed and the global sync state should be updated"]
    pub fn peer_disconnected(&mut self, peer_id: &PeerId) -> Result<(), CustodyBackfillError> {
        if matches!(self.state(), CustodyBackFillState::Failed) {
            return Ok(());
        }

        // Remove the peer from the participation list
        self.participating_peers.remove(peer_id);
        Ok(())
    }

    pub fn state(&self) -> CustodyBackFillState {
        self.network_globals.custody_sync_state.read().clone()
    }

    /// Updates the global network state indicating the current state of a backfill sync.
    fn set_state(&self, state: CustodyBackFillState) {
        *self.network_globals.custody_sync_state.write() = state;
    }

    /// A fully synced peer has joined us.
    /// If we are in a failed state, update a local variable to indicate we are able to restart
    /// the failed sync on the next attempt.
    pub fn fully_synced_peer_joined(&mut self) {
        if matches!(self.state(), CustodyBackFillState::Failed) {
            self.restart_failed_sync = true;
        }
    }

    /// An RPC error has occurred.
    ///
    /// If the batch exists it is re-requested.
    #[must_use = "A failure here indicates the custody sync has failed and the global sync state should be updated"]
    pub fn inject_error(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        request: CustodySyncBatchRequestId,
        peer_id: &PeerId,
        err: RpcResponseError,
    ) -> Result<(), CustodyBackfillError> {
        if let Some(batch) = self.batches.get_mut(&request.epoch) {
            // A batch could be retried without the peer failing the request (disconnecting/
            // sending an error /timeout) if the peer is removed from the chain for other
            // reasons. Check that this data column belongs to the expected peer
            if !batch.is_expecting_data_column(&request.id) {
                return Ok(());
            }
            debug!(batch_epoch = %request.epoch, error = ?err, "Batch download failed");
            match batch.download_failed(Some(*peer_id)) {
                Err(e) => {
                    self.fail_sync(CustodyBackfillError::BatchInvalidState(request.epoch, e.0))
                }
                Ok(BatchOperationOutcome::Failed { blacklist: _ }) => {
                    self.fail_sync(CustodyBackfillError::BatchDownloadFailed(request.epoch))
                }
                Ok(BatchOperationOutcome::Continue) => self.send_batch(network, request.epoch),
            }
        } else {
            // this could be an error for an old batch, removed when the chain advances
            Ok(())
        }
    }
}
