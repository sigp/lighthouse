use std::{
    collections::{BTreeMap, HashSet, btree_map::Entry},
    marker::PhantomData,
    sync::Arc,
};

use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::{
    NetworkGlobals, PeerAction, PeerId,
    service::api_types::{CustodyBackFillBatchRequestId, CustodyBackfillBatchId},
    types::CustodyBackFillState,
};
use lighthouse_tracing::SPAN_CUSTODY_BACKFILL_SYNC_BATCH_REQUEST;
use logging::crit;
use std::hash::{DefaultHasher, Hash, Hasher};
use tracing::{debug, error, info, info_span, warn};
use types::{DataColumnSidecarList, Epoch, EthSpec};

use crate::sync::{
    backfill_sync::{BACKFILL_EPOCHS_PER_BATCH, ProcessResult, SyncStart},
    batch::{
        BatchConfig, BatchId, BatchInfo, BatchOperationOutcome, BatchProcessingResult, BatchState,
        ByRangeRequestType,
    },
    block_sidecar_coupling::CouplingError,
    manager::CustodyBatchProcessResult,
    network_context::{RpcResponseError, SyncNetworkContext},
};

/// The maximum number of batches to queue before requesting more.
const BACKFILL_BATCH_BUFFER_SIZE: u8 = 5;

/// Columns are downloaded in batches from peers. This constant specifies how many epochs worth of
/// columns per batch are requested _at most_. A batch may request less columns to account for
/// already requested columns. There is a timeout for each batch request. If this value is too high,
/// we will negatively report peers with poor bandwidth. This can be set arbitrarily high, in which
/// case the responder will fill the response up to the max request size, assuming they have the
/// bandwidth to do so.
pub const CUSTODY_BACKFILL_EPOCHS_PER_BATCH: u64 = 1;

type CustodyBackFillBatchInfo<E> =
    BatchInfo<E, CustodyBackFillBatchConfig<E>, DataColumnSidecarList<E>>;
type CustodyBackFillBatches<E> = BTreeMap<BatchId, CustodyBackFillBatchInfo<E>>;

#[derive(Debug)]
pub struct CustodyBackFillBatchConfig<E: EthSpec> {
    marker: PhantomData<E>,
}

impl<E: EthSpec> BatchConfig for CustodyBackFillBatchConfig<E> {
    fn max_batch_download_attempts() -> u8 {
        5
    }
    fn max_batch_processing_attempts() -> u8 {
        5
    }
    fn batch_attempt_hash<D: Hash>(data: &D) -> u64 {
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish()
    }
}

/// The ways a custody backfill sync can fail.
// The info in the enum variants is displayed in logging, clippy thinks it's dead code.
#[derive(Debug)]
pub enum CustodyBackfillError {
    /// A batch failed to be downloaded.
    BatchDownloadFailed(#[allow(dead_code)] BatchId),
    /// A batch could not be processed.
    BatchProcessingFailed(#[allow(dead_code)] BatchId),
    /// A batch entered an invalid state.
    BatchInvalidState(#[allow(dead_code)] BatchId, #[allow(dead_code)] String),
    /// The sync algorithm entered an invalid state.
    InvalidSyncState(#[allow(dead_code)] String),
    /// The chain became paused.
    Paused,
}

pub struct CustodyBackFillSync<T: BeaconChainTypes> {
    /// Keeps track of the current progress of the custody backfill.
    /// This only gets refreshed from the beacon chain if we enter a failed state.
    current_start: BatchId,

    /// Starting epoch of the batch that needs to be processed next.
    /// This is incremented as the chain advances.
    processing_target: BatchId,

    /// The custody group count we are trying to fulfill up to the DA window.
    /// This is used as an indicator to restart custody backfill sync if the cgc
    /// was changed in the middle of a currently active sync.
    cgc: u64,

    /// Run ID of this backfill process. Increments if sync restarts. Used to differentiate batch
    /// results from different runs.
    run_id: u64,

    /// Starting epoch of the next batch that needs to be downloaded.
    to_be_downloaded: BatchId,

    /// Keeps track if we have requested the final batch.
    last_batch_downloaded: bool,

    /// Sorted map of batches undergoing some kind of processing.
    batches: CustodyBackFillBatches<T::EthSpec>,

    /// The current processing batch, if any.
    current_processing_batch: Option<BatchId>,

    /// Batches validated.
    validated_batches: u64,

    /// These are batches that we've skipped because we have no columns to fetch for the epoch.
    skipped_batches: HashSet<BatchId>,

    /// When a custody backfill sync fails, we keep track of whether a new fully synced peer has joined.
    /// This signifies that we are able to attempt to restart a failed chain.
    restart_failed_sync: bool,

    /// Reference to the beacon chain to obtain initial starting points for custody backfill sync.
    beacon_chain: Arc<BeaconChain<T>>,

    /// Reference to the network globals in order to obtain valid peers to backfill columns from
    /// (i.e synced peers).
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,
}

impl<T: BeaconChainTypes> CustodyBackFillSync<T> {
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    ) -> Self {
        Self {
            current_start: Epoch::new(0),
            processing_target: Epoch::new(0),
            cgc: 0,
            run_id: 0,
            to_be_downloaded: Epoch::new(0),
            last_batch_downloaded: false,
            batches: BTreeMap::new(),
            skipped_batches: HashSet::new(),
            current_processing_batch: None,
            validated_batches: 0,
            restart_failed_sync: false,
            beacon_chain,
            network_globals,
        }
    }

    /// Pauses the custody sync if it's currently syncing.
    pub fn pause(&mut self, reason: String) {
        if let CustodyBackFillState::Syncing = self.state() {
            debug!(processed_epochs = %self.validated_batches, to_be_processed = %self.current_start,"Custody backfill sync paused");
            self.set_state(CustodyBackFillState::Pending(reason));
        }
    }

    /// Checks if custody backfill sync should start and sets the missing columns
    /// custody backfill sync will attempt to fetch.
    /// The criteria to start custody sync is:
    /// - The earliest data column epoch's custodied columns != previous epoch's custodied columns
    /// - The earliest data column epoch is a finalied epoch
    pub fn should_start_custody_backfill_sync(&mut self) -> bool {
        let Some(da_boundary_epoch) = self.beacon_chain.get_column_da_boundary() else {
            return false;
        };

        // This is the epoch in which we have met our current custody requirements
        let Some(earliest_data_column_epoch) =
            self.beacon_chain.earliest_custodied_data_column_epoch()
        else {
            return false;
        };

        // Check if we have missing columns between the da boundary and `earliest_data_column_epoch`
        let missing_columns = self
            .beacon_chain
            .get_missing_columns_for_epoch(da_boundary_epoch);

        if !missing_columns.is_empty() {
            let latest_finalized_epoch = self
                .beacon_chain
                .canonical_head
                .cached_head()
                .finalized_checkpoint()
                .epoch;

            // Check that the earliest data column epoch is a finalized epoch.
            return earliest_data_column_epoch <= latest_finalized_epoch;
        }

        false
    }

    fn restart_sync(&mut self) {
        // Set state to paused
        self.set_state(CustodyBackFillState::Pending(
            "CGC count has changed and custody backfill sync needs to restart".to_string(),
        ));

        // Remove all batches and active requests.
        self.batches.clear();
        self.skipped_batches.clear();
        self.restart_failed_sync = false;

        // Reset all downloading and processing targets
        // NOTE: Lets keep validated_batches for posterity
        self.processing_target = Epoch::new(0);
        self.to_be_downloaded = Epoch::new(0);
        self.last_batch_downloaded = false;
        self.current_processing_batch = None;
        self.validated_batches = 0;
        self.run_id += 1;

        self.set_start_epoch();
        self.set_cgc();
    }

    fn restart_if_required(&mut self) -> bool {
        let cgc_at_head = self
            .beacon_chain
            .data_availability_checker
            .custody_context()
            .custody_group_count_at_head(&self.beacon_chain.spec);

        if cgc_at_head != self.cgc {
            self.restart_sync();
            return true;
        }

        false
    }

    /// Starts syncing.
    #[must_use = "A failure here indicates custody backfill sync has failed and the global sync state should be updated"]
    pub fn start(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<SyncStart, CustodyBackfillError> {
        match self.state() {
            CustodyBackFillState::Syncing => {
                if self.restart_if_required() {
                    return Ok(SyncStart::NotSyncing);
                }

                if self.check_completed() {
                    self.set_state(CustodyBackFillState::Completed);
                    return Ok(SyncStart::NotSyncing);
                }
            }
            CustodyBackFillState::Pending(_) | CustodyBackFillState::Completed => {
                if self.check_completed() {
                    self.set_state(CustodyBackFillState::Completed);
                    return Ok(SyncStart::NotSyncing);
                }
                self.set_cgc();

                if !self.should_start_custody_backfill_sync() {
                    return Ok(SyncStart::NotSyncing);
                }
                self.set_start_epoch();
                if self
                    .network_globals
                    .peers
                    .read()
                    .synced_peers()
                    .next()
                    .is_some()
                {
                    debug!(
                        run_id = self.run_id,
                        current_start = %self.current_start,
                        processing_target = %self.processing_target,
                        to_be_downloaded = %self.to_be_downloaded,
                        "Starting custody backfill sync"
                    );
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
        }

        let Some(column_da_boundary) = self.beacon_chain.get_column_da_boundary() else {
            return Ok(SyncStart::NotSyncing);
        };

        Ok(SyncStart::Syncing {
            completed: (self.validated_batches
                * CUSTODY_BACKFILL_EPOCHS_PER_BATCH
                * T::EthSpec::slots_per_epoch()) as usize,
            remaining: self
                .current_start
                .end_slot(T::EthSpec::slots_per_epoch())
                .saturating_sub(column_da_boundary.start_slot(T::EthSpec::slots_per_epoch()))
                .as_usize(),
        })
    }

    fn set_cgc(&mut self) {
        self.cgc = self
            .beacon_chain
            .data_availability_checker
            .custody_context()
            .custody_group_count_at_head(&self.beacon_chain.spec);
    }

    fn set_start_epoch(&mut self) {
        let earliest_data_column_epoch = self
            .beacon_chain
            .earliest_custodied_data_column_epoch()
            .unwrap_or(Epoch::new(0));

        self.current_start = earliest_data_column_epoch + 1;
        self.processing_target = self.current_start;
        self.to_be_downloaded = self.current_start;
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
                if matches!(batch.state(), BatchState::AwaitingDownload) {
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
        let Some(column_da_boundary) = self.beacon_chain.get_column_da_boundary() else {
            return None;
        };

        // Skip all batches (Epochs) that don't have missing columns.
        for epoch in Epoch::range_inclusive_rev(self.to_be_downloaded, column_da_boundary) {
            let missing_columns = self.beacon_chain.get_missing_columns_for_epoch(epoch);

            if !missing_columns.is_empty() {
                self.to_be_downloaded = epoch;
                break;
            }

            // This batch is being skipped, insert it into the skipped batches mapping.
            self.skipped_batches.insert(epoch);

            if epoch == column_da_boundary {
                return None;
            }
        }

        // Don't request batches before the column da boundary
        if self.to_be_downloaded < column_da_boundary {
            return None;
        }

        // Don't request batches beyond the DA window
        if self.last_batch_downloaded {
            return None;
        }

        // Only request batches up to the buffer size limit
        // NOTE: we don't count batches in the AwaitingValidation state, to prevent stalling sync
        // if the current processing window is contained in a long range of skip slots.
        let in_buffer = |batch: &CustodyBackFillBatchInfo<T::EthSpec>| {
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
                let missing_columns = self.beacon_chain.get_missing_columns_for_epoch(batch_id);
                entry.insert(BatchInfo::new(
                    &batch_id,
                    CUSTODY_BACKFILL_EPOCHS_PER_BATCH,
                    ByRangeRequestType::Columns(missing_columns),
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
        // Check if we need to restart custody backfill sync due to a recent cgc change
        if self.restart_if_required() {
            return Ok(ProcessResult::Successful);
        }

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

        let (data_columns, _) = match batch.start_processing() {
            Err(e) => {
                return self
                    .fail_sync(CustodyBackfillError::BatchInvalidState(batch_id, e.0))
                    .map(|_| ProcessResult::Successful);
            }
            Ok(v) => v,
        };

        self.current_processing_batch = Some(batch_id);

        if let Err(e) = network.beacon_processor().send_historic_data_columns(
            CustodyBackfillBatchId {
                epoch: batch_id,
                run_id: self.run_id,
            },
            data_columns,
            self.cgc,
        ) {
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
                CustodyBackfillBatchId {
                    epoch: batch_id,
                    run_id: self.run_id,
                },
                &CustodyBatchProcessResult::Error { peer_action: None },
            )
        } else {
            Ok(ProcessResult::Successful)
        }
    }

    /// A data column has been received for a batch.
    /// If the column correctly completes the batch it will be processed if possible.
    /// If this returns an error, custody sync has failed and will be restarted once new peers
    /// join the system.
    /// The sync manager should update the global sync state on failure.
    #[must_use = "A failure here indicates custody backfill sync has failed and the global sync state should be updated"]
    pub fn on_data_column_response(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        req_id: CustodyBackFillBatchRequestId,
        peer_id: &PeerId,
        resp: Result<DataColumnSidecarList<T::EthSpec>, RpcResponseError>,
    ) -> Result<ProcessResult, CustodyBackfillError> {
        if req_id.batch_id.run_id != self.run_id {
            debug!(%req_id, "Ignoring custody backfill download response from different run_id");
            return Ok(ProcessResult::Successful);
        }

        let batch_id = req_id.batch_id.epoch;
        // check if we have this batch
        let Some(batch) = self.batches.get_mut(&batch_id) else {
            if !matches!(self.state(), CustodyBackFillState::Pending(_)) {
                // A batch might get removed when custody sync advances, so this is non fatal.
                debug!(epoch = %batch_id, "Received a column for unknown batch");
            }
            return Ok(ProcessResult::Successful);
        };

        // A batch could be retried without the peer failing the request (disconnecting/
        // sending an error /timeout) if the peer is removed for other
        // reasons. Check that this column belongs to the expected peer, and that the
        // request_id matches
        if !batch.is_expecting_request_id(&req_id.id) {
            return Ok(ProcessResult::Successful);
        }

        match resp {
            Ok(data_columns) => {
                let received = data_columns.len();

                match batch.download_completed(data_columns, *peer_id) {
                    Ok(_) => {
                        let awaiting_batches = self.processing_target.saturating_sub(batch_id)
                            / CUSTODY_BACKFILL_EPOCHS_PER_BATCH;
                        debug!(
                            %req_id,
                            blocks = received,
                            %awaiting_batches,
                            "Completed batch received"
                        );

                        // pre-emptively request more columns from peers whilst we process current columns.
                        self.request_batches(network)?;
                        self.process_completed_batches(network)
                    }
                    Err(e) => {
                        self.fail_sync(CustodyBackfillError::BatchInvalidState(batch_id, e.0))?;
                        Ok(ProcessResult::Successful)
                    }
                }
            }
            Err(err) => {
                debug!(batch_epoch = %batch_id, error = ?err, "Batch download failed");

                // If there are any coupling errors, penalize the appropriate peers
                if let RpcResponseError::BlockComponentCouplingError(coupling_error) = err
                    && let CouplingError::DataColumnPeerFailure {
                        error,
                        faulty_peers,
                        exceeded_retries: _,
                    } = coupling_error
                {
                    for (column_index, faulty_peer) in faulty_peers {
                        debug!(
                            ?error,
                            ?column_index,
                            ?faulty_peer,
                            "Custody backfill sync penalizing peer"
                        );
                        network.report_peer(
                            faulty_peer,
                            PeerAction::LowToleranceError,
                            "Peer failed to serve column",
                        );
                    }
                }

                match batch.download_failed(Some(*peer_id)) {
                    Err(e) => {
                        self.fail_sync(CustodyBackfillError::BatchInvalidState(batch_id, e.0))?;
                    }
                    Ok(BatchOperationOutcome::Failed { blacklist: _ }) => {
                        self.fail_sync(CustodyBackfillError::BatchDownloadFailed(batch_id))?;
                    }
                    Ok(BatchOperationOutcome::Continue) => {
                        self.send_batch(network, batch_id)?;
                    }
                }
                Ok(ProcessResult::Successful)
            }
        }
    }

    /// The beacon processor has completed processing a batch. This function handles the result
    /// of the batch processor.
    /// If an error is returned custody backfill sync has failed.
    #[must_use = "A failure here indicates custody backfill sync has failed and the global sync state should be updated"]
    pub fn on_batch_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        custody_batch_id: CustodyBackfillBatchId,
        result: &CustodyBatchProcessResult,
    ) -> Result<ProcessResult, CustodyBackfillError> {
        let batch_id = custody_batch_id.epoch;
        if custody_batch_id.run_id != self.run_id {
            debug!(batch = %custody_batch_id, "Ignoring custody backfill error from different run_id");
            return Ok(ProcessResult::Successful);
        }

        // The first two cases are possible in regular sync, should not occur in custody backfill, but we
        // keep this logic for handling potential processing race conditions.
        // result
        let batch = match &self.current_processing_batch {
            Some(processing_id) if *processing_id != batch_id => {
                debug!(
                    batch_epoch = %batch_id,
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
            batch_id = %custody_batch_id,
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

                debug!(imported_count=?imported_columns, "Succesfully imported historical data columns");

                self.advance_custody_backfill_sync(batch_id);

                let Some(column_da_boundary) = self.beacon_chain.get_column_da_boundary() else {
                    return Err(CustodyBackfillError::InvalidSyncState(
                        "Can't calculate column data availability boundary".to_string(),
                    ));
                };

                if batch_id == self.processing_target {
                    // Advance processing target to the previous epoch
                    // If the current processing target is above the column DA boundary
                    if self.processing_target > column_da_boundary {
                        self.processing_target = self
                            .processing_target
                            .saturating_sub(CUSTODY_BACKFILL_EPOCHS_PER_BATCH);
                    }
                }

                // check if custody sync has completed syncing up to the DA window
                if self.check_completed() {
                    info!(
                        validated_epochs = ?self.validated_batches,
                        run_id = self.run_id,
                        "Custody backfill sync completed"
                    );
                    self.batches.clear();
                    self.restart_failed_sync = false;
                    self.processing_target = self.current_start;
                    self.to_be_downloaded = self.current_start;
                    self.last_batch_downloaded = false;
                    self.current_processing_batch = None;
                    self.validated_batches = 0;
                    self.skipped_batches.clear();
                    self.set_state(CustodyBackFillState::Completed);
                    self.beacon_chain.update_data_column_custody_info(None);
                    Ok(ProcessResult::SyncCompleted)
                } else {
                    // custody sync is not completed
                    // attempt to request more batches
                    self.request_batches(network)?;
                    // attempt to process more batches
                    self.process_completed_batches(network)
                }
            }
            CustodyBatchProcessResult::Error { peer_action } => {
                match peer_action {
                    // Faulty failure
                    Some(peer_action) => {
                        match batch.processing_completed(BatchProcessingResult::FaultyFailure) {
                            Err(e) => {
                                // Batch was in the wrong state
                                self.fail_sync(CustodyBackfillError::BatchInvalidState(
                                    batch_id, e.0,
                                ))
                                .map(|_| ProcessResult::Successful)
                            }
                            Ok(BatchOperationOutcome::Failed { blacklist: _ }) => {
                                warn!(
                                    score_adjustment = ?peer_action,
                                    batch_epoch = %batch_id,
                                    "Custody backfill batch failed to download. Penalizing peers"
                                );
                                self.fail_sync(CustodyBackfillError::BatchProcessingFailed(
                                    batch_id,
                                ))
                                .map(|_| ProcessResult::Successful)
                            }

                            Ok(BatchOperationOutcome::Continue) => {
                                self.advance_custody_backfill_sync(batch_id);
                                // Handle this invalid batch, that is within the re-process retries limit.
                                self.handle_invalid_batch(network, batch_id)
                                    .map(|_| ProcessResult::Successful)
                            }
                        }
                    }
                    // Non faulty failure
                    None => {
                        if let Err(e) =
                            batch.processing_completed(BatchProcessingResult::NonFaultyFailure)
                        {
                            self.fail_sync(CustodyBackfillError::BatchInvalidState(batch_id, e.0))?;
                        }
                        self.send_batch(network, batch_id)?;
                        Ok(ProcessResult::Successful)
                    }
                }
            }
        }
    }

    /// Processes the next ready batch.
    fn process_completed_batches(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<ProcessResult, CustodyBackfillError> {
        // Only process batches if custody backfill is syncing and only process one batch at a time
        if self.state() != CustodyBackFillState::Syncing || self.current_processing_batch.is_some()
        {
            return Ok(ProcessResult::Successful);
        }

        // Don't try to process batches before the Fulu fork epoch since data columns don't exist
        if let Some(fulu_fork_epoch) = self.beacon_chain.spec.fulu_fork_epoch
            && self.processing_target < fulu_fork_epoch
        {
            return Ok(ProcessResult::Successful);
        }

        // Check if we need to restart custody backfill sync due to a cgc change.
        if self.restart_if_required() {
            return Ok(ProcessResult::Successful);
        }

        while self.skipped_batches.contains(&self.processing_target) {
            self.skipped_batches.remove(&self.processing_target);
            // Update data column custody info with the skipped batch
            if let Err(e) = self
                .beacon_chain
                .safely_backfill_data_column_custody_info(self.processing_target)
            {
                // I can't see a scenario where this could happen, but if we don't
                // handle this edge case custody backfill sync could be stuck indefinitely.
                error!(
                    error=?e,
                    "Unable to update data column custody info, restarting sync"
                );
                self.restart_sync();
            };
            self.processing_target -= BACKFILL_EPOCHS_PER_BATCH;
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
                // Batches can be in `AwaitingDownload` state if there weren't good data column subnet
                // peers to send the request to.
                BatchState::AwaitingDownload => return Ok(ProcessResult::Successful),
                BatchState::AwaitingValidation(..) => {
                    // The batch is validated
                }
                BatchState::Poisoned => unreachable!("Poisoned batch"),
                BatchState::Failed | BatchState::Processing(_) => {
                    // these are all inconsistent states:
                    // - Failed -> non recoverable batch. Columns should have been removed
                    // - AwaitingDownload -> A recoverable failed batch should have been
                    //   re-requested.
                    // - Processing -> `self.current_processing_batch` is None
                    self.fail_sync(CustodyBackfillError::InvalidSyncState(String::from(
                        "Invalid expected batch state",
                    )))?;
                    return Ok(ProcessResult::Successful);
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

    /// Removes any batches previous to the given `validating_epoch` and advance custody backfill sync
    /// to `validating_epoch`.
    ///
    /// The `validating_epoch` must align with batch boundaries.
    fn advance_custody_backfill_sync(&mut self, validating_epoch: Epoch) {
        let Some(column_da_boundary) = self.beacon_chain.get_column_da_boundary() else {
            return;
        };
        // make sure this epoch produces an advancement, unless its at the column DA boundary
        if validating_epoch >= self.current_start && validating_epoch > column_da_boundary {
            return;
        }

        // We can now validate higher batches than the current batch. Here we remove all
        // batches that are higher than the current batch. We add on an extra
        // `BACKFILL_EPOCHS_PER_BATCH` as `split_off` is inclusive.
        let removed_batches = self
            .batches
            .split_off(&(validating_epoch + CUSTODY_BACKFILL_EPOCHS_PER_BATCH));

        for (id, batch) in removed_batches.into_iter() {
            self.validated_batches = self.validated_batches.saturating_add(1);
            match batch.state() {
                BatchState::Downloading(..) | BatchState::AwaitingValidation(..) => {}
                BatchState::Failed | BatchState::Poisoned | BatchState::AwaitingDownload => {
                    crit!("Batch indicates inconsistent data columns while advancing custody sync")
                }
                BatchState::AwaitingProcessing(..) => {}
                BatchState::Processing(_) => {
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
            // if custody backfill sync is advanced by Range beyond the previous `self.to_be_downloaded`, we
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

        // The previous batch could be incomplete due to the columns being too large to fit in
        // a single RPC request or there could be consecutive empty batches which are not supposed
        // to be there

        // The current (sub-optimal) strategy is to simply re-request all batches that could
        // potentially be faulty. If a batch returns a different result than the original and
        // results in successful processing, we downvote the original peer that sent us the batch.

        // this is our robust `processing_target`. All previous batches must be awaiting
        // validation
        let mut redownload_queue = Vec::new();

        for (id, _) in self.batches.iter_mut().filter(|&(&id, _)| id > batch_id) {
            redownload_queue.push(*id);
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
    fn check_completed(&mut self) -> bool {
        if self.would_complete(self.current_start) {
            // Check that the data column custody info `earliest_available_slot`
            // is in an epoch that is less than or equal to the current DA boundary
            let Some(earliest_data_column_epoch) =
                self.beacon_chain.earliest_custodied_data_column_epoch()
            else {
                return false;
            };

            let Some(column_da_boundary) = self.beacon_chain.get_column_da_boundary() else {
                return false;
            };

            return earliest_data_column_epoch <= column_da_boundary;
        }
        false
    }

    /// Checks if custody backfill would complete by syncing to `start_epoch`.
    fn would_complete(&self, start_epoch: Epoch) -> bool {
        let Some(column_da_boundary) = self.beacon_chain.get_column_da_boundary() else {
            return false;
        };
        start_epoch <= column_da_boundary
    }

    /// Requests the batch assigned to the given id from a given peer.
    fn send_batch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
    ) -> Result<(), CustodyBackfillError> {
        let span = info_span!(SPAN_CUSTODY_BACKFILL_SYNC_BATCH_REQUEST);
        let _enter = span.enter();

        if let Some(batch) = self.batches.get_mut(&batch_id) {
            let synced_peers = self
                .network_globals
                .peers
                .read()
                .synced_peers_for_epoch(batch_id)
                .cloned()
                .collect::<HashSet<_>>();

            let request = batch.to_data_columns_by_range_request().map_err(|_| {
                CustodyBackfillError::InvalidSyncState(
                    "Can't convert to data column by range request".to_string(),
                )
            })?;
            let failed_peers = batch.failed_peers();

            match network.custody_backfill_data_columns_batch_request(
                request,
                CustodyBackfillBatchId {
                    epoch: batch_id,
                    run_id: self.run_id,
                },
                &synced_peers,
                &failed_peers,
            ) {
                Ok(request_id) => {
                    // inform the batch about the new request
                    if let Err(e) = batch.start_downloading(request_id.id) {
                        return self
                            .fail_sync(CustodyBackfillError::BatchInvalidState(batch_id, e.0));
                    }
                    debug!(epoch = %batch_id, %batch, "Requesting batch");

                    return Ok(());
                }
                Err(e) => match e {
                    crate::sync::network_context::RpcRequestSendError::NoPeer(no_peer) => {
                        // If we are here we have no more synced peers
                        debug!(
                            "reason" = format!("insufficient_synced_peers({no_peer:?})"),
                            "Custody sync paused"
                        );
                        self.pause("Insufficient peers".to_string());
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
        self.pause("Sync has failed".to_string());
        // Remove all batches and active requests.
        self.batches.clear();
        self.restart_failed_sync = false;

        // Reset all downloading and processing targets
        // NOTE: Lets keep validated_batches for posterity
        self.processing_target = self.current_start;
        self.to_be_downloaded = self.current_start;
        self.last_batch_downloaded = false;
        self.current_processing_batch = None;
        self.restart_sync();

        Err(error)
    }

    pub fn state(&self) -> CustodyBackFillState {
        self.network_globals.custody_sync_state.read().clone()
    }

    /// Updates the global network state indicating the current state of a backfill sync.
    pub fn set_state(&self, state: CustodyBackFillState) {
        *self.network_globals.custody_sync_state.write() = state;
    }

    /// A fully synced peer has joined us.
    /// If we are in a failed state, update a local variable to indicate we are able to restart
    /// the failed sync on the next attempt.
    pub fn fully_synced_peer_joined(&mut self) {
        if matches!(self.state(), CustodyBackFillState::Pending(_)) {
            self.restart_failed_sync = true;
        }
    }
}
