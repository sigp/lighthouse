mod custody_batch;
mod custody_sync_manager;

use std::{
    collections::{btree_map::Entry, BTreeMap, HashSet},
    sync::Arc,
    time::Instant,
};

use crate::sync::range_sync::WrongState;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::{
    service::api_types::{Id, RangeRequestId},
    types::BackFillState,
    NetworkGlobals, PeerAction, PeerId,
};
use logging::crit;
use tracing::{debug, error, info, instrument, warn};
use types::{DataColumnSidecarList, Epoch, EthSpec, Slot};

use crate::sync::{
    backfill_sync::{BackFillError, ProcessResult, SyncStart, BACKFILL_EPOCHS_PER_BATCH},
    custody_sync::custody_batch::{CustodyBatchInfo, CustodyBatchState},
    network_context::{RpcRequestSendError, SyncNetworkContext},
    range_sync::{BatchId, BatchProcessingResult},
    BatchOperationOutcome, BatchProcessResult,
};

pub use custody_batch::{CustodyByRangeParentRequestId, CustodySyncBatchConfig};
pub use custody_sync_manager::CustodyBatchProcessResult;

/// The maximum number of batches to queue before requesting more.
const BACKFILL_BATCH_BUFFER_SIZE: u8 = 20;

pub type CustodyBackSyncBatchId = Epoch;

pub struct CustodyBackfillSync<T: BeaconChainTypes> {
    /// Keeps track of the current progress of the custody backfill.
    /// This only gets refreshed from the beacon chain if we enter a failed state.
    current_start: BatchId,

    /// Starting epoch of the batch that needs to be processed next.
    /// This is incremented as the custody backfill advances.
    processing_target: BatchId,

    /// Starting epoch of the next batch that needs to be downloaded.
    to_be_downloaded: BatchId,

    /// Keeps track if we have requested the final batch.
    last_batch_downloaded: bool,

    /// Sorted map of batches undergoing some kind of processing.
    batches: BTreeMap<BatchId, CustodyBatchInfo<T::EthSpec>>,

    /// The current processing batch, if any.
    current_processing_batch: Option<BatchId>,

    /// Batches validated.
    validated_batches: u64,

    /// We keep track of peers that are participating in the backfill sync. CustodySync
    /// only use peers that custody the columns we'd like to backfill. If CustodySync fails, we don't
    /// want to penalize all our synced peers, so we use this variable to keep track of peers that
    /// have participated and only penalize these peers if custody sync fails.
    participating_peers: HashSet<PeerId>,

    /// When a custody backfill sync fails, we keep track of whether a new fully synced peer has joined.
    /// This signifies that we are able to attempt to restart a failed chain.
    restart_failed_sync: bool,

    /// Reference to the beacon chain to obtain initial starting points for the backfill sync.
    beacon_chain: Arc<BeaconChain<T>>,

    /// Reference to the network globals in order to obtain valid peers to backfill blocks from
    /// (i.e synced peers).
    network_globals: Arc<NetworkGlobals<T::EthSpec>>,

    /// The data column indices we're looking to backfill.
    data_column_indices: Vec<u64>,
}

impl<T: BeaconChainTypes> CustodyBackfillSync<T> {
    #[instrument(parent = None,
        name = "custody_backfill_sync",
        skip_all
    )]
    pub fn new(
        beacon_chain: Arc<BeaconChain<T>>,
        current_start: Epoch,
        data_column_indices: Vec<u64>,
        network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    ) -> Self {
        let cbs = CustodyBackfillSync {
            batches: BTreeMap::new(),
            processing_target: current_start,
            current_start,
            last_batch_downloaded: false,
            to_be_downloaded: current_start,
            network_globals,
            current_processing_batch: None,
            validated_batches: 0,
            participating_peers: HashSet::new(),
            restart_failed_sync: false,
            beacon_chain,
            data_column_indices,
        };

        // Update the global network state with the current backfill state.
        cbs.set_state(BackFillState::Paused);
        cbs
    }

    /// Starts or resumes syncing.
    ///
    /// If resuming is successful, reports back the current syncing metrics.
    #[must_use = "A failure here indicates the custody backfill sync has failed and the global sync state should be updated"]
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    pub fn start(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<SyncStart, BackFillError> {
        match self.state() {
            BackFillState::Syncing => {} // already syncing ignore.
            BackFillState::Paused => {
                if self
                    .network_globals
                    .peers
                    .read()
                    .synced_peers()
                    .next()
                    .is_some()
                {
                    // TODO(cgc-backfill) get peers that we can sync with
                    // If there are peers to resume with, begin the resume.
                    debug!(start_epoch = ?self.current_start, awaiting_batches = self.batches.len(), processing_target = ?self.processing_target, "Resuming custody backfill sync");
                    self.set_state(BackFillState::Syncing);
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
            BackFillState::Failed => {
                // Attempt to recover from a failed sync. All local variables should be reset and
                // cleared already for a fresh start.
                // We only attempt to restart a failed custody backfill sync if a new synced peer has been
                // added.
                if !self.restart_failed_sync {
                    return Ok(SyncStart::NotSyncing);
                }

                self.set_state(BackFillState::Syncing);

                // TODO(cgc-backfill) we could try figuring out what epoch to start at again, or we can just
                // live with potentially requesting redundant data columns

                debug!(start_epoch = %self.current_start, "Resuming a failed custody backfill sync");

                // begin requesting blocks from the peer pool, until all peers are exhausted.
                self.request_batches(network)?;
            }
            BackFillState::Completed => return Ok(SyncStart::NotSyncing),
        }

        Ok(SyncStart::Syncing {
            completed: (self.validated_batches
                * BACKFILL_EPOCHS_PER_BATCH
                * T::EthSpec::slots_per_epoch()) as usize,
            remaining: self
                .current_start
                .start_slot(T::EthSpec::slots_per_epoch())
                .saturating_sub(self.beacon_chain.genesis_backfill_slot)
                .as_usize(),
        })
    }

    /// When resuming a chain, this function searches for batches that need to be re-downloaded and
    /// transitions their state to redownload the batch.
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn resume_batches(&mut self, network: &mut SyncNetworkContext<T>) -> Result<(), BackFillError> {
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

    /// Requests the batch assigned to the given id from a given peer.
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn send_batch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
    ) -> Result<(), BackFillError> {
        if let Some(batch) = self.batches.get_mut(&batch_id) {
            let synced_peers = self
                .network_globals
                .peers
                .read()
                .synced_peers()
                .cloned()
                .collect::<HashSet<_>>();

            let failed_peers = batch.failed_peers();

            // TODO(cgc-backfill) calculate start slot
            // match network.dat
            match network.custody_sync_data_columns_by_range_request(
                Slot::new(0),
                T::EthSpec::slots_per_epoch(),
                &self.data_column_indices,
                batch_id,
                &synced_peers,
                &failed_peers,
            ) {
                Ok(request_id) => {
                    debug!(epoch = %batch_id, %batch, "Requesting batch");
                    if let Err(e) = batch.start_downloading(request_id) {
                        return self.fail_sync(BackFillError::BatchInvalidState(batch_id, e.0));
                    }
                }
                Err(e) => match e {
                    RpcRequestSendError::NoPeer(no_peer_error) => {
                        // If we are here the chain has no more synced peers
                        info!(
                            "reason" = format!("insufficient_synced_peers({no_peer_error:?})"),
                            "Custody backfill sync paused"
                        );
                        self.set_state(BackFillState::Paused);
                        return Err(BackFillError::Paused);
                    }
                    RpcRequestSendError::InternalError(e) => {
                        // NOTE: under normal conditions this shouldn't happen but we handle it anyway
                        warn!(%batch_id, error = ?e, %batch, "Could not send batch request");
                        // register the failed download and check if the batch can be retried
                        if let Err(e) = batch.start_downloading(1) {
                            return self.fail_sync(BackFillError::BatchInvalidState(batch_id, e.0));
                        }

                        match batch.download_failed(None) {
                            Err(e) => {
                                self.fail_sync(BackFillError::BatchInvalidState(batch_id, e.0))?
                            }
                            Ok(BatchOperationOutcome::Failed { blacklist: _ }) => {
                                self.fail_sync(BackFillError::BatchDownloadFailed(batch_id))?
                            }
                            Ok(BatchOperationOutcome::Continue) => {
                                return self.send_batch(network, batch_id)
                            }
                        }
                    }
                },
            }
        };

        Ok(())
    }

    /// The syncing process has failed.
    ///
    /// This resets past variables, to allow for a fresh start when resuming.
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn fail_sync(&mut self, error: BackFillError) -> Result<(), BackFillError> {
        // Some errors shouldn't fail the chain.
        if matches!(error, BackFillError::Paused) {
            return Ok(());
        }

        // Set the state
        self.set_state(BackFillState::Failed);
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
        error!(?error, "Custody backfill sync failed");

        // Return the error, kinda weird pattern, but I want to use
        // `self.fail_chain(_)?` in other parts of the code.
        Err(error)
    }

    /// Attempts to request the next required batches from the peer pool if custody backfill is in syncing state. It will exhaust the peer
    /// pool and left over batches until the batch buffer is reached or all peers are exhausted.
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn request_batches(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<(), BackFillError> {
        if !matches!(self.state(), BackFillState::Syncing) {
            return Ok(());
        }

        // find the next pending batch and request it from the peer
        // Note: for this function to not infinite loop we must:
        // - If `include_next_batch` returns Some we MUST increase the count of batches that are
        //   accounted in the `BACKFILL_BATCH_BUFFER_SIZE` limit in the `matches!` statement of
        //   that function.
        while let Some(batch_id) = self.include_next_batch(network) {
            // send the batch
            self.send_batch(network, batch_id)?;
        }

        // No more batches, simply stop
        Ok(())
    }

    /// Processes the next ready batch.
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn process_completed_batches(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<ProcessResult, BackFillError> {
        // Only process batches if backfill is syncing and only process one batch at a time
        if self.state() != BackFillState::Syncing || self.current_processing_batch.is_some() {
            return Ok(ProcessResult::Successful);
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
                    self.fail_sync(BackFillError::InvalidSyncState(String::from(
                        "Invalid expected batch state",
                    )))?;
                    return Ok(ProcessResult::Successful);
                }
                CustodyBatchState::AwaitingValidation(_) => {
                    // TODO: I don't think this state is possible, log a CRIT just in case.
                    // If this is not observed, add it to the failed state branch above.
                    crit!(
                        batch = ?self.processing_target,
                        "Chain encountered a robust batch awaiting validation"
                    );

                    self.processing_target -= BACKFILL_EPOCHS_PER_BATCH;
                    if self.to_be_downloaded >= self.processing_target {
                        self.to_be_downloaded = self.processing_target - BACKFILL_EPOCHS_PER_BATCH;
                    }
                    self.request_batches(network)?;
                }
            }
        } else {
            self.fail_sync(BackFillError::InvalidSyncState(format!(
                "Batch not found for current processing target {}",
                self.processing_target
            )))?;
            return Ok(ProcessResult::Successful);
        }
        Ok(ProcessResult::Successful)
    }

    /// Processes the batch with the given id.
    /// The batch must exist and be ready for processing
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn process_batch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
    ) -> Result<ProcessResult, BackFillError> {
        // Only process batches if this chain is Syncing, and only one at a time
        if self.state() != BackFillState::Syncing || self.current_processing_batch.is_some() {
            return Ok(ProcessResult::Successful);
        }

        let Some(batch) = self.batches.get_mut(&batch_id) else {
            return self
                .fail_sync(BackFillError::InvalidSyncState(format!(
                    "Trying to process a batch that does not exist: {}",
                    batch_id
                )))
                .map(|_| ProcessResult::Successful);
        };

        // NOTE: We send empty batches to the processor in order to trigger the block processor
        // result callback. This is done, because an empty batch could end a chain and the logic
        // for removing chains and checking completion is in the callback.

        let (data_column_sidecar_list, _) = match batch.start_processing() {
            Err(e) => {
                return self
                    .fail_sync(BackFillError::BatchInvalidState(batch_id, e.0))
                    .map(|_| ProcessResult::Successful)
            }
            Ok(v) => v,
        };

        let process_id = batch_id as CustodyBackSyncBatchId;
        self.current_processing_batch = Some(batch_id);

        if let Err(e) = network
            .beacon_processor()
            .send_data_column_sidecar_list(process_id, data_column_sidecar_list)
        {
            crit!(
                msg = "process_batch",
                error = %e,
                batch = ?self.processing_target,
                "Failed to send custody backfill segment to processor."
            );
            // This is unlikely to happen but it would stall syncing since the batch now has no
            // blocks to continue, and the chain is expecting a processing result that won't
            // arrive. To mitigate this, (fake) fail this processing so that the batch is
            // re-downloaded.
            self.on_batch_process_result(
                network,
                batch_id,
                &CustodyBatchProcessResult::NonFaultyFailure,
            )
        } else {
            Ok(ProcessResult::Successful)
        }
    }

    /// The block processor has completed processing a batch. This function handles the result
    /// of the batch processor.
    /// If an error is returned the Custody BackFill sync has failed.
    #[instrument(parent = None,
        level = "info",
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    #[must_use = "A failure here indicates the custody backfill sync has failed and the global sync state should be updated"]
    pub fn on_batch_process_result(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
        result: &CustodyBatchProcessResult,
    ) -> Result<ProcessResult, BackFillError> {
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
                            .fail_sync(BackFillError::InvalidSyncState(format!(
                                "Current processing batch not found: {}",
                                batch_id
                            )))
                            .map(|_| ProcessResult::Successful);
                    }
                }
            }
        };

        let Some(peer) = batch.processing_peer() else {
            self.fail_sync(BackFillError::BatchInvalidState(
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
                imported_data_columns,
                ..
            } => {
                // TODO(cgc-backfill)
                todo!()
            }
            CustodyBatchProcessResult::FaultyFailure {
                imported_data_columns,
                penalty,
            } => {
                match batch.processing_completed(BatchProcessingResult::FaultyFailure) {
                    Err(e) => {
                        // Batch was in the wrong state
                        self.fail_sync(BackFillError::BatchInvalidState(batch_id, e.0))
                            .map(|_| ProcessResult::Successful)
                    }
                    Ok(BatchOperationOutcome::Failed { blacklist: _ }) => {
                        // check that we have not exceeded the re-process retry counter
                        // If a batch has exceeded the invalid batch lookup attempts limit, it means
                        // that it is likely all peers are sending invalid batches
                        // repeatedly and are either malicious or faulty. We stop custody backfill sync and
                        // report all synced peers that have participated.
                        warn!(
                            score_adjustment = %penalty,
                            batch_epoch = %batch_id,
                            "Custody backfill batch failed to download. Penalizing peers"
                        );

                        for peer in self.participating_peers.drain() {
                            // TODO(das): `participating_peers` only includes block peers. Should we
                            // penalize the custody column peers too?
                            network.report_peer(peer, *penalty, "backfill_batch_failed");
                        }
                        self.fail_sync(BackFillError::BatchProcessingFailed(batch_id))
                            .map(|_| ProcessResult::Successful)
                    }

                    Ok(BatchOperationOutcome::Continue) => {
                        // chain can continue. Check if it can be progressed
                        if *imported_data_columns > 0 {
                            // At least one block was successfully verified and imported, then we can be sure all
                            // previous batches are valid and we only need to download the current failed
                            // batch.
                            self.advance(network, batch_id);
                        }
                        // Handle this invalid batch, that is within the re-process retries limit.
                        self.handle_invalid_batch(network, batch_id)
                            .map(|_| ProcessResult::Successful)
                    }
                }
            }
            CustodyBatchProcessResult::NonFaultyFailure => {
                if let Err(e) = batch.processing_completed(BatchProcessingResult::NonFaultyFailure)
                {
                    self.fail_sync(BackFillError::BatchInvalidState(batch_id, e.0))?;
                }
                self.send_batch(network, batch_id)?;
                Ok(ProcessResult::Successful)
            }
        }
    }

    /// An invalid batch has been received that could not be processed, but that can be retried.
    ///
    /// These events occur when a peer has successfully responded with data columns, but the data columns we
    /// have received are incorrect or invalid. This indicates the peer has not performed as
    /// intended and can result in down scoring a peer.
    #[instrument(parent = None,
        level = "info",
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn handle_invalid_batch(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
    ) -> Result<(), BackFillError> {
        // The current batch could not be processed, indicating either the current or previous
        // batches are invalid.

        // TODO(cgc-backfill) update comments
        // The previous batch could be incomplete due to the block sizes being too large to fit in
        // a single RPC request or there could be consecutive empty batches which are not supposed
        // to be there

        // The current (sub-optimal) strategy is to simply re-request all batches that could
        // potentially be faulty. If a batch returns a different result than the original and
        // results in successful processing, we downvote the original peer that sent us the batch.

        // this is our robust `processing_target`. All previous batches must be awaiting
        // validation
        let mut redownload_queue = Vec::new();

        for (id, batch) in self
            .batches
            .iter_mut()
            .filter(|(&id, _batch)| id > batch_id)
        {
            match batch
                .validation_failed()
                .map_err(|e| BackFillError::BatchInvalidState(batch_id, e.0))?
            {
                BatchOperationOutcome::Failed { blacklist: _ } => {
                    // Batch has failed and cannot be redownloaded.
                    return self.fail_sync(BackFillError::BatchProcessingFailed(batch_id));
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

    // TODO(cgc-backfill) update comments
    /// Removes any batches previous to the given `validating_epoch` and updates the current
    /// boundaries of the chain.
    ///
    /// The `validating_epoch` must align with batch boundaries.
    ///
    /// If a previous batch has been validated and it had been re-processed, penalize the original
    /// peer.
    #[instrument(parent = None,
        level = "info",
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn advance(&mut self, network: &mut SyncNetworkContext<T>, validating_epoch: Epoch) {
        // make sure this epoch produces an advancement
        if validating_epoch >= self.current_start {
            return;
        }

        // We can now validate higher batches that the current batch. Here we remove all
        // batches that are higher than the current batch. We add on an extra
        // `BACKFILL_EPOCHS_PER_BATCH` as `split_off` is inclusive.
        let removed_batches = self
            .batches
            .split_off(&(validating_epoch + BACKFILL_EPOCHS_PER_BATCH));

        for (id, batch) in removed_batches.into_iter() {
            self.validated_batches = self.validated_batches.saturating_add(1);
            // only for batches awaiting validation can we be sure the last attempt is
            // right, and thus, that any different attempt is wrong
            match batch.state() {
                CustodyBatchState::AwaitingValidation(ref processed_attempt) => {
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
                    crit!("batch indicates inconsistent chain state while advancing custody backfill sync")
                }
                CustodyBatchState::AwaitingProcessing(..) => {}
                CustodyBatchState::Processing(_) => {
                    debug!(batch = %id, %batch, "Advancing custody backfill sync while processing a batch");
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
            // if custody backfill is advanced by Range beyond the previous `self.to_be_downloaded`, we
            // won't have this batch, so we need to request it.
            self.to_be_downloaded -= BACKFILL_EPOCHS_PER_BATCH;
        }
        debug!(?validating_epoch, processing_target = ?self.processing_target, "Custody backfill advanced");
    }

    /// Creates the next required batch from the chain. If there are no more batches required,
    /// `false` is returned.
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn include_next_batch(&mut self, network: &mut SyncNetworkContext<T>) -> Option<BatchId> {
        // TODO(cgc-backfill) make sure were stopping at the DA window as per
        // the comment below
        // don't request batches beyond the data availability window;
        if self.last_batch_downloaded {
            return None;
        }

        // only request batches up to the buffer size limit
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
                    .saturating_sub(BACKFILL_EPOCHS_PER_BATCH);
                self.include_next_batch(network)
            }
            Entry::Vacant(entry) => {
                let batch_type = network.batch_type(batch_id);
                entry.insert(CustodyBatchInfo::new(&batch_id, BACKFILL_EPOCHS_PER_BATCH));
                if self.would_complete(batch_id) {
                    self.last_batch_downloaded = true;
                }
                self.to_be_downloaded = self
                    .to_be_downloaded
                    .saturating_sub(BACKFILL_EPOCHS_PER_BATCH);
                Some(batch_id)
            }
        }
    }

    /// Data columns have been received for this batch.
    /// If the data column(s) correctly complete the batch it will be processed if possible.
    /// If this returns an error, the custody backfill sync has failed and will be restarted once new peers
    /// join the system.
    /// The sync manager should update the global sync state on failure.
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    #[must_use = "A failure here indicates the custdy backfill sync has failed and the global sync state should be updated"]
    pub fn on_block_response(
        &mut self,
        network: &mut SyncNetworkContext<T>,
        batch_id: BatchId,
        peer_id: &PeerId,
        request_id: Id,
        data_columns: DataColumnSidecarList<T::EthSpec>,
    ) -> Result<ProcessResult, BackFillError> {
        // check if we have this batch
        let Some(batch) = self.batches.get_mut(&batch_id) else {
            if !matches!(self.state(), BackFillState::Failed) {
                // A batch might get removed when custody backfill sync advances, so this is non fatal.
                debug!(epoch = %batch_id, "Received a data column for unknown batch");
            }
            return Ok(ProcessResult::Successful);
        };

        // A batch could be retried without the peer failing the request (disconnecting/
        // sending an error /timeout) if the peer is removed for other
        // reasons. Check that the data columns belong to the expected peer, and that the
        // request_id matches
        if !batch.is_expecting_data_columns(&request_id) {
            return Ok(ProcessResult::Successful);
        }

        match batch.download_completed(data_columns, *peer_id) {
            Ok(received) => {
                let awaiting_batches =
                    self.processing_target.saturating_sub(batch_id) / BACKFILL_EPOCHS_PER_BATCH;
                debug!(
                    epoch = %batch_id,
                    blocks = received,
                    %awaiting_batches,
                    "Completed batch received"
                );

                // pre-emptively request more data columns from peers whilst we process current data columns,
                self.request_batches(network)?;
                self.process_completed_batches(network)
            }
            Err(e) => {
                self.fail_sync(BackFillError::BatchInvalidState(batch_id, e.0))?;
                Ok(ProcessResult::Successful)
            }
        }
    }

    /// Checks if custody backfill would complete by syncing to `start_epoch`.
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn would_complete(&self, _start_epoch: Epoch) -> bool {
        // TODO(cgc-backfill) this should return true if start
        // start epoch == DA window
        false
    }

    /// Updates the global network state indicating the current state of a backfill sync.
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn set_state(&self, state: BackFillState) {
        *self.network_globals.backfill_state.write() = state;
    }

    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn state(&self) -> BackFillState {
        self.network_globals.backfill_state.read().clone()
    }
}
