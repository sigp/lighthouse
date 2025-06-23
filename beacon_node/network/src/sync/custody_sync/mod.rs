mod custody_batch;

use std::{
    collections::{btree_map::Entry, BTreeMap, HashSet},
    sync::Arc,
};

use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::{
    rpc::methods::DataColumnsByRangeRequest, service::api_types::RangeRequestId,
    types::BackFillState, NetworkGlobals, PeerId,
};
use logging::crit;
use tracing::{debug, error, info, instrument, warn};
use types::{DataColumnSidecar, DataColumnSidecarList, Epoch, EthSpec, Slot};

use crate::{
    network_beacon_processor::ChainSegmentProcessId,
    sync::{
        backfill_sync::{
            BackFillError, ProcessResult, ResetEpochError, SyncStart, BACKFILL_EPOCHS_PER_BATCH,
        },
        custody_sync::custody_batch::{CustodyBatchInfo, CustodyBatchState},
        network_context::{RpcRequestSendError, SyncNetworkContext},
        range_sync::BatchId,
        BatchOperationOutcome,
    },
};

pub use custody_batch::CustodySyncBatchConfig;

/// The maximum number of batches to queue before requesting more.
const BACKFILL_BATCH_BUFFER_SIZE: u8 = 20;

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
        data_column_indices: Vec<u64>,
        current_start: Epoch,
        beacon_chain: Arc<BeaconChain<T>>,
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
                todo!(),
                T::EthSpec::slots_per_epoch(),
                self.data_column_indices,
                RangeRequestId::CustodySync { batch_id },
                &synced_peers,
                &failed_peers,
            ) {
                Ok(request_ids) => {
                    for request_id in request_ids {
                        if let Err(e) = batch.start_downloading(request_id) {
                            return self.fail_sync(BackFillError::BatchInvalidState(batch_id, e.0));
                        }
                        debug!(epoch = %batch_id, %batch, "Requesting batch");
                        return Ok(());
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

        let process_id = ChainSegmentProcessId::CustodyBackSyncBatchId(batch_id);
        self.current_processing_batch = Some(batch_id);

        if let Err(e) = network
            .beacon_processor()
            .send_chain_segment(process_id, blocks)
        {
            crit!(
                msg = "process_batch",
                error = %e,
                batch = ?self.processing_target,
                "Failed to send backfill segment to processor."
            );
            // This is unlikely to happen but it would stall syncing since the batch now has no
            // blocks to continue, and the chain is expecting a processing result that won't
            // arrive. To mitigate this, (fake) fail this processing so that the batch is
            // re-downloaded.
            self.on_batch_process_result(network, batch_id, &BatchProcessResult::NonFaultyFailure)
        } else {
            Ok(ProcessResult::Successful)
        }
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
