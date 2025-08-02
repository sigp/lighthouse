use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::{types::BackFillState, NetworkGlobals, PeerId};
use logging::crit;
use tracing::{debug, error, info, instrument, warn};

use types::EthSpec;

use crate::sync::{
    backfill_sync::{ProcessResult, SyncStart},
    network_context::SyncNetworkContext,
    range_sync::{BatchId, BatchOperationOutcome, CustodyBatchInfo, CustodyBatchState},
};

mod manager;

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
    // BatchProcessingFailed(#[allow(dead_code)] BatchId),
    /// A batch entered an invalid state.
    BatchInvalidState(#[allow(dead_code)] BatchId, #[allow(dead_code)] String),
    /// The sync algorithm entered an invalid state.
    InvalidSyncState(#[allow(dead_code)] String),
    // /// The chain became paused.
    Paused,
}

struct CustodySync<T: BeaconChainTypes> {
    /// Keeps track of the current progress of the custody backfill.
    /// This only gets refreshed from the beacon chain if we enter a failed state.
    current_start: BatchId,

    /// Starting epoch of the batch that needs to be processed next.
    /// This is incremented as the chain advances.
    processing_target: BatchId,

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
    /// Pauses the backfill sync if it's currently syncing.
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    pub fn pause(&mut self) {
        if let BackFillState::Syncing = self.state() {
            debug!(processed_epochs = %self.validated_batches, to_be_processed = %self.current_start,"Custody backfill sync paused");
            self.set_state(BackFillState::Paused);
        }
    }

    /// Starts or resumes syncing.
    ///
    /// If resuming is successful, reports back the current syncing metrics.
    #[must_use = "A failure here indicates the backfill sync has failed and the global sync state should be updated"]
    #[instrument(parent = None,
        fields(service = "backfill_sync"),
        name = "backfill_sync",
        skip_all
    )]
    pub fn start(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<SyncStart, CustodyBackfillError> {
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
                    // If there are peers to resume with, begin the resume.
                    debug!(start_epoch = ?self.current_start, awaiting_batches = self.batches.len(), processing_target = ?self.processing_target, "Resuming backfill sync");
                    self.set_state(BackFillState::Syncing);
                    // Resume any previously failed batches.
                    self.resume_batches(network)?;
                    // begin requesting blocks from the peer pool, until all peers are exhausted.
                    self.request_batches(network)?;

                    // // start processing batches if needed
                    // self.process_completed_batches(network)?;
                } else {
                    return Ok(SyncStart::NotSyncing);
                }
            }
            BackFillState::Failed => {
                // Attempt to recover from a failed sync. All local variables should be reset and
                // cleared already for a fresh start.
                // We only attempt to restart a failed backfill sync if a new synced peer has been
                // added.
                if !self.restart_failed_sync {
                    return Ok(SyncStart::NotSyncing);
                }

                self.set_state(BackFillState::Syncing);

                // Obtain a new start slot, from the beacon chain and handle possible errors.
                // if let Err(e) = self.reset_start_epoch() {
                //     // This infallible match exists to force us to update this code if a future
                //     // refactor of `ResetEpochError` adds a variant.
                //     let ResetEpochError::SyncCompleted = e;
                //     error!("Backfill sync completed whilst in failed status");
                //     self.set_state(BackFillState::Completed);
                //     return Err(BackFillError::InvalidSyncState(String::from(
                //         "chain completed",
                //     )));
                // }

                debug!(start_epoch = %self.current_start, "Resuming a failed backfill sync");

                // begin requesting data columns from the peer pool, until all peers are exhausted.
                self.request_batches(network)?;
            }
            BackFillState::Completed => return Ok(SyncStart::NotSyncing),
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

    /// Attempts to request the next required batches from the peer pool. It will exhaust the peer
    /// pool and left over batches until the batch buffer is reached or all peers are exhausted.
    #[instrument(parent = None,
        fields(service = "backfill_sync"),
        name = "backfill_sync",
        skip_all
    )]
    fn request_batches(
        &mut self,
        network: &mut SyncNetworkContext<T>,
    ) -> Result<(), CustodyBackfillError> {
        if !matches!(self.state(), BackFillState::Syncing) {
            return Ok(());
        }

        // find the next pending batch and request it from the peer
        // Note: for this function to not infinite loop we must:
        // - If `include_next_batch` returns Some we MUST increase the count of batches that are
        //   accounted in the `BACKFILL_BATCH_BUFFER_SIZE` limit in the `matches!` statement of
        //   that function.
        // while let Some(batch_id) = self.include_next_batch(network) {
        //     // send the batch
        //     self.send_batch(network, batch_id)?;
        // }

        // No more batches, simply stop
        Ok(())
    }

    /// When resuming a chain, this function searches for batches that need to be re-downloaded and
    /// transitions their state to redownload the batch.
    #[instrument(parent = None,
        fields(service = "backfill_sync"),
        name = "backfill_sync",
        skip_all
    )]
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

    /// Requests the batch assigned to the given id from a given peer.
    #[instrument(parent = None,
        fields(service = "backfill_sync"),
        name = "backfill_sync",
        skip_all
    )]
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

            match network.custody_sync_data_column_by_range_request(
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
                            "Backfill sync paused"
                        );
                        self.set_state(BackFillState::Paused);
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
                                return self.send_batch(network, batch_id)
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
    #[instrument(parent = None,
        fields(service = "custody_backfill_sync"),
        name = "custody_backfill_sync",
        skip_all
    )]
    fn fail_sync(&mut self, error: CustodyBackfillError) -> Result<(), CustodyBackfillError> {
        // Some errors shouldn't cause failure.
        if matches!(error, CustodyBackfillError::Paused) {
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
        error!(?error, "Backfill sync failed");

        // Return the error, kinda weird pattern, but I want to use
        // `self.fail_chain(_)?` in other parts of the code.
        Err(error)
    }

    /// A peer has disconnected.
    /// If the peer has active batches, those are considered failed and re-requested.
    #[instrument(parent = None,
        fields(service = "custoy_backfill_sync"),
        name = "custoy_backfill_sync",
        skip_all
    )]
    #[must_use = "A failure here indicates custody sync has failed and the global sync state should be updated"]
    pub fn peer_disconnected(&mut self, peer_id: &PeerId) -> Result<(), CustodyBackfillError> {
        if matches!(self.state(), BackFillState::Failed) {
            return Ok(());
        }

        // Remove the peer from the participation list
        self.participating_peers.remove(peer_id);
        Ok(())
    }

    fn state(&self) -> BackFillState {
        self.network_globals.custody_sync_state.read().clone()
    }

    /// Updates the global network state indicating the current state of a backfill sync.
    #[instrument(parent = None,
        fields(service = "backfill_sync"),
        name = "backfill_sync",
        skip_all
    )]
    fn set_state(&self, state: BackFillState) {
        *self.network_globals.backfill_state.write() = state;
    }
}
