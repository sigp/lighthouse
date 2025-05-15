use crate::metrics::{self, register_process_result_metrics};
use crate::network_beacon_processor::{NetworkBeaconProcessor, FUTURE_SLOT_TOLERANCE};
use crate::sync::BatchProcessResult;
use crate::sync::{
    manager::{BlockProcessType, SyncMessage},
    ChainId,
};
use beacon_chain::block_verification_types::{AsBlock, RpcBlock};
use beacon_chain::data_availability_checker::AvailabilityCheckError;
use beacon_chain::data_column_verification::verify_kzg_for_data_column_list;
use beacon_chain::{
    validator_monitor::get_slot_delay_ms, AvailabilityProcessingStatus, BeaconChainTypes,
    BlockError, ChainSegmentResult, HistoricalBlockError, NotifyExecutionLayer,
};
use beacon_processor::{
    work_reprocessing_queue::{QueuedRpcBlock, ReprocessQueueMessage},
    AsyncFn, BlockingFn, DuplicateCache,
};
use lighthouse_network::PeerAction;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use store::KzgCommitment;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use types::beacon_block_body::format_kzg_commitments;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{
    BlockImportSource, ColumnIndex, DataColumnSidecar, DataColumnSidecarList, Epoch, Hash256,
};

/// Id associated to a batch processing request, either a sync batch or a parent lookup.
#[derive(Clone, Debug, PartialEq)]
pub enum ChainSegmentProcessId {
    /// Processing Id of a range syncing batch.
    RangeBatchId(ChainId, Epoch),
    /// Processing ID for a backfill syncing batch.
    BackSyncBatchId(Epoch),
}

/// Returned when a chain segment import fails.
#[derive(Debug)]
pub struct ChainSegmentFailed {
    /// To be displayed in logs.
    pub message: String,
    /// Used to penalize peers.
    pub peer_action: Option<PeerGroupAction>,
}

/// Tracks which block(s) component caused the block to be invalid. Used to attribute fault in sync.
#[derive(Debug)]
pub struct PeerGroupAction {
    pub block_peer: Option<PeerAction>,
    pub column_peer: HashMap<ColumnIndex, PeerAction>,
}

impl PeerGroupAction {
    fn block_peer(action: PeerAction) -> Self {
        Self {
            block_peer: Some(action),
            column_peer: <_>::default(),
        }
    }

    fn column_peers(columns: &[ColumnIndex], action: PeerAction) -> Self {
        Self {
            block_peer: None,
            column_peer: HashMap::from_iter(columns.iter().map(|index| (*index, action))),
        }
    }

    fn from_availability_check_error(e: &AvailabilityCheckError) -> Option<Self> {
        match e {
            AvailabilityCheckError::InvalidBlobs(_) => {
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            AvailabilityCheckError::InvalidColumn(errors) => Some(PeerGroupAction::column_peers(
                &errors.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
                PeerAction::LowToleranceError,
            )),
            AvailabilityCheckError::KzgCommitmentMismatch { .. } => None, // should never happen after checking inclusion proof
            AvailabilityCheckError::Unexpected(_) => None,                // internal
            AvailabilityCheckError::MissingBlobs => {
                Some(PeerGroupAction::block_peer(PeerAction::HighToleranceError))
            }
            // TOOD(das): PeerAction::High may be too soft of a penalty. Also may be deprecated
            // with https://github.com/sigp/lighthouse/issues/6258
            AvailabilityCheckError::MissingCustodyColumns(columns) => Some(
                PeerGroupAction::column_peers(columns, PeerAction::HighToleranceError),
            ),
            AvailabilityCheckError::BlobIndexInvalid(_) => {
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            AvailabilityCheckError::DataColumnIndexInvalid(_) => None, // unreachable
            AvailabilityCheckError::StoreError(_) => None,             // unreachable
            AvailabilityCheckError::BlockReplayError(_) => None,       // internal error
            AvailabilityCheckError::RebuildingStateCaches(_) => None,  // internal error
            AvailabilityCheckError::SlotClockError => None,            // internal error
        }
    }
}

impl<T: BeaconChainTypes> NetworkBeaconProcessor<T> {
    /// Returns an async closure which processes a beacon block received via RPC.
    ///
    /// This separate function was required to prevent a cycle during compiler
    /// type checking.
    pub fn generate_rpc_beacon_block_process_fn(
        self: Arc<Self>,
        block_root: Hash256,
        block: RpcBlock<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) -> AsyncFn {
        let process_fn = async move {
            let reprocess_tx = self.reprocess_tx.clone();
            let duplicate_cache = self.duplicate_cache.clone();
            self.process_rpc_block(
                block_root,
                block,
                seen_timestamp,
                process_type,
                reprocess_tx,
                duplicate_cache,
            )
            .await;
        };
        Box::pin(process_fn)
    }

    /// Returns the `process_fn` and `ignore_fn` required when requeuing an RPC block.
    pub fn generate_rpc_beacon_block_fns(
        self: Arc<Self>,
        block_root: Hash256,
        block: RpcBlock<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) -> (AsyncFn, BlockingFn) {
        // An async closure which will import the block.
        let process_fn = self.clone().generate_rpc_beacon_block_process_fn(
            block_root,
            block,
            seen_timestamp,
            process_type.clone(),
        );
        // A closure which will ignore the block.
        let ignore_fn = move || {
            // Sync handles these results
            self.send_sync_message(SyncMessage::BlockComponentProcessed {
                process_type,
                result: crate::sync::manager::BlockProcessingResult::Ignored,
            });
        };
        (process_fn, Box::new(ignore_fn))
    }

    /// Attempt to process a block received from a direct RPC request.
    #[allow(clippy::too_many_arguments)]
    pub async fn process_rpc_block(
        self: Arc<NetworkBeaconProcessor<T>>,
        block_root: Hash256,
        block: RpcBlock<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
        reprocess_tx: mpsc::Sender<ReprocessQueueMessage>,
        duplicate_cache: DuplicateCache,
    ) {
        // Check if the block is already being imported through another source
        let Some(handle) = duplicate_cache.check_and_insert(block_root) else {
            debug!(
                action = "sending rpc block to reprocessing queue",
                %block_root,
                ?process_type,
                "Gossip block is being processed"
            );

            // Send message to work reprocess queue to retry the block
            let (process_fn, ignore_fn) = self.clone().generate_rpc_beacon_block_fns(
                block_root,
                block,
                seen_timestamp,
                process_type,
            );
            let reprocess_msg = ReprocessQueueMessage::RpcBlock(QueuedRpcBlock {
                beacon_block_root: block_root,
                process_fn,
                ignore_fn,
            });

            if reprocess_tx.try_send(reprocess_msg).is_err() {
                error!(source = "rpc", %block_root,"Failed to inform block import")
            };
            return;
        };

        let slot = block.slot();
        let block_has_data = block.as_block().num_expected_blobs() > 0;
        let parent_root = block.message().parent_root();
        let commitments_formatted = block.as_block().commitments_formatted();

        debug!(
            ?block_root,
            proposer = block.message().proposer_index(),
            slot = %block.slot(),
            commitments_formatted,
            ?process_type,
            "Processing RPC block"
        );

        let signed_beacon_block = block.block_cloned();
        let result = self
            .chain
            .process_block_with_early_caching(
                block_root,
                block,
                BlockImportSource::Lookup,
                NotifyExecutionLayer::Yes,
            )
            .await;
        register_process_result_metrics(&result, metrics::BlockSource::Rpc, "block");

        // RPC block imported, regardless of process type
        match result.as_ref() {
            Ok(AvailabilityProcessingStatus::Imported(hash)) => {
                info!(
                    %slot,
                    %hash,
                    "New RPC block received",
                );
                // Trigger processing for work referencing this block.
                let reprocess_msg = ReprocessQueueMessage::BlockImported {
                    block_root: *hash,
                    parent_root,
                };
                if reprocess_tx.try_send(reprocess_msg).is_err() {
                    error!(
                        source = "rpc",
                        block_root = %hash,
                        "Failed to inform block import"
                    );
                };
                self.chain.block_times_cache.write().set_time_observed(
                    *hash,
                    slot,
                    seen_timestamp,
                    None,
                    None,
                );

                self.chain.recompute_head_at_current_slot().await;
            }
            Ok(AvailabilityProcessingStatus::MissingComponents(..)) => {
                // Block is valid, we can now attempt fetching blobs from EL using version hashes
                // derived from kzg commitments from the block, without having to wait for all blobs
                // to be sent from the peers if we already have them.
                let publish_blobs = false;
                self.fetch_engine_blobs_and_publish(signed_beacon_block, block_root, publish_blobs)
                    .await
            }
            _ => {}
        }

        // RPC block imported or execution validated. If the block was already imported by gossip we
        // receive Err(BlockError::AlreadyKnown).
        if result.is_ok() &&
            // Block has at least one blob, so it produced columns
            block_has_data &&
            // Block slot is within the DA boundary (should always be the case) and PeerDAS is activated
            self.chain.should_sample_slot(slot)
        {
            self.send_sync_message(SyncMessage::SampleBlock(block_root, slot));
        }

        // Sync handles these results
        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type,
            result: result.into(),
        });

        // Drop the handle to remove the entry from the cache
        drop(handle);
    }

    /// Returns an async closure which processes a list of blobs received via RPC.
    ///
    /// This separate function was required to prevent a cycle during compiler
    /// type checking.
    pub fn generate_rpc_blobs_process_fn(
        self: Arc<Self>,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) -> AsyncFn {
        let process_fn = async move {
            self.clone()
                .process_rpc_blobs(block_root, blobs, seen_timestamp, process_type)
                .await;
        };
        Box::pin(process_fn)
    }

    /// Attempt to process a list of blobs received from a direct RPC request.
    pub async fn process_rpc_blobs(
        self: Arc<NetworkBeaconProcessor<T>>,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) {
        let Some(slot) = blobs
            .iter()
            .find_map(|blob| blob.as_ref().map(|blob| blob.slot()))
        else {
            return;
        };

        let (indices, commitments): (Vec<u64>, Vec<KzgCommitment>) = blobs
            .iter()
            .filter_map(|blob_opt| {
                blob_opt
                    .as_ref()
                    .map(|blob| (blob.index, blob.kzg_commitment))
            })
            .unzip();
        let commitments = format_kzg_commitments(&commitments);

        debug!(
            ?indices,
            %block_root,
            %slot,
            commitments,
            "RPC blobs received"
        );

        if let Ok(current_slot) = self.chain.slot() {
            if current_slot == slot {
                // Note: this metric is useful to gauge how long it takes to receive blobs requested
                // over rpc. Since we always send the request for block components at `slot_clock.single_lookup_delay()`
                // we can use that as a baseline to measure against.
                let delay = get_slot_delay_ms(seen_timestamp, slot, &self.chain.slot_clock);

                metrics::observe_duration(&metrics::BEACON_BLOB_RPC_SLOT_START_DELAY_TIME, delay);
            }
        }

        let result = self.chain.process_rpc_blobs(slot, block_root, blobs).await;
        register_process_result_metrics(&result, metrics::BlockSource::Rpc, "blobs");

        match &result {
            Ok(AvailabilityProcessingStatus::Imported(hash)) => {
                debug!(
                    result = "imported block and blobs",
                    %slot,
                    block_hash = %hash,
                    "Block components retrieved"
                );
                self.chain.recompute_head_at_current_slot().await;
            }
            Ok(AvailabilityProcessingStatus::MissingComponents(_, _)) => {
                debug!(
                    block_hash = %block_root,
                    %slot,
                    "Missing components over rpc"
                );
            }
            Err(BlockError::DuplicateFullyImported(_)) => {
                debug!(
                    block_hash = %block_root,
                    %slot,
                    "Blobs have already been imported"
                );
            }
            Err(e) => {
                warn!(
                    error = ?e,
                    block_hash = %block_root,
                    %slot,
                    "Error when importing rpc blobs"
                );
            }
        }

        // Sync handles these results
        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type,
            result: result.into(),
        });
    }

    pub async fn process_rpc_custody_columns(
        self: Arc<NetworkBeaconProcessor<T>>,
        block_root: Hash256,
        custody_columns: DataColumnSidecarList<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) {
        // custody_columns must always have at least one element
        let Some(slot) = custody_columns.first().map(|d| d.slot()) else {
            return;
        };

        if let Ok(current_slot) = self.chain.slot() {
            if current_slot == slot {
                let delay = get_slot_delay_ms(seen_timestamp, slot, &self.chain.slot_clock);
                metrics::observe_duration(&metrics::BEACON_BLOB_RPC_SLOT_START_DELAY_TIME, delay);
            }
        }

        let mut indices = custody_columns.iter().map(|d| d.index).collect::<Vec<_>>();
        indices.sort_unstable();
        debug!(
            ?indices,
            %block_root,
            %slot,
            "RPC custody data columns received"
        );

        let mut result = self
            .chain
            .process_rpc_custody_columns(custody_columns)
            .await;
        register_process_result_metrics(&result, metrics::BlockSource::Rpc, "custody_columns");

        match &result {
            Ok(availability) => match availability {
                AvailabilityProcessingStatus::Imported(hash) => {
                    debug!(
                        result = "imported block and custody columns",
                        block_hash = %hash,
                        "Block components retrieved"
                    );
                    self.chain.recompute_head_at_current_slot().await;
                }
                AvailabilityProcessingStatus::MissingComponents(_, _) => {
                    debug!(
                        block_hash = %block_root,
                        "Missing components over rpc"
                    );
                    // Attempt reconstruction here before notifying sync, to avoid sending out more requests
                    // that we may no longer need.
                    // We don't publish columns reconstructed from rpc columns to the gossip network,
                    // as these are likely historic columns.
                    let publish_columns = false;
                    if let Some(availability) = self
                        .attempt_data_column_reconstruction(block_root, publish_columns)
                        .await
                    {
                        result = Ok(availability)
                    }
                }
            },
            Err(BlockError::DuplicateFullyImported(_)) => {
                debug!(
                    block_hash = %block_root,
                    "Custody columns have already been imported"
                );
            }
            Err(e) => {
                warn!(
                    error = ?e,
                    block_hash = %block_root,
                    "Error when importing rpc custody columns"
                );
            }
        }

        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type,
            result: result.into(),
        });
    }

    /// Validate a list of data columns received from RPC requests
    pub async fn validate_rpc_data_columns(
        self: Arc<NetworkBeaconProcessor<T>>,
        _block_root: Hash256,
        data_columns: Vec<Arc<DataColumnSidecar<T::EthSpec>>>,
        _seen_timestamp: Duration,
    ) -> Result<(), String> {
        verify_kzg_for_data_column_list(data_columns.iter(), &self.chain.kzg)
            .map_err(|err| format!("{err:?}"))
    }

    /// Process a sampling completed event, inserting it into fork-choice
    pub async fn process_sampling_completed(
        self: Arc<NetworkBeaconProcessor<T>>,
        block_root: Hash256,
    ) {
        self.chain.process_sampling_completed(block_root).await;
    }

    /// Attempt to import the chain segment (`blocks`) to the beacon chain, informing the sync
    /// thread if more blocks are needed to process it.
    pub async fn process_chain_segment(
        &self,
        sync_type: ChainSegmentProcessId,
        downloaded_blocks: Vec<RpcBlock<T::EthSpec>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) {
        let result = match sync_type {
            // this a request from the range sync
            ChainSegmentProcessId::RangeBatchId(chain_id, epoch) => {
                let start_slot = downloaded_blocks.first().map(|b| b.slot().as_u64());
                let end_slot = downloaded_blocks.last().map(|b| b.slot().as_u64());
                let sent_blocks = downloaded_blocks.len();

                match self
                    .process_blocks(downloaded_blocks.iter(), notify_execution_layer)
                    .await
                {
                    (imported_blocks, Ok(_)) => {
                        debug!(
                            batch_epoch = %epoch,
                            first_block_slot = start_slot,
                            chain = chain_id,
                            last_block_slot = end_slot,
                            processed_blocks = sent_blocks,
                            service= "sync",
                            "Batch processed");
                        BatchProcessResult::Success {
                            sent_blocks,
                            imported_blocks,
                        }
                    }
                    (imported_blocks, Err(e)) => {
                        debug!(
                            batch_epoch = %epoch,
                            first_block_slot = start_slot,
                            chain = chain_id,
                            last_block_slot = end_slot,
                            imported_blocks,
                            error = %e.message,
                            service = "sync",
                            "Batch processing failed");
                        match e.peer_action {
                            Some(penalty) => BatchProcessResult::FaultyFailure {
                                imported_blocks,
                                peer_action: penalty,
                                error: e.message,
                            },
                            None => BatchProcessResult::NonFaultyFailure,
                        }
                    }
                }
            }
            // this a request from the Backfill sync
            ChainSegmentProcessId::BackSyncBatchId(epoch) => {
                let start_slot = downloaded_blocks.first().map(|b| b.slot().as_u64());
                let end_slot = downloaded_blocks.last().map(|b| b.slot().as_u64());
                let sent_blocks = downloaded_blocks.len();
                let n_blobs = downloaded_blocks
                    .iter()
                    .map(|wrapped| wrapped.n_blobs())
                    .sum::<usize>();
                let n_data_columns = downloaded_blocks
                    .iter()
                    .map(|wrapped| wrapped.n_data_columns())
                    .sum::<usize>();

                match self.process_backfill_blocks(downloaded_blocks) {
                    Ok(imported_blocks) => {
                        debug!(
                            batch_epoch = %epoch,
                            first_block_slot = start_slot,
                            keep_execution_payload = !self.chain.store.get_config().prune_payloads,
                            last_block_slot = end_slot,
                            processed_blocks = sent_blocks,
                            processed_blobs = n_blobs,
                            processed_data_columns = n_data_columns,
                            service= "sync",
                            "Backfill batch processed");
                        BatchProcessResult::Success {
                            sent_blocks,
                            imported_blocks,
                        }
                    }
                    Err(e) => {
                        debug!(
                            batch_epoch = %epoch,
                            first_block_slot = start_slot,
                            last_block_slot = end_slot,
                            processed_blobs = n_blobs,
                            error = %e.message,
                            service = "sync",
                            "Backfill batch processing failed"
                        );
                        match e.peer_action {
                            Some(peer_action) => BatchProcessResult::FaultyFailure {
                                imported_blocks: 0,
                                peer_action,
                                error: e.message,
                            },
                            None => BatchProcessResult::NonFaultyFailure,
                        }
                    }
                }
            }
        };

        self.send_sync_message(SyncMessage::BatchProcessed { sync_type, result });
    }

    /// Helper function to process blocks batches which only consumes the chain and blocks to process.
    async fn process_blocks<'a>(
        &self,
        downloaded_blocks: impl Iterator<Item = &'a RpcBlock<T::EthSpec>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> (usize, Result<(), ChainSegmentFailed>) {
        let blocks: Vec<_> = downloaded_blocks.cloned().collect();
        match self
            .chain
            .process_chain_segment(blocks, notify_execution_layer)
            .await
        {
            ChainSegmentResult::Successful { imported_blocks } => {
                metrics::inc_counter(&metrics::BEACON_PROCESSOR_CHAIN_SEGMENT_SUCCESS_TOTAL);
                if !imported_blocks.is_empty() {
                    self.chain.recompute_head_at_current_slot().await;

                    for (block_root, block_slot) in &imported_blocks {
                        if self.chain.should_sample_slot(*block_slot) {
                            self.send_sync_message(SyncMessage::SampleBlock(
                                *block_root,
                                *block_slot,
                            ));
                        }
                    }
                }
                (imported_blocks.len(), Ok(()))
            }
            ChainSegmentResult::Failed {
                imported_blocks,
                error,
            } => {
                metrics::inc_counter(&metrics::BEACON_PROCESSOR_CHAIN_SEGMENT_FAILED_TOTAL);
                let r = self.handle_failed_chain_segment(error);
                if !imported_blocks.is_empty() {
                    self.chain.recompute_head_at_current_slot().await;
                }
                (imported_blocks.len(), r)
            }
        }
    }

    /// Helper function to process backfill block batches which only consumes the chain and blocks to process.
    fn process_backfill_blocks(
        &self,
        downloaded_blocks: Vec<RpcBlock<T::EthSpec>>,
    ) -> Result<usize, ChainSegmentFailed> {
        match self
            .chain
            .verify_and_import_historical_block_batch(downloaded_blocks)
        {
            Ok(imported_blocks) => {
                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_BACKFILL_CHAIN_SEGMENT_SUCCESS_TOTAL,
                );
                Ok(imported_blocks)
            }
            Err(e) => {
                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_BACKFILL_CHAIN_SEGMENT_FAILED_TOTAL,
                );
                let peer_action = match &e {
                    HistoricalBlockError::AvailabilityCheckError(e) => {
                        PeerGroupAction::from_availability_check_error(e)
                    }
                    // The peer is faulty if they send blocks with bad roots or invalid signatures
                    HistoricalBlockError::MismatchedBlockRoot { .. }
                    | HistoricalBlockError::InvalidSignature(_) => {
                        Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
                    }
                    // Blobs are served by the block_peer
                    HistoricalBlockError::InvalidBlobsSignature(_) => {
                        Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
                    }
                    HistoricalBlockError::InvalidDataColumnsSignature(indices) => Some(
                        PeerGroupAction::column_peers(indices, PeerAction::LowToleranceError),
                    ),
                    HistoricalBlockError::ValidatorPubkeyCacheTimeout
                    | HistoricalBlockError::IndexOutOfBounds
                    | HistoricalBlockError::StoreError(_)
                    | HistoricalBlockError::Unexpected(_) => {
                        // This is an internal error, do not penalize the peer.
                        None
                    } // Do not use a fallback match, handle all errors explicitly
                };

                if peer_action.is_some() {
                    // All errors that result in a peer penalty are "expected" external faults the
                    // node runner can't do anything about
                    debug!(?e, "Backfill sync processing error");
                } else {
                    // All others are some type of internal error worth surfacing?
                    warn!(?e, "Unexpected backfill sync processing error");
                }

                Err(ChainSegmentFailed {
                    // Render the full error in debug for full details
                    message: format!("{:?}", e),
                    peer_action,
                })
            }
        }
    }

    /// Helper function to handle a `BlockError` from `process_chain_segment`
    fn handle_failed_chain_segment(&self, error: BlockError) -> Result<(), ChainSegmentFailed> {
        let peer_action = match &error {
            BlockError::ParentUnknown { .. } => {
                // blocks should be sequential and all parents should exist
                // Peers are faulty if they send non-sequential blocks.
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            BlockError::FutureSlot {
                present_slot,
                block_slot,
            } => {
                if *present_slot + FUTURE_SLOT_TOLERANCE >= *block_slot {
                    // The block is too far in the future, drop it.
                    warn!(
                        msg = "block for future slot rejected, check your time",
                        %present_slot,
                        %block_slot,
                        FUTURE_SLOT_TOLERANCE,
                        "Block is ahead of our slot clock"
                    );
                }
                // Peers are faulty if they send blocks from the future.
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            // Block is invalid
            BlockError::StateRootMismatch { .. }
            | BlockError::BlockSlotLimitReached
            | BlockError::IncorrectBlockProposer { .. }
            | BlockError::UnknownValidator { .. }
            | BlockError::BlockIsNotLaterThanParent { .. }
            | BlockError::NonLinearParentRoots
            | BlockError::NonLinearSlots
            | BlockError::PerBlockProcessingError(_)
            | BlockError::InconsistentFork(_)
            | BlockError::InvalidSignature(_) => {
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            // Currently blobs are served by the block peer
            BlockError::InvalidBlobsSignature(_) => {
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            BlockError::InvalidDataColumnsSignature(indices) => Some(
                PeerGroupAction::column_peers(indices, PeerAction::LowToleranceError),
            ),
            BlockError::GenesisBlock
            | BlockError::WouldRevertFinalizedSlot { .. }
            | BlockError::DuplicateFullyImported(_)
            | BlockError::DuplicateImportStatusUnknown(..) => {
                // This can happen for many reasons. Head sync's can download multiples and parent
                // lookups can download blocks before range sync
                return Ok(());
            }
            // Not syncing to a chain that conflicts with the canonical or manual finalized checkpoint
            BlockError::NotFinalizedDescendant { .. } | BlockError::WeakSubjectivityConflict => {
                Some(PeerGroupAction::block_peer(PeerAction::Fatal))
            }
            BlockError::AvailabilityCheck(e) => PeerGroupAction::from_availability_check_error(e),
            BlockError::ExecutionPayloadError(e) => {
                if !e.penalize_peer() {
                    // These errors indicate an issue with the EL and not the `ChainSegment`.
                    // Pause the syncing while the EL recovers
                    None
                } else {
                    Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
                }
            }
            // We need to penalise harshly in case this represents an actual attack. In case
            // of a faulty EL it will usually require manual intervention to fix anyway, so
            // it's not too bad if we drop most of our peers.
            BlockError::ParentExecutionPayloadInvalid { parent_root } => {
                warn!(
                    ?parent_root,
                    advice = "check execution node for corruption then restart it and Lighthouse",
                    "Failed to sync chain built on invalid parent"
                );
                Some(PeerGroupAction::block_peer(PeerAction::LowToleranceError))
            }
            // Penalise peers for sending us banned blocks.
            BlockError::KnownInvalidExecutionPayload(block_root) => {
                warn!(?block_root, "Received block known to be invalid");
                Some(PeerGroupAction::block_peer(PeerAction::Fatal))
            }
            BlockError::Slashable => {
                Some(PeerGroupAction::block_peer(PeerAction::MidToleranceError))
            }
            // Do not penalize peers for internal errors.
            // BlobNotRequired is never constructed on this path
            // TODO(sync): Double check that all `BeaconChainError` variants are actually internal
            // errors in thie code path
            BlockError::BeaconChainError(_)
            | BlockError::InternalError(_)
            | BlockError::BlobNotRequired(_) => None,
            // Do not use a fallback match, handle all errors explicitly
        };

        if peer_action.is_some() {
            debug!(?error, "Range sync processing error");
        } else {
            warn!(?error, "Unexpected range sync processing error");
        }

        Err(ChainSegmentFailed {
            message: format!("{error:?}"),
            peer_action,
        })
    }
}
