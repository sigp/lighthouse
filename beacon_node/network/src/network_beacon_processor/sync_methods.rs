use crate::metrics::{self, register_process_result_metrics};
use crate::network_beacon_processor::{FUTURE_SLOT_TOLERANCE, NetworkBeaconProcessor};
use crate::sync::BatchProcessResult;
use crate::sync::manager::CustodyBatchProcessResult;
use crate::sync::{
    ChainId,
    manager::{BlockProcessType, SyncMessage},
};
use beacon_chain::block_verification_types::{AsBlock, RpcBlock};
use beacon_chain::data_availability_checker::AvailabilityCheckError;
use beacon_chain::data_availability_checker::MaybeAvailableBlock;
use beacon_chain::historical_data_columns::HistoricalDataColumnError;
use beacon_chain::{
    AvailabilityProcessingStatus, BeaconChainTypes, BlockError, ChainSegmentResult,
    HistoricalBlockError, NotifyExecutionLayer, validator_monitor::get_slot_delay_ms,
};
use beacon_processor::{
    AsyncFn, BlockingFn, DuplicateCache,
    work_reprocessing_queue::{QueuedRpcBlock, ReprocessQueueMessage},
};
use beacon_processor::{Work, WorkEvent};
use lighthouse_network::PeerAction;
use lighthouse_network::service::api_types::CustodyBackfillBatchId;
use lighthouse_tracing::{
    SPAN_CUSTODY_BACKFILL_SYNC_IMPORT_COLUMNS, SPAN_PROCESS_CHAIN_SEGMENT,
    SPAN_PROCESS_CHAIN_SEGMENT_BACKFILL, SPAN_PROCESS_RPC_BLOBS, SPAN_PROCESS_RPC_BLOCK,
    SPAN_PROCESS_RPC_CUSTODY_COLUMNS,
};
use logging::crit;
use std::sync::Arc;
use std::time::Duration;
use store::KzgCommitment;
use tracing::{debug, debug_span, error, info, instrument, warn};
use types::beacon_block_body::format_kzg_commitments;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{BlockImportSource, DataColumnSidecarList, Epoch, Hash256};

/// Id associated to a batch processing request, either a sync batch or a parent lookup.
#[derive(Clone, Debug, PartialEq)]
pub enum ChainSegmentProcessId {
    /// Processing Id of a range syncing batch.
    RangeBatchId(ChainId, Epoch),
    /// Processing ID for a backfill syncing batch.
    BackSyncBatchId(Epoch),
}

/// Returned when a chain segment import fails.
struct ChainSegmentFailed {
    /// To be displayed in logs.
    message: String,
    /// Used to penalize peers.
    peer_action: Option<PeerAction>,
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
            let duplicate_cache = self.duplicate_cache.clone();
            self.process_rpc_block(
                block_root,
                block,
                seen_timestamp,
                process_type,
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
    #[instrument(
        name = SPAN_PROCESS_RPC_BLOCK,
        parent = None,
        level = "debug",
        skip_all,
        fields(?block_root),
    )]
    pub async fn process_rpc_block(
        self: Arc<NetworkBeaconProcessor<T>>,
        block_root: Hash256,
        block: RpcBlock<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
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

            if self
                .beacon_processor_send
                .try_send(WorkEvent {
                    drop_during_sync: false,
                    work: Work::Reprocess(reprocess_msg),
                })
                .is_err()
            {
                error!(source = "rpc", %block_root,"Failed to inform block import")
            };
            return;
        };

        let slot = block.slot();
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
            .process_block(
                block_root,
                block,
                NotifyExecutionLayer::Yes,
                BlockImportSource::Lookup,
                || Ok(()),
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
                if self
                    .beacon_processor_send
                    .try_send(WorkEvent {
                        drop_during_sync: false,
                        work: Work::Reprocess(reprocess_msg),
                    })
                    .is_err()
                {
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
    #[instrument(
        name = SPAN_PROCESS_RPC_BLOBS,
        parent = None,
        level = "debug",
        skip_all,
        fields(?block_root),
    )]
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

        if let Ok(current_slot) = self.chain.slot()
            && current_slot == slot
        {
            // Note: this metric is useful to gauge how long it takes to receive blobs requested
            // over rpc. Since we always send the request for block components at `slot_clock.single_lookup_delay()`
            // we can use that as a baseline to measure against.
            let delay = get_slot_delay_ms(seen_timestamp, slot, &self.chain.slot_clock);

            metrics::observe_duration(&metrics::BEACON_BLOB_RPC_SLOT_START_DELAY_TIME, delay);
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
            // Errors are handled and logged in `block_lookups`
            Err(_) => {}
        }

        // Sync handles these results
        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type,
            result: result.into(),
        });
    }

    #[instrument(
        name = SPAN_PROCESS_RPC_CUSTODY_COLUMNS,
        parent = None,
        level = "debug",
        skip_all,
        fields(?block_root),
    )]
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

        if let Ok(current_slot) = self.chain.slot()
            && current_slot == slot
        {
            let delay = get_slot_delay_ms(seen_timestamp, slot, &self.chain.slot_clock);
            metrics::observe_duration(&metrics::BEACON_BLOB_RPC_SLOT_START_DELAY_TIME, delay);
        }

        let mut indices = custody_columns.iter().map(|d| d.index).collect::<Vec<_>>();
        indices.sort_unstable();
        debug!(
            ?indices,
            %block_root,
            %slot,
            "RPC custody data columns received"
        );

        let result = self
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
                }
            },
            Err(BlockError::DuplicateFullyImported(_)) => {
                debug!(
                    block_hash = %block_root,
                    "Custody columns have already been imported"
                );
            }
            // Errors are handled and logged in `block_lookups`
            Err(_) => {}
        }

        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type,
            result: result.into(),
        });
    }

    pub fn process_historic_data_columns(
        &self,
        batch_id: CustodyBackfillBatchId,
        downloaded_columns: DataColumnSidecarList<T::EthSpec>,
        expected_cgc: u64,
    ) {
        let _guard = debug_span!(
            SPAN_CUSTODY_BACKFILL_SYNC_IMPORT_COLUMNS,
            epoch = %batch_id.epoch,
            columns_received_count = downloaded_columns.len()
        )
        .entered();

        let sent_columns = downloaded_columns.len();
        let result = match self.chain.import_historical_data_column_batch(
            batch_id.epoch,
            downloaded_columns,
            expected_cgc,
        ) {
            Ok(imported_columns) => {
                metrics::inc_counter_by(
                    &metrics::BEACON_PROCESSOR_CUSTODY_BACKFILL_COLUMN_IMPORT_SUCCESS_TOTAL,
                    imported_columns as u64,
                );
                CustodyBatchProcessResult::Success {
                    sent_columns,
                    imported_columns,
                }
            }
            Err(e) => {
                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_CUSTODY_BACKFILL_BATCH_FAILED_TOTAL,
                );
                let peer_action: Option<PeerAction> = match &e {
                    HistoricalDataColumnError::NoBlockFound {
                        data_column_block_root,
                        expected_block_root,
                    } => {
                        debug!(
                            error = "no_block_found",
                            ?data_column_block_root,
                            ?expected_block_root,
                            "Custody backfill batch processing error"
                        );
                        // The peer is faulty if they send blocks with bad roots.
                        Some(PeerAction::LowToleranceError)
                    }
                    HistoricalDataColumnError::MissingDataColumns { .. } => {
                        warn!(
                            error = ?e,
                            "Custody backfill batch processing error",
                        );
                        // The peer is faulty if they don't return data columns
                        // that they advertised as available.
                        Some(PeerAction::LowToleranceError)
                    }
                    HistoricalDataColumnError::InvalidKzg => {
                        warn!(
                            error = ?e,
                            "Custody backfill batch processing error",
                        );
                        // The peer is faulty if they don't return data columns
                        // with valid kzg commitments.
                        Some(PeerAction::LowToleranceError)
                    }
                    HistoricalDataColumnError::BeaconChainError(e) => {
                        match &**e {
                            beacon_chain::BeaconChainError::FailedColumnCustodyInfoUpdate => {}
                            _ => {
                                warn!(
                                    error = ?e,
                                    "Custody backfill batch processing error",
                                );
                            }
                        }

                        // This is an interal error, don't penalize the peer
                        None
                    }
                    HistoricalDataColumnError::IndexOutOfBounds => {
                        error!(
                            error = ?e,
                            "Custody backfill batch out of bounds error"
                        );
                        // This should never occur, don't penalize the peer.
                        None
                    }
                    HistoricalDataColumnError::StoreError(e) => {
                        warn!(error = ?e, "Custody backfill batch processing error");
                        // This is an internal error, don't penalize the peer.
                        None
                    }
                };
                CustodyBatchProcessResult::Error { peer_action }
            }
        };
        self.send_sync_message(SyncMessage::CustodyBatchProcessed { result, batch_id });
    }

    /// Attempt to import the chain segment (`blocks`) to the beacon chain, informing the sync
    /// thread if more blocks are needed to process it.
    #[instrument(
        name = SPAN_PROCESS_CHAIN_SEGMENT,
        parent = None,
        level = "debug",
        skip_all,
        fields(process_id = ?process_id, downloaded_blocks = downloaded_blocks.len())
    )]
    pub async fn process_chain_segment(
        &self,
        process_id: ChainSegmentProcessId,
        downloaded_blocks: Vec<RpcBlock<T::EthSpec>>,
    ) {
        let ChainSegmentProcessId::RangeBatchId(chain_id, epoch) = process_id else {
            // This is a request from range sync, this should _never_ happen
            crit!(
                error = "process_chain_segment called on a variant other than RangeBatchId",
                "Please notify the devs"
            );
            return;
        };

        let start_slot = downloaded_blocks.first().map(|b| b.slot().as_u64());
        let end_slot = downloaded_blocks.last().map(|b| b.slot().as_u64());
        let sent_blocks = downloaded_blocks.len();
        let notify_execution_layer = if self
            .network_globals
            .sync_state
            .read()
            .is_syncing_finalized()
        {
            NotifyExecutionLayer::No
        } else {
            NotifyExecutionLayer::Yes
        };

        let result = match self
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
                        penalty,
                    },
                    None => BatchProcessResult::NonFaultyFailure,
                }
            }
        };

        self.send_sync_message(SyncMessage::BatchProcessed {
            sync_type: process_id,
            result,
        });
    }

    /// Attempt to import the chain segment (`blocks`) to the beacon chain, informing the sync
    /// thread if more blocks are needed to process it.
    #[instrument(
        name = SPAN_PROCESS_CHAIN_SEGMENT_BACKFILL,
        parent = None,
        level = "debug",
        skip_all,
        fields(downloaded_blocks = downloaded_blocks.len())
    )]
    pub fn process_chain_segment_backfill(
        &self,
        process_id: ChainSegmentProcessId,
        downloaded_blocks: Vec<RpcBlock<T::EthSpec>>,
    ) {
        let ChainSegmentProcessId::BackSyncBatchId(epoch) = process_id else {
            // this a request from RangeSync, this should _never_ happen
            crit!(
                error =
                    "process_chain_segment_backfill called on a variant other than BackSyncBatchId",
                "Please notify the devs"
            );
            return;
        };

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

        let result = match self.process_backfill_blocks(downloaded_blocks) {
            (imported_blocks, Ok(_)) => {
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
            (_, Err(e)) => {
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
                    Some(penalty) => BatchProcessResult::FaultyFailure {
                        imported_blocks: 0,
                        penalty,
                    },
                    None => BatchProcessResult::NonFaultyFailure,
                }
            }
        };

        self.send_sync_message(SyncMessage::BatchProcessed {
            sync_type: process_id,
            result,
        });
    }

    /// Helper function to process blocks batches which only consumes the chain and blocks to process.
    #[instrument(skip_all)]
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
    #[instrument(skip_all)]
    fn process_backfill_blocks(
        &self,
        downloaded_blocks: Vec<RpcBlock<T::EthSpec>>,
    ) -> (usize, Result<(), ChainSegmentFailed>) {
        let total_blocks = downloaded_blocks.len();
        let available_blocks = match self
            .chain
            .data_availability_checker
            .verify_kzg_for_rpc_blocks(downloaded_blocks)
        {
            Ok(blocks) => blocks
                .into_iter()
                .filter_map(|maybe_available| match maybe_available {
                    MaybeAvailableBlock::Available(block) => Some(block),
                    MaybeAvailableBlock::AvailabilityPending { .. } => None,
                })
                .collect::<Vec<_>>(),
            Err(e) => match e {
                AvailabilityCheckError::StoreError(_) => {
                    return (
                        0,
                        Err(ChainSegmentFailed {
                            peer_action: None,
                            message: "Failed to check block availability".into(),
                        }),
                    );
                }
                e => {
                    return (
                        0,
                        Err(ChainSegmentFailed {
                            peer_action: Some(PeerAction::LowToleranceError),
                            message: format!("Failed to check block availability : {:?}", e),
                        }),
                    );
                }
            },
        };

        if available_blocks.len() != total_blocks {
            return (
                0,
                Err(ChainSegmentFailed {
                    peer_action: Some(PeerAction::LowToleranceError),
                    message: format!(
                        "{} out of {} blocks were unavailable",
                        (total_blocks - available_blocks.len()),
                        total_blocks
                    ),
                }),
            );
        }

        match self.chain.import_historical_block_batch(available_blocks) {
            Ok(imported_blocks) => {
                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_BACKFILL_CHAIN_SEGMENT_SUCCESS_TOTAL,
                );
                (imported_blocks, Ok(()))
            }
            Err(e) => {
                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_BACKFILL_CHAIN_SEGMENT_FAILED_TOTAL,
                );
                let peer_action = match &e {
                    HistoricalBlockError::MismatchedBlockRoot {
                        block_root,
                        expected_block_root,
                    } => {
                        debug!(
                            error = "mismatched_block_root",
                            ?block_root,
                            expected_root = ?expected_block_root,
                            "Backfill batch processing error"
                        );
                        // The peer is faulty if they send blocks with bad roots.
                        Some(PeerAction::LowToleranceError)
                    }
                    HistoricalBlockError::InvalidSignature
                    | HistoricalBlockError::SignatureSet(_) => {
                        warn!(
                            error = ?e,
                            "Backfill batch processing error"
                        );
                        // The peer is faulty if they bad signatures.
                        Some(PeerAction::LowToleranceError)
                    }
                    HistoricalBlockError::MissingOldestBlockRoot { slot } => {
                        warn!(
                            %slot,
                            error = "missing_oldest_block_root",
                            "Backfill batch processing error"
                        );
                        // This is an internal error, do not penalize the peer.
                        None
                    }

                    HistoricalBlockError::ValidatorPubkeyCacheTimeout => {
                        warn!(
                            error = "pubkey_cache_timeout",
                            "Backfill batch processing error"
                        );
                        // This is an internal error, do not penalize the peer.
                        None
                    }
                    HistoricalBlockError::IndexOutOfBounds => {
                        error!(
                            error = ?e,
                            "Backfill batch OOB error"
                        );
                        // This should never occur, don't penalize the peer.
                        None
                    }
                    HistoricalBlockError::StoreError(e) => {
                        warn!(error = ?e, "Backfill batch processing error");
                        // This is an internal error, don't penalize the peer.
                        None
                    } //
                      // Do not use a fallback match, handle all errors explicitly
                };
                let err_str: &'static str = e.into();
                (
                    0,
                    Err(ChainSegmentFailed {
                        message: format!("{:?}", err_str),
                        // This is an internal error, don't penalize the peer.
                        peer_action,
                    }),
                )
            }
        }
    }

    /// Helper function to handle a `BlockError` from `process_chain_segment`
    fn handle_failed_chain_segment(&self, error: BlockError) -> Result<(), ChainSegmentFailed> {
        match error {
            BlockError::ParentUnknown { parent_root, .. } => {
                // blocks should be sequential and all parents should exist
                Err(ChainSegmentFailed {
                    message: format!("Block has an unknown parent: {}", parent_root),
                    // Peers are faulty if they send non-sequential blocks.
                    peer_action: Some(PeerAction::LowToleranceError),
                })
            }
            BlockError::DuplicateFullyImported(_)
            | BlockError::DuplicateImportStatusUnknown(..) => {
                // This can happen for many reasons. Head sync's can download multiples and parent
                // lookups can download blocks before range sync
                Ok(())
            }
            BlockError::FutureSlot {
                present_slot,
                block_slot,
            } => {
                if present_slot + FUTURE_SLOT_TOLERANCE >= block_slot {
                    // The block is too far in the future, drop it.
                    warn!(
                        msg = "block for future slot rejected, check your time",
                        %present_slot,
                        %block_slot,
                        FUTURE_SLOT_TOLERANCE,
                        "Block is ahead of our slot clock"
                    );
                } else {
                    // The block is in the future, but not too far.
                    debug!(
                        %present_slot,
                        %block_slot,
                        FUTURE_SLOT_TOLERANCE,
                        "Block is slightly ahead of our slot clock. Ignoring."
                    );
                }

                Err(ChainSegmentFailed {
                    message: format!(
                        "Block with slot {} is higher than the current slot {}",
                        block_slot, present_slot
                    ),
                    // Peers are faulty if they send blocks from the future.
                    peer_action: Some(PeerAction::LowToleranceError),
                })
            }
            BlockError::WouldRevertFinalizedSlot { .. } => {
                debug!("Finalized or earlier block processed");
                Ok(())
            }
            BlockError::NotFinalizedDescendant { block_parent_root } => {
                debug!(
                    "Not syncing to a chain that conflicts with the canonical or manual finalized checkpoint"
                );
                Err(ChainSegmentFailed {
                    message: format!(
                        "Block with parent_root {} conflicts with our checkpoint state",
                        block_parent_root
                    ),
                    peer_action: Some(PeerAction::Fatal),
                })
            }
            BlockError::GenesisBlock => {
                debug!("Genesis block was processed");
                Ok(())
            }
            BlockError::BeaconChainError(e) => {
                warn!(
                    msg = "unexpected condition in processing block.",
                    outcome = ?e,
                    "BlockProcessingFailure"
                );

                Err(ChainSegmentFailed {
                    message: format!("Internal error whilst processing block: {:?}", e),
                    // Do not penalize peers for internal errors.
                    peer_action: None,
                })
            }
            ref err @ BlockError::ExecutionPayloadError(ref epe) => {
                if !epe.penalize_peer() {
                    // These errors indicate an issue with the EL and not the `ChainSegment`.
                    // Pause the syncing while the EL recovers
                    debug!(
                        outcome = "pausing sync",
                        ?err,
                        "Execution layer verification failed"
                    );
                    Err(ChainSegmentFailed {
                        message: format!("Execution layer offline. Reason: {:?}", err),
                        // Do not penalize peers for internal errors.
                        peer_action: None,
                    })
                } else {
                    debug!(
                        error = ?err,
                        "Invalid execution payload"
                    );
                    Err(ChainSegmentFailed {
                        message: format!(
                            "Peer sent a block containing invalid execution payload. Reason: {:?}",
                            err
                        ),
                        peer_action: Some(PeerAction::LowToleranceError),
                    })
                }
            }
            ref err @ BlockError::ParentExecutionPayloadInvalid { ref parent_root } => {
                warn!(
                    ?parent_root,
                    advice = "check execution node for corruption then restart it and Lighthouse",
                    "Failed to sync chain built on invalid parent"
                );
                Err(ChainSegmentFailed {
                    message: format!("Peer sent invalid block. Reason: {err:?}"),
                    // We need to penalise harshly in case this represents an actual attack. In case
                    // of a faulty EL it will usually require manual intervention to fix anyway, so
                    // it's not too bad if we drop most of our peers.
                    peer_action: Some(PeerAction::LowToleranceError),
                })
            }
            // Penalise peers for sending us banned blocks.
            BlockError::KnownInvalidExecutionPayload(block_root) => {
                warn!(?block_root, "Received block known to be invalid",);
                Err(ChainSegmentFailed {
                    message: format!("Banned block: {block_root:?}"),
                    peer_action: Some(PeerAction::Fatal),
                })
            }
            other => {
                debug!(
                    msg = "peer sent invalid block",
                    outcome = %other,
                    "Invalid block received"
                );

                Err(ChainSegmentFailed {
                    message: format!("Peer sent invalid block. Reason: {:?}", other),
                    // Do not penalize peers for internal errors.
                    peer_action: None,
                })
            }
        }
    }
}
