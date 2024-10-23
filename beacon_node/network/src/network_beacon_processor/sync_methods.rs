use crate::metrics;
use crate::network_beacon_processor::NetworkBeaconProcessor;
use crate::sync::BatchProcessResult;
use crate::sync::{
    manager::{BlockProcessType, SyncMessage},
    ChainId,
};
use beacon_chain::block_verification_types::{AsBlock, RpcBlock};
use beacon_chain::data_availability_checker::AvailabilityCheckError;
use beacon_chain::data_availability_checker::MaybeAvailableBlock;
use beacon_chain::data_column_verification::verify_kzg_for_data_column_list;
use beacon_chain::ExecutionPayloadError;
use beacon_chain::{
    validator_monitor::get_slot_delay_ms, AvailabilityProcessingStatus, BeaconChainError,
    BeaconChainTypes, BlockError, ChainSegmentResult, HistoricalBlockError, NotifyExecutionLayer,
};
use beacon_processor::{
    work_reprocessing_queue::{QueuedRpcBlock, ReprocessQueueMessage},
    AsyncFn, BlockingFn, DuplicateCache,
};
use lighthouse_network::PeerAction;
use slog::{debug, error, info, warn};
use std::sync::Arc;
use std::time::Duration;
use store::KzgCommitment;
use tokio::sync::mpsc;
use types::beacon_block_body::format_kzg_commitments;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{BlockImportSource, DataColumnSidecar, DataColumnSidecarList, Epoch, Hash256};

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

#[derive(Debug, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Internal Errors (not caused by peers).
    ///
    /// An internal no-retry error is permanent and block processing should not be
    /// re-attempted.
    Internal { retry: bool },
    /// Errors caused by faulty / malicious peers.
    ///
    /// No retry errors are deterministic against the block's root. Re-downloading data
    /// key-ed by block root MUST result in the same no-retry error (i.e. invalid parent,
    /// invalid state root, etc).
    ///
    /// The error also indicates which block component index is malicious if applicable.
    Malicious { retry: bool, index: usize },
}

impl ErrorCategory {
    // Helper functions for readibility on large match statements
    pub fn internal_no_retry() -> Self {
        Self::Internal { retry: false }
    }
    pub fn internal_retry() -> Self {
        Self::Internal { retry: true }
    }
    pub fn malicious_no_retry() -> Self {
        Self::Malicious {
            retry: false,
            index: 0,
        }
    }
    pub fn malicious_retry() -> Self {
        Self::Malicious {
            retry: true,
            index: 0,
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
                self.log,
                "Gossip block is being processed";
                "action" => "sending rpc block to reprocessing queue",
                "block_root" => %block_root,
                "process_type" => ?process_type,
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
                error!(self.log, "Failed to inform block import"; "source" => "rpc", "block_root" => %block_root)
            };
            return;
        };

        let slot = block.slot();
        let block_has_data = block.as_block().num_expected_blobs() > 0;
        let parent_root = block.message().parent_root();
        let commitments_formatted = block.as_block().commitments_formatted();

        debug!(
            self.log,
            "Processing RPC block";
            "block_root" => ?block_root,
            "proposer" => block.message().proposer_index(),
            "slot" => block.slot(),
            "commitments" => commitments_formatted,
            "process_type" => ?process_type,
        );

        let result = self
            .chain
            .process_block_with_early_caching(
                block_root,
                block,
                BlockImportSource::Lookup,
                NotifyExecutionLayer::Yes,
            )
            .await;

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_RPC_BLOCK_IMPORTED_TOTAL);

        // RPC block imported, regardless of process type
        if let &Ok(AvailabilityProcessingStatus::Imported(hash)) = &result {
            info!(self.log, "New RPC block received"; "slot" => slot, "hash" => %hash);

            // Trigger processing for work referencing this block.
            let reprocess_msg = ReprocessQueueMessage::BlockImported {
                block_root: hash,
                parent_root,
            };
            if reprocess_tx.try_send(reprocess_msg).is_err() {
                error!(self.log, "Failed to inform block import"; "source" => "rpc", "block_root" => %hash)
            };
            self.chain.block_times_cache.write().set_time_observed(
                hash,
                slot,
                seen_timestamp,
                None,
                None,
            );

            self.chain.recompute_head_at_current_slot().await;
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
            self.log,
            "RPC blobs received";
            "indices" => ?indices,
            "block_root" => %block_root,
            "slot" => %slot,
            "commitments" => commitments,
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

        match &result {
            Ok(AvailabilityProcessingStatus::Imported(hash)) => {
                debug!(
                    self.log,
                    "Block components retrieved";
                    "result" => "imported block and blobs",
                    "slot" => %slot,
                    "block_hash" => %hash,
                );
                self.chain.recompute_head_at_current_slot().await;
            }
            Ok(AvailabilityProcessingStatus::MissingComponents(_, _)) => {
                debug!(
                    self.log,
                    "Missing components over rpc";
                    "block_hash" => %block_root,
                    "slot" => %slot,
                );
            }
            Err(BlockError::DuplicateFullyImported(_)) => {
                debug!(
                    self.log,
                    "Blobs have already been imported";
                    "block_hash" => %block_root,
                    "slot" => %slot,
                );
            }
            Err(e) => {
                warn!(
                    self.log,
                    "Error when importing rpc blobs";
                    "error" => ?e,
                    "block_hash" => %block_root,
                    "slot" => %slot,
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
        _seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) {
        let mut result = self
            .chain
            .process_rpc_custody_columns(custody_columns)
            .await;

        match &result {
            Ok(availability) => match availability {
                AvailabilityProcessingStatus::Imported(hash) => {
                    debug!(
                        self.log,
                        "Block components retrieved";
                        "result" => "imported block and custody columns",
                        "block_hash" => %hash,
                    );
                    self.chain.recompute_head_at_current_slot().await;
                }
                AvailabilityProcessingStatus::MissingComponents(_, _) => {
                    debug!(
                        self.log,
                        "Missing components over rpc";
                        "block_hash" => %block_root,
                    );
                    // Attempt reconstruction here before notifying sync, to avoid sending out more requests
                    // that we may no longer need.
                    if let Some(availability) =
                        self.attempt_data_column_reconstruction(block_root).await
                    {
                        result = Ok(availability)
                    }
                }
            },
            Err(BlockError::DuplicateFullyImported(_)) => {
                debug!(
                    self.log,
                    "Custody columns have already been imported";
                    "block_hash" => %block_root,
                );
            }
            Err(e) => {
                warn!(
                    self.log,
                    "Error when importing rpc custody columns";
                    "error" => ?e,
                    "block_hash" => %block_root,
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
                        debug!(self.log, "Batch processed";
                            "batch_epoch" => epoch,
                            "first_block_slot" => start_slot,
                            "chain" => chain_id,
                            "last_block_slot" => end_slot,
                            "processed_blocks" => sent_blocks,
                            "service"=> "sync");
                        BatchProcessResult::Success {
                            sent_blocks,
                            imported_blocks,
                        }
                    }
                    (imported_blocks, Err(e)) => {
                        debug!(self.log, "Batch processing failed";
                            "batch_epoch" => epoch,
                            "first_block_slot" => start_slot,
                            "chain" => chain_id,
                            "last_block_slot" => end_slot,
                            "imported_blocks" => imported_blocks,
                            "error" => %e.message,
                            "service" => "sync");
                        match e.peer_action {
                            Some(penalty) => BatchProcessResult::FaultyFailure {
                                imported_blocks,
                                penalty,
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
                    (imported_blocks, Ok(_)) => {
                        debug!(self.log, "Backfill batch processed";
                            "batch_epoch" => epoch,
                            "first_block_slot" => start_slot,
                            "last_block_slot" => end_slot,
                            "processed_blocks" => sent_blocks,
                            "processed_blobs" => n_blobs,
                            "processed_data_columns" => n_data_columns,
                            "service"=> "sync");
                        BatchProcessResult::Success {
                            sent_blocks,
                            imported_blocks,
                        }
                    }
                    (_, Err(e)) => {
                        debug!(self.log, "Backfill batch processing failed";
                            "batch_epoch" => epoch,
                            "first_block_slot" => start_slot,
                            "last_block_slot" => end_slot,
                            "processed_blobs" => n_blobs,
                            "error" => %e.message,
                            "service" => "sync");
                        match e.peer_action {
                            Some(penalty) => BatchProcessResult::FaultyFailure {
                                imported_blocks: 0,
                                penalty,
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
                    )
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
            Err(error) => {
                metrics::inc_counter(
                    &metrics::BEACON_PROCESSOR_BACKFILL_CHAIN_SEGMENT_FAILED_TOTAL,
                );
                let err = match error {
                    // Handle the historical block errors specifically
                    BeaconChainError::HistoricalBlockError(e) => match e {
                        HistoricalBlockError::MismatchedBlockRoot {
                            block_root,
                            expected_block_root,
                        } => {
                            debug!(
                                self.log,
                                "Backfill batch processing error";
                                "error" => "mismatched_block_root",
                                "block_root" => ?block_root,
                                "expected_root" => ?expected_block_root
                            );

                            ChainSegmentFailed {
                                message: String::from("mismatched_block_root"),
                                // The peer is faulty if they send blocks with bad roots.
                                peer_action: Some(PeerAction::LowToleranceError),
                            }
                        }
                        HistoricalBlockError::InvalidSignature
                        | HistoricalBlockError::SignatureSet(_) => {
                            warn!(
                                self.log,
                                "Backfill batch processing error";
                                "error" => ?e
                            );

                            ChainSegmentFailed {
                                message: "invalid_signature".into(),
                                // The peer is faulty if they bad signatures.
                                peer_action: Some(PeerAction::LowToleranceError),
                            }
                        }
                        HistoricalBlockError::ValidatorPubkeyCacheTimeout => {
                            warn!(
                                self.log,
                                "Backfill batch processing error";
                                "error" => "pubkey_cache_timeout"
                            );

                            ChainSegmentFailed {
                                message: "pubkey_cache_timeout".into(),
                                // This is an internal error, do not penalize the peer.
                                peer_action: None,
                            }
                        }
                        HistoricalBlockError::NoAnchorInfo => {
                            warn!(self.log, "Backfill not required");

                            ChainSegmentFailed {
                                message: String::from("no_anchor_info"),
                                // There is no need to do a historical sync, this is not a fault of
                                // the peer.
                                peer_action: None,
                            }
                        }
                        HistoricalBlockError::IndexOutOfBounds => {
                            error!(
                                self.log,
                                "Backfill batch OOB error";
                                "error" => ?e,
                            );
                            ChainSegmentFailed {
                                message: String::from("logic_error"),
                                // This should never occur, don't penalize the peer.
                                peer_action: None,
                            }
                        }
                        HistoricalBlockError::BlockOutOfRange { .. } => {
                            error!(
                                self.log,
                                "Backfill batch error";
                                "error" => ?e,
                            );
                            ChainSegmentFailed {
                                message: String::from("unexpected_error"),
                                // This should never occur, don't penalize the peer.
                                peer_action: None,
                            }
                        }
                    },
                    other => {
                        warn!(self.log, "Backfill batch processing error"; "error" => ?other);
                        ChainSegmentFailed {
                            message: format!("{:?}", other),
                            // This is an internal error, don't penalize the peer.
                            peer_action: None,
                        }
                    }
                };
                (0, Err(err))
            }
        }
    }

    /// Helper function to handle a `BlockError` from `process_chain_segment`
    fn handle_failed_chain_segment(&self, error: BlockError) -> Result<(), ChainSegmentFailed> {
        let result = match &error {
            // blocks should be sequential and all parents should exist
            BlockError::ParentUnknown { .. } => Err(ErrorCategory::malicious_retry()),
            // A peer may craft a block that is at a future slot. It's possible that
            // eventually the slot will no longer be in the future. However, since it's
            // malicious action to serve an RPC with a future slot we will not retry.
            BlockError::FutureSlot { .. } => Err(ErrorCategory::malicious_no_retry()),

            // Okay to reprocess blocks that are finalized.
            BlockError::GenesisBlock | BlockError::WouldRevertFinalizedSlot { .. } => Ok(()),

            // Since we request blocks by slot we should retry all conditions of invalid block.
            BlockError::StateRootMismatch { .. }
            | BlockError::NotFinalizedDescendant { .. }
            | BlockError::BlockSlotLimitReached
            | BlockError::IncorrectBlockProposer { .. }
            | BlockError::UnknownValidator { .. }
            | BlockError::BlockIsNotLaterThanParent { .. }
            | BlockError::PerBlockProcessingError(_)
            | BlockError::InconsistentFork(_)
            | BlockError::WeakSubjectivityConflict
            | BlockError::ProposalSignatureInvalid
            | BlockError::InvalidSignature
            | BlockError::NonLinearParentRoots
            | BlockError::NonLinearSlots => Err(ErrorCategory::malicious_retry()),

            // This can happen for many reasons. Head sync's can download multiples and parent
            // lookups can download blocks before range sync
            BlockError::DuplicateFullyImported { .. } => Ok(()),
            BlockError::DuplicateImportStatusUnknown { .. } => {
                // This is unreachable because RPC blocks do not undergo gossip verification, and
                // this error can *only* come from gossip verification.
                Err(ErrorCategory::internal_no_retry())
            }
            // TODO: review `ExecutionPayloadError` variants
            BlockError::ExecutionPayloadError(e) => Err(match e {
                // The peer has nothing to do with this error, do not penalize them.
                ExecutionPayloadError::NoExecutionConnection => ErrorCategory::internal_no_retry(),
                // The peer has nothing to do with this error, do not penalize them.
                ExecutionPayloadError::RequestFailed(_) => ErrorCategory::internal_retry(),
                // Execution payload is invalid
                ExecutionPayloadError::RejectedByExecutionEngine { .. }
                | ExecutionPayloadError::InvalidPayloadTimestamp { .. }
                | ExecutionPayloadError::InvalidTerminalPoWBlock { .. }
                | ExecutionPayloadError::InvalidActivationEpoch { .. }
                | ExecutionPayloadError::InvalidTerminalBlockHash { .. } => {
                    ErrorCategory::malicious_retry()
                }
                // Do not penalize the peer since it's not their fault that *we're* optimistic.
                ExecutionPayloadError::UnverifiedNonOptimisticCandidate => {
                    ErrorCategory::internal_retry()
                }
            }),
            // Should retry? Probably
            BlockError::ParentExecutionPayloadInvalid { .. } => {
                Err(ErrorCategory::malicious_retry())
            }
            // TODO: Review AvailabilityCheckError variants
            BlockError::AvailabilityCheck(e) => Err(match e {
                AvailabilityCheckError::SszTypes(_)
                | AvailabilityCheckError::StoreError(_)
                | AvailabilityCheckError::Unexpected
                | AvailabilityCheckError::ParentStateMissing(_)
                | AvailabilityCheckError::BlockReplayError(_)
                | AvailabilityCheckError::RebuildingStateCaches(_)
                | AvailabilityCheckError::SlotClockError => ErrorCategory::internal_retry(),
                AvailabilityCheckError::InvalidColumn(index, _) => ErrorCategory::Malicious {
                    retry: true,
                    index: *index as usize,
                },
                AvailabilityCheckError::InvalidBlobs { .. }
                | AvailabilityCheckError::MissingBlobs
                | AvailabilityCheckError::MissingCustodyColumns
                | AvailabilityCheckError::DecodeError(_)
                | AvailabilityCheckError::ReconstructColumnsError { .. }
                | AvailabilityCheckError::BlobIndexInvalid(_)
                | AvailabilityCheckError::DataColumnIndexInvalid(_)
                | AvailabilityCheckError::KzgCommitmentMismatch { .. } => {
                    ErrorCategory::malicious_retry()
                } // Do not use a fallback match, handle all errors explicitly
            }),
            // The proposer making a slashable block is not the peer's fault nor ours. Mark
            // as internal (don't penalize peer), and retry: the serving peer could send the wrong
            // block at this slot, which happens to not be slashable.
            BlockError::Slashable => Err(ErrorCategory::internal_retry()),
            // TODO: BeaconChainError should be retried?
            BlockError::BeaconChainError(_) | BlockError::InternalError(_) => {
                Err(ErrorCategory::internal_no_retry())
            }
            // unreachable, this error is only part of gossip
            BlockError::BlobNotRequired(_) => Err(ErrorCategory::malicious_retry()),
        };
        // Do not use a fallback match, handle all errors explicitly

        // Pass retry and malicious signals to range sync to do retry and score properly
        result.map_err(|err| ChainSegmentFailed {
            message: format!("{:?}", error),
            // This is an internal error, don't penalize the peer.
            peer_action: if matches!(err, ErrorCategory::Malicious { .. }) {
                Some(PeerAction::LowToleranceError)
            } else {
                None
            },
        })
    }
}
