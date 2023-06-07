use std::time::Duration;

use super::{super::work_reprocessing_queue::ReprocessQueueMessage, Worker};
use crate::beacon_processor::work_reprocessing_queue::QueuedRpcBlock;
use crate::beacon_processor::worker::FUTURE_SLOT_TOLERANCE;
use crate::beacon_processor::DuplicateCache;
use crate::metrics;
use crate::sync::manager::{BlockProcessType, ResponseType, SyncMessage};
use crate::sync::{BatchProcessResult, ChainId};
use beacon_chain::blob_verification::BlockWrapper;
use beacon_chain::blob_verification::{AsBlock, MaybeAvailableBlock};
use beacon_chain::data_availability_checker::AvailabilityCheckError;
use beacon_chain::{
    observed_block_producers::Error as ObserveError, validator_monitor::get_block_delay_ms,
    BeaconChainError, BeaconChainTypes, BlockError, ChainSegmentResult, HistoricalBlockError,
    NotifyExecutionLayer,
};
use beacon_chain::{AvailabilityProcessingStatus, CountUnrealized};
use lighthouse_network::PeerAction;
use slog::{debug, error, info, warn};
use slot_clock::SlotClock;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use types::blob_sidecar::FixedBlobSidecarList;
use types::{Epoch, Hash256, SignedBeaconBlock};

/// Id associated to a batch processing request, either a sync batch or a parent lookup.
#[derive(Clone, Debug, PartialEq)]
pub enum ChainSegmentProcessId {
    /// Processing Id of a range syncing batch.
    RangeBatchId(ChainId, Epoch, CountUnrealized),
    /// Processing ID for a backfill syncing batch.
    BackSyncBatchId(Epoch),
    /// Processing Id of the parent lookup of a block.
    ParentLookup(Hash256),
}

/// Returned when a chain segment import fails.
struct ChainSegmentFailed {
    /// To be displayed in logs.
    message: String,
    /// Used to penalize peers.
    peer_action: Option<PeerAction>,
}

impl<T: BeaconChainTypes> Worker<T> {
    /// Attempt to process a block received from a direct RPC request.
    #[allow(clippy::too_many_arguments)]
    pub async fn process_rpc_block(
        self,
        block_root: Hash256,
        block: BlockWrapper<T::EthSpec>,
        seen_timestamp: Duration,
        process_type: BlockProcessType,
        reprocess_tx: mpsc::Sender<ReprocessQueueMessage<T>>,
        duplicate_cache: DuplicateCache,
        should_process: bool,
    ) {
        if !should_process {
            // Sync handles these results
            self.send_sync_message(SyncMessage::BlockComponentProcessed {
                process_type,
                result: crate::sync::manager::BlockProcessingResult::Ignored,
                response_type: crate::sync::manager::ResponseType::Block,
            });
            return;
        }
        // Check if the block is already being imported through another source
        let handle = match duplicate_cache.check_and_insert(block_root) {
            Some(handle) => handle,
            None => {
                debug!(
                    self.log,
                    "Gossip block is being processed";
                    "action" => "sending rpc block to reprocessing queue",
                    "block_root" => %block_root,
                );
                // Send message to work reprocess queue to retry the block
                let reprocess_msg = ReprocessQueueMessage::RpcBlock(QueuedRpcBlock {
                    block_root,
                    block: block.clone(),
                    process_type,
                    seen_timestamp,
                    should_process: true,
                });

                if reprocess_tx.try_send(reprocess_msg).is_err() {
                    error!(self.log, "Failed to inform block import"; "source" => "rpc", "block_root" => %block_root)
                };
                return;
            }
        };

        // Returns `true` if the time now is after the 4s attestation deadline.
        let block_is_late = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            // If we can't read the system time clock then indicate that the
            // block is late (and therefore should *not* be requeued). This
            // avoids infinite loops.
            .map_or(true, |now| {
                get_block_delay_ms(now, block.message(), &self.chain.slot_clock)
                    > self.chain.slot_clock.unagg_attestation_production_delay()
            });

        // Checks if a block from this proposer is already known.
        let proposal_already_known = || {
            match self
                .chain
                .observed_block_producers
                .read()
                .proposer_has_been_observed(block.message())
            {
                Ok(is_observed) => is_observed,
                // Both of these blocks will be rejected, so reject them now rather
                // than re-queuing them.
                Err(ObserveError::FinalizedBlock { .. })
                | Err(ObserveError::ValidatorIndexTooHigh { .. }) => false,
            }
        };

        // Returns `true` if the block is already known to fork choice. Notably,
        // this will return `false` for blocks that we've already imported but
        // ancestors of the finalized checkpoint. That should not be an issue
        // for our use here since finalized blocks will always be late and won't
        // be requeued anyway.
        let block_is_already_known = || {
            self.chain
                .canonical_head
                .fork_choice_read_lock()
                .contains_block(&block_root)
        };

        // If we've already seen a block from this proposer *and* the block
        // arrived before the attestation deadline, requeue it to ensure it is
        // imported late enough that it won't receive a proposer boost.
        //
        // Don't requeue blocks if they're already known to fork choice, just
        // push them through to block processing so they can be handled through
        // the normal channels.
        if !block_is_late && proposal_already_known() && !block_is_already_known() {
            debug!(
                self.log,
                "Delaying processing of duplicate RPC block";
                "block_root" => ?block_root,
                "proposer" => block.message().proposer_index(),
                "slot" => block.slot()
            );

            // Send message to work reprocess queue to retry the block
            let reprocess_msg = ReprocessQueueMessage::RpcBlock(QueuedRpcBlock {
                block_root,
                block: block.clone(),
                process_type,
                seen_timestamp,
                should_process: true,
            });

            if reprocess_tx.try_send(reprocess_msg).is_err() {
                error!(
                    self.log,
                    "Failed to inform block import";
                    "source" => "rpc",
                    "block_root" => %block_root
                );
            }
            return;
        }

        let slot = block.slot();
        let parent_root = block.message().parent_root();

        let result = self
            .chain
            .process_block(
                block_root,
                block,
                CountUnrealized::True,
                NotifyExecutionLayer::Yes,
            )
            .await;

        metrics::inc_counter(&metrics::BEACON_PROCESSOR_RPC_BLOCK_IMPORTED_TOTAL);

        // RPC block imported, regardless of process type
        //TODO(sean) do we need to do anything here for missing blobs? or is passing the result
        // along to sync enough?
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
            if matches!(process_type, BlockProcessType::SingleBlock { .. }) {
                self.chain.block_times_cache.write().set_time_observed(
                    hash,
                    slot,
                    seen_timestamp,
                    None,
                    None,
                );

                self.chain.recompute_head_at_current_slot().await;
            }
        }
        // Sync handles these results
        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type,
            result: result.into(),
            response_type: ResponseType::Block,
        });

        // Drop the handle to remove the entry from the cache
        drop(handle);
    }

    pub async fn process_rpc_blobs(
        self,
        block_root: Hash256,
        blobs: FixedBlobSidecarList<T::EthSpec>,
        _seen_timestamp: Duration,
        process_type: BlockProcessType,
    ) {
        let Some(slot) = blobs.iter().find_map(|blob|{
            blob.as_ref().map(|blob| blob.slot)
        }) else {
            return;
        };

        let result = self
            .chain
            .check_availability_and_maybe_import(
                slot,
                |chain| {
                    chain
                        .data_availability_checker
                        .put_rpc_blobs(block_root, blobs)
                },
                CountUnrealized::True,
            )
            .await;

        // Sync handles these results
        self.send_sync_message(SyncMessage::BlockComponentProcessed {
            process_type,
            result: result.into(),
            response_type: ResponseType::Blob,
        });
    }

    /// Attempt to import the chain segment (`blocks`) to the beacon chain, informing the sync
    /// thread if more blocks are needed to process it.
    pub async fn process_chain_segment(
        &self,
        sync_type: ChainSegmentProcessId,
        downloaded_blocks: Vec<BlockWrapper<T::EthSpec>>,
        notify_execution_layer: NotifyExecutionLayer,
    ) {
        let result = match sync_type {
            // this a request from the range sync
            ChainSegmentProcessId::RangeBatchId(chain_id, epoch, count_unrealized) => {
                let start_slot = downloaded_blocks.first().map(|b| b.slot().as_u64());
                let end_slot = downloaded_blocks.last().map(|b| b.slot().as_u64());
                let sent_blocks = downloaded_blocks.len();

                match self
                    .process_blocks(
                        downloaded_blocks.iter(),
                        count_unrealized,
                        notify_execution_layer,
                    )
                    .await
                {
                    (_, Ok(_)) => {
                        debug!(self.log, "Batch processed";
                            "batch_epoch" => epoch,
                            "first_block_slot" => start_slot,
                            "chain" => chain_id,
                            "last_block_slot" => end_slot,
                            "processed_blocks" => sent_blocks,
                            "service"=> "sync");
                        BatchProcessResult::Success {
                            was_non_empty: sent_blocks > 0,
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
                                imported_blocks: imported_blocks > 0,
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

                match self.process_backfill_blocks(downloaded_blocks) {
                    (_, Ok(_)) => {
                        debug!(self.log, "Backfill batch processed";
                            "batch_epoch" => epoch,
                            "first_block_slot" => start_slot,
                            "last_block_slot" => end_slot,
                            "processed_blocks" => sent_blocks,
                            "processed_blobs" => n_blobs,
                            "service"=> "sync");
                        BatchProcessResult::Success {
                            was_non_empty: sent_blocks > 0,
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
                                imported_blocks: false,
                                penalty,
                            },
                            None => BatchProcessResult::NonFaultyFailure,
                        }
                    }
                }
            }
            // this is a parent lookup request from the sync manager
            ChainSegmentProcessId::ParentLookup(chain_head) => {
                debug!(
                    self.log, "Processing parent lookup";
                    "chain_hash" => %chain_head,
                    "blocks" => downloaded_blocks.len()
                );
                // parent blocks are ordered from highest slot to lowest, so we need to process in
                // reverse
                match self
                    .process_blocks(
                        downloaded_blocks.iter().rev(),
                        CountUnrealized::True,
                        notify_execution_layer,
                    )
                    .await
                {
                    (imported_blocks, Err(e)) => {
                        debug!(self.log, "Parent lookup failed"; "error" => %e.message);
                        match e.peer_action {
                            Some(penalty) => BatchProcessResult::FaultyFailure {
                                imported_blocks: imported_blocks > 0,
                                penalty,
                            },
                            None => BatchProcessResult::NonFaultyFailure,
                        }
                    }
                    (imported_blocks, Ok(_)) => {
                        debug!(self.log, "Parent lookup processed successfully");
                        BatchProcessResult::Success {
                            was_non_empty: imported_blocks > 0,
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
        downloaded_blocks: impl Iterator<Item = &'a BlockWrapper<T::EthSpec>>,
        count_unrealized: CountUnrealized,
        notify_execution_layer: NotifyExecutionLayer,
    ) -> (usize, Result<(), ChainSegmentFailed>) {
        let blocks: Vec<_> = downloaded_blocks.cloned().collect();
        match self
            .chain
            .process_chain_segment(blocks, count_unrealized, notify_execution_layer)
            .await
        {
            ChainSegmentResult::Successful { imported_blocks } => {
                metrics::inc_counter(&metrics::BEACON_PROCESSOR_CHAIN_SEGMENT_SUCCESS_TOTAL);
                if imported_blocks > 0 {
                    self.chain.recompute_head_at_current_slot().await;
                }
                (imported_blocks, Ok(()))
            }
            ChainSegmentResult::Failed {
                imported_blocks,
                error,
            } => {
                metrics::inc_counter(&metrics::BEACON_PROCESSOR_CHAIN_SEGMENT_FAILED_TOTAL);
                let r = self.handle_failed_chain_segment(error);
                if imported_blocks > 0 {
                    self.chain.recompute_head_at_current_slot().await;
                }
                (imported_blocks, r)
            }
        }
    }

    /// Helper function to process backfill block batches which only consumes the chain and blocks to process.
    fn process_backfill_blocks(
        &self,
        downloaded_blocks: Vec<BlockWrapper<T::EthSpec>>,
    ) -> (usize, Result<(), ChainSegmentFailed>) {
        let total_blocks = downloaded_blocks.len();
        let available_blocks = match downloaded_blocks
            .into_iter()
            .map(|block| {
                self.chain
                    .data_availability_checker
                    .check_availability(block)
            })
            .collect::<Result<Vec<_>, _>>()
        {
            Ok(blocks) => blocks
                .into_iter()
                .filter_map(|maybe_available| match maybe_available {
                    MaybeAvailableBlock::Available(block) => Some(block),
                    MaybeAvailableBlock::AvailabilityPending(_) => None,
                })
                .collect::<Vec<_>>(),
            Err(e) => match e {
                AvailabilityCheckError::StoreError(_)
                | AvailabilityCheckError::KzgNotInitialized => {
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
    fn handle_failed_chain_segment(
        &self,
        error: BlockError<T::EthSpec>,
    ) -> Result<(), ChainSegmentFailed> {
        match error {
            BlockError::ParentUnknown(block) => {
                // blocks should be sequential and all parents should exist
                Err(ChainSegmentFailed {
                    message: format!("Block has an unknown parent: {}", block.parent_root()),
                    // Peers are faulty if they send non-sequential blocks.
                    peer_action: Some(PeerAction::LowToleranceError),
                })
            }
            BlockError::BlockIsAlreadyKnown => {
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
                        self.log, "Block is ahead of our slot clock";
                        "msg" => "block for future slot rejected, check your time",
                        "present_slot" => present_slot,
                        "block_slot" => block_slot,
                        "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                    );
                } else {
                    // The block is in the future, but not too far.
                    debug!(
                        self.log, "Block is slightly ahead of our slot clock. Ignoring.";
                        "present_slot" => present_slot,
                        "block_slot" => block_slot,
                        "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
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
                debug!(self.log, "Finalized or earlier block processed";);
                Ok(())
            }
            BlockError::GenesisBlock => {
                debug!(self.log, "Genesis block was processed");
                Ok(())
            }
            BlockError::BeaconChainError(e) => {
                warn!(
                    self.log, "BlockProcessingFailure";
                    "msg" => "unexpected condition in processing block.",
                    "outcome" => ?e,
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
                    debug!(self.log,
                        "Execution layer verification failed";
                        "outcome" => "pausing sync",
                        "err" => ?err
                    );
                    Err(ChainSegmentFailed {
                        message: format!("Execution layer offline. Reason: {:?}", err),
                        // Do not penalize peers for internal errors.
                        peer_action: None,
                    })
                } else {
                    debug!(self.log,
                        "Invalid execution payload";
                        "error" => ?err
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
                    self.log,
                    "Failed to sync chain built on invalid parent";
                    "parent_root" => ?parent_root,
                    "advice" => "check execution node for corruption then restart it and Lighthouse",
                );
                Err(ChainSegmentFailed {
                    message: format!("Peer sent invalid block. Reason: {err:?}"),
                    // We need to penalise harshly in case this represents an actual attack. In case
                    // of a faulty EL it will usually require manual intervention to fix anyway, so
                    // it's not too bad if we drop most of our peers.
                    peer_action: Some(PeerAction::LowToleranceError),
                })
            }
            other => {
                debug!(
                    self.log, "Invalid block received";
                    "msg" => "peer sent invalid block",
                    "outcome" => %other,
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
