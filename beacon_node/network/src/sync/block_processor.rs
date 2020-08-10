use crate::router::processor::FUTURE_SLOT_TOLERANCE;
use crate::sync::manager::SyncMessage;
use crate::sync::range_sync::{BatchId, ChainId};
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockError, ChainSegmentResult};
use eth2_libp2p::PeerId;
use slog::{debug, error, trace, warn};
use std::sync::{Arc, Weak};
use tokio::sync::mpsc;
use types::{EthSpec, SignedBeaconBlock};

/// Id associated to a block processing request, either a batch or a single block.
#[derive(Clone, Debug, PartialEq)]
pub enum ProcessId {
    /// Processing Id of a range syncing batch.
    RangeBatchId(ChainId, BatchId),
    /// Processing Id of the parent lookup of a block
    ParentLookup(PeerId),
}

/// The result of a block processing request.
// TODO: When correct batch error handling occurs, we will include an error type.
#[derive(Debug)]
pub enum BatchProcessResult {
    /// The batch was completed successfully.
    Success,
    /// The batch processing failed.
    Failed,
    /// The batch processing failed but managed to import at least one block.
    Partial,
}

/// Spawns a thread handling the block processing of a request: range syncing or parent lookup.
pub fn spawn_block_processor<T: BeaconChainTypes>(
    chain: Weak<BeaconChain<T>>,
    process_id: ProcessId,
    downloaded_blocks: Vec<SignedBeaconBlock<T::EthSpec>>,
    sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    log: slog::Logger,
) {
    std::thread::spawn(move || {
        match process_id {
            // this a request from the range sync
            ProcessId::RangeBatchId(chain_id, batch_id) => {
                let len = downloaded_blocks.len();
                let start_slot = if len > 0 {
                    downloaded_blocks[0].message.slot.as_u64()
                } else {
                    0
                };
                let end_slot = if len > 0 {
                    downloaded_blocks[len - 1].message.slot.as_u64()
                } else {
                    0
                };

                debug!(log, "Processing batch"; "id" => *batch_id, "blocks" => downloaded_blocks.len(),  "start_slot" => start_slot, "end_slot" => end_slot);
                let result = match process_blocks(chain, downloaded_blocks.iter(), &log) {
                    (_, Ok(_)) => {
                        debug!(log, "Batch processed"; "id" => *batch_id , "start_slot" => start_slot, "end_slot" => end_slot);
                        BatchProcessResult::Success
                    }
                    (imported_blocks, Err(e)) if imported_blocks > 0 => {
                        debug!(log, "Batch processing failed but imported some blocks";
                            "id" => *batch_id, "error" => e, "imported_blocks"=> imported_blocks);
                        BatchProcessResult::Partial
                    }
                    (_, Err(e)) => {
                        debug!(log, "Batch processing failed"; "id" => *batch_id, "error" => e);
                        BatchProcessResult::Failed
                    }
                };

                let msg = SyncMessage::BatchProcessed {
                    chain_id,
                    batch_id,
                    downloaded_blocks,
                    result,
                };
                sync_send.send(msg).unwrap_or_else(|_| {
                    debug!(
                        log,
                        "Block processor could not inform range sync result. Likely shutting down."
                    );
                });
            }
            // this a parent lookup request from the sync manager
            ProcessId::ParentLookup(peer_id) => {
                debug!(
                    log, "Processing parent lookup";
                    "last_peer_id" => format!("{}", peer_id),
                    "blocks" => downloaded_blocks.len()
                );
                // parent blocks are ordered from highest slot to lowest, so we need to process in
                // reverse
                match process_blocks(chain, downloaded_blocks.iter().rev(), &log) {
                    (_, Err(e)) => {
                        warn!(log, "Parent lookup failed"; "last_peer_id" => format!("{}", peer_id), "error" => e);
                        sync_send
                        .send(SyncMessage::ParentLookupFailed(peer_id))
                        .unwrap_or_else(|_| {
                            // on failure, inform to downvote the peer
                            debug!(
                                log,
                                "Block processor could not inform parent lookup result. Likely shutting down."
                            );
                        });
                    }
                    (_, Ok(_)) => {
                        debug!(log, "Parent lookup processed successfully");
                    }
                }
            }
        }
    });
}

/// Helper function to process blocks batches which only consumes the chain and blocks to process.
fn process_blocks<
    'a,
    T: BeaconChainTypes,
    I: Iterator<Item = &'a SignedBeaconBlock<T::EthSpec>>,
>(
    chain: Weak<BeaconChain<T>>,
    downloaded_blocks: I,
    log: &slog::Logger,
) -> (usize, Result<(), String>) {
    if let Some(chain) = chain.upgrade() {
        let blocks = downloaded_blocks.cloned().collect::<Vec<_>>();
        let (imported_blocks, r) = match chain.process_chain_segment(blocks) {
            ChainSegmentResult::Successful { imported_blocks } => {
                if imported_blocks == 0 {
                    debug!(log, "All blocks already known");
                } else {
                    debug!(
                        log, "Imported blocks from network";
                        "count" => imported_blocks,
                    );
                    // Batch completed successfully with at least one block, run fork choice.
                    run_fork_choice(chain, log);
                }

                (imported_blocks, Ok(()))
            }
            ChainSegmentResult::Failed {
                imported_blocks,
                error,
            } => {
                let r = handle_failed_chain_segment(error, log);
                if imported_blocks > 0 {
                    run_fork_choice(chain, log);
                }
                (imported_blocks, r)
            }
        };

        return (imported_blocks, r);
    }

    (0, Ok(()))
}

/// Runs fork-choice on a given chain. This is used during block processing after one successful
/// block import.
fn run_fork_choice<T: BeaconChainTypes>(chain: Arc<BeaconChain<T>>, log: &slog::Logger) {
    match chain.fork_choice() {
        Ok(()) => trace!(
            log,
            "Fork choice success";
            "location" => "batch processing"
        ),
        Err(e) => error!(
            log,
            "Fork choice failed";
            "error" => format!("{:?}", e),
            "location" => "batch import error"
        ),
    }
}

/// Helper function to handle a `BlockError` from `process_chain_segment`
fn handle_failed_chain_segment<T: EthSpec>(
    error: BlockError<T>,
    log: &slog::Logger,
) -> Result<(), String> {
    match error {
        BlockError::ParentUnknown(block) => {
            // blocks should be sequential and all parents should exist

            Err(format!(
                "Block has an unknown parent: {}",
                block.parent_root()
            ))
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
                    log, "Block is ahead of our slot clock";
                    "msg" => "block for future slot rejected, check your time",
                    "present_slot" => present_slot,
                    "block_slot" => block_slot,
                    "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                );
            } else {
                // The block is in the future, but not too far.
                debug!(
                    log, "Block is slightly ahead of our slot clock, ignoring.";
                    "present_slot" => present_slot,
                    "block_slot" => block_slot,
                    "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                );
            }

            Err(format!(
                "Block with slot {} is higher than the current slot {}",
                block_slot, present_slot
            ))
        }
        BlockError::WouldRevertFinalizedSlot { .. } => {
            debug!( log, "Finalized or earlier block processed";);

            Ok(())
        }
        BlockError::GenesisBlock => {
            debug!(log, "Genesis block was processed");
            Ok(())
        }
        BlockError::BeaconChainError(e) => {
            warn!(
                log, "BlockProcessingFailure";
                "msg" => "unexpected condition in processing block.",
                "outcome" => format!("{:?}", e)
            );

            Err(format!("Internal error whilst processing block: {:?}", e))
        }
        other => {
            debug!(
                log, "Invalid block received";
                "msg" => "peer sent invalid block",
                "outcome" => format!("{:?}", other),
            );

            Err(format!("Peer sent invalid block. Reason: {:?}", other))
        }
    }
}
