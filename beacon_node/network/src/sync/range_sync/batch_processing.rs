use super::batch::Batch;
use crate::message_processor::FUTURE_SLOT_TOLERANCE;
use crate::sync::manager::SyncMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use slog::{debug, error, trace, warn};
use std::sync::{Arc, Weak};
use tokio::sync::mpsc;

/// The result of attempting to process a batch of blocks.
// TODO: When correct batch error handling occurs, we will include an error type.
#[derive(Debug)]
pub enum BatchProcessResult {
    /// The batch was completed successfully.
    Success,
    /// The batch processing failed.
    Failed,
}

// TODO: Refactor to async fn, with stable futures
pub fn spawn_batch_processor<T: BeaconChainTypes>(
    chain: Weak<BeaconChain<T>>,
    process_id: u64,
    batch: Batch<T::EthSpec>,
    mut sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    log: slog::Logger,
) {
    std::thread::spawn(move || {
        debug!(log, "Processing batch"; "id" => *batch.id);
        let result = match process_batch(chain, &batch, &log) {
            Ok(_) => BatchProcessResult::Success,
            Err(_) => BatchProcessResult::Failed,
        };

        debug!(log, "Batch processed"; "id" => *batch.id, "result" => format!("{:?}", result));

        sync_send
            .try_send(SyncMessage::BatchProcessed {
                process_id,
                batch: Box::new(batch),
                result,
            })
            .unwrap_or_else(|_| {
                debug!(
                    log,
                    "Batch result could not inform sync. Likely shutting down."
                );
            });
    });
}

// Helper function to process block batches which only consumes the chain and blocks to process
fn process_batch<T: BeaconChainTypes>(
    chain: Weak<BeaconChain<T>>,
    batch: &Batch<T::EthSpec>,
    log: &slog::Logger,
) -> Result<(), String> {
    let mut successful_block_import = false;
    for block in &batch.downloaded_blocks {
        if let Some(chain) = chain.upgrade() {
            let processing_result = chain.process_block(block.clone());

            if let Ok(outcome) = processing_result {
                match outcome {
                    BlockProcessingOutcome::Processed { block_root } => {
                        // The block was valid and we processed it successfully.
                        trace!(
                            log, "Imported block from network";
                            "slot" => block.slot,
                            "block_root" => format!("{}", block_root),
                        );
                        successful_block_import = true;
                    }
                    BlockProcessingOutcome::ParentUnknown { parent } => {
                        // blocks should be sequential and all parents should exist
                        warn!(
                            log, "Parent block is unknown";
                            "parent_root" => format!("{}", parent),
                            "baby_block_slot" => block.slot,
                        );
                        if successful_block_import {
                            run_fork_choice(chain, log);
                        }
                        return Err(format!(
                            "Block at slot {} has an unknown parent.",
                            block.slot
                        ));
                    }
                    BlockProcessingOutcome::BlockIsAlreadyKnown => {
                        // this block is already known to us, move to the next
                        debug!(
                            log, "Imported a block that is already known";
                            "block_slot" => block.slot,
                        );
                    }
                    BlockProcessingOutcome::FutureSlot {
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
                            if successful_block_import {
                                run_fork_choice(chain, log);
                            }
                            return Err(format!(
                                "Block at slot {} is too far in the future",
                                block.slot
                            ));
                        } else {
                            // The block is in the future, but not too far.
                            debug!(
                                log, "Block is slightly ahead of our slot clock, ignoring.";
                                "present_slot" => present_slot,
                                "block_slot" => block_slot,
                                "FUTURE_SLOT_TOLERANCE" => FUTURE_SLOT_TOLERANCE,
                            );
                        }
                    }
                    BlockProcessingOutcome::WouldRevertFinalizedSlot { .. } => {
                        debug!(
                            log, "Finalized or earlier block processed";
                            "outcome" => format!("{:?}", outcome),
                        );
                        // block reached our finalized slot or was earlier, move to the next block
                    }
                    BlockProcessingOutcome::GenesisBlock => {
                        debug!(
                            log, "Genesis block was processed";
                            "outcome" => format!("{:?}", outcome),
                        );
                    }
                    _ => {
                        warn!(
                            log, "Invalid block received";
                            "msg" => "peer sent invalid block",
                            "outcome" => format!("{:?}", outcome),
                        );
                        if successful_block_import {
                            run_fork_choice(chain, log);
                        }
                        return Err(format!("Invalid block at slot {}", block.slot));
                    }
                }
            } else {
                warn!(
                    log, "BlockProcessingFailure";
                    "msg" => "unexpected condition in processing block.",
                    "outcome" => format!("{:?}", processing_result)
                );
                if successful_block_import {
                    run_fork_choice(chain, log);
                }
                return Err(format!(
                    "Unexpected block processing error: {:?}",
                    processing_result
                ));
            }
        } else {
            return Ok(()); // terminate early due to dropped beacon chain
        }
    }

    // Batch completed successfully, run fork choice.
    if let Some(chain) = chain.upgrade() {
        run_fork_choice(chain, log);
    }

    Ok(())
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
