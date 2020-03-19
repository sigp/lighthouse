use crate::message_processor::FUTURE_SLOT_TOLERANCE;
use crate::sync::manager::SyncMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::PeerId;
use slog::{debug, error, trace, warn};
use std::sync::{Arc, Weak};
use tokio::sync::mpsc;
use types::SignedBeaconBlock;
use crate::sync::range_sync::BatchId;

/// Id associated to a block processing request, either a batch or a single block.
#[derive(Clone, Debug, PartialEq)]
pub enum ProcessId {
    /// Processing Id of a range syncing batch.
    RangeBatchId(BatchId),
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
}

/// Spawns a thread handling the block processing of a request: range syncing or parent lookup.
pub fn spawn_block_processor<T: BeaconChainTypes>(
    chain: Weak<BeaconChain<T>>,
    process_id: ProcessId,
    mut downloaded_blocks: Vec<SignedBeaconBlock<T::EthSpec>>,
    mut sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    log: slog::Logger,
) {
    match process_id {
        ProcessId::RangeBatchId(batch_id) => {
            std::thread::spawn(move || {
                debug!(log, "Processing batch"; "id" => *batch_id);
                let result = match process_batch(chain, &mut downloaded_blocks, &log) {
                    Ok(_) => BatchProcessResult::Success,
                    Err(_) => BatchProcessResult::Failed,
                };

                debug!(log, "Batch processed"; "id" => *batch_id, "result" => format!("{:?}", result));
                let msg = SyncMessage::BatchProcessed {
                    batch_id: batch_id,
                    downloaded_blocks: downloaded_blocks,
                    result,
                };
                sync_send.try_send(msg).unwrap_or_else(|_| {
                    debug!(
                        log,
                        "Block processor could not inform range sync result. Likely shutting down."
                    );
                });
            });
        }
        ProcessId::ParentLookup(peer_id) => {
            std::thread::spawn(move || {
                match parent_lookup(chain, downloaded_blocks, &log) {
                    Ok(_) => {
                        // Do nothing on success
                    },
                    Err(_) => sync_send
                        .try_send(SyncMessage::ParentLookupFailed(peer_id))
                        .unwrap_or_else(|_| {
                            debug!(
                                log,
                                "Block processor could not inform parent lookup result. Likely shutting down."
                            );
                        }),
                };
            });
        }
    }
}

/// Helper function to process block batches which only consumes the chain and blocks to process.
fn process_batch<T: BeaconChainTypes>(
    chain: Weak<BeaconChain<T>>,
    downloaded_blocks: &mut Vec<SignedBeaconBlock<T::EthSpec>>,
    log: &slog::Logger,
) -> Result<(), String> {
    let mut successful_block_import = false;
    for block in downloaded_blocks.iter() {
        if let Some(chain) = chain.upgrade() {
            let processing_result = chain.process_block(block.clone());

            if let Ok(outcome) = processing_result {
                match outcome {
                    BlockProcessingOutcome::Processed { block_root } => {
                        // The block was valid and we processed it successfully.
                        trace!(
                            log, "Imported block from network";
                            "slot" => block.slot(),
                            "block_root" => format!("{}", block_root),
                        );
                        successful_block_import = true;
                    }
                    BlockProcessingOutcome::ParentUnknown { parent, .. } => {
                        // blocks should be sequential and all parents should exist
                        warn!(
                            log, "Parent block is unknown";
                            "parent_root" => format!("{}", parent),
                            "baby_block_slot" => block.slot(),
                        );
                        if successful_block_import {
                            run_fork_choice(chain, log);
                        }
                        return Err(format!(
                            "Block at slot {} has an unknown parent.",
                            block.slot()
                        ));
                    }
                    BlockProcessingOutcome::BlockIsAlreadyKnown => {
                        // this block is already known to us, move to the next
                        debug!(
                            log, "Imported a block that is already known";
                            "block_slot" => block.slot(),
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
                                block.slot()
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
                        return Err(format!("Invalid block at slot {}", block.slot()));
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

/// Handles the parent lookup processing given a list of blocks.
fn parent_lookup<T: BeaconChainTypes>(
    chain: Weak<BeaconChain<T>>,
    mut downloaded_blocks: Vec<SignedBeaconBlock<T::EthSpec>>,
    log: &slog::Logger,
) -> Result<(), String> {
    let total_blocks_to_process = downloaded_blocks.len().saturating_add(1);
    while let Some(block) = downloaded_blocks.pop() {
        // check if the chain exists
        if let Some(chain) = chain.upgrade() {
            match chain.process_block(block) {
                Ok(BlockProcessingOutcome::Processed { .. })
                | Ok(BlockProcessingOutcome::BlockIsAlreadyKnown { .. }) => {} // continue to the next block
                // all else is considered a failure
                Ok(outcome) => {
                    // the previous blocks have failed, notify the user the chain lookup has
                    // failed and drop the parent queue
                    debug!(
                        log, "Invalid parent chain. Past blocks failure";
                        "outcome" => format!("{:?}", outcome),
                    );
                    return Err("Parent lookup failed".to_string());
                }
                Err(e) => {
                    warn!(
                        log, "Parent chain processing error.";
                        "error" => format!("{:?}", e)
                    );
                    return Err("Parent lookup failed".to_string());
                }
            }
        } else {
            // chain doesn't exist, end the processing
            break;
        }
    }

    // the last received block has been successfully processed, process all other blocks in the
    // chain

    // at least one block has been processed, run fork-choice
    if let Some(chain) = chain.upgrade() {
        match chain.fork_choice() {
            Ok(()) => trace!(
                log,
                "Fork choice success";
                "block_imports" => total_blocks_to_process - downloaded_blocks.len(),
                "location" => "parent request"
            ),
            Err(e) => error!(
                log,
                "Fork choice failed";
                "error" => format!("{:?}", e),
                "location" => "parent request"
            ),
        };
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
