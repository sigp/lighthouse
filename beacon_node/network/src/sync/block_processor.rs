use crate::message_processor::FUTURE_SLOT_TOLERANCE;
use crate::sync::manager::SyncMessage;
use crate::sync::range_sync::BatchId;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockProcessingOutcome};
use eth2_libp2p::PeerId;
use slog::{debug, error, trace, warn};
use std::sync::{Arc, Weak};
use tokio::sync::mpsc;
use types::SignedBeaconBlock;

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
    downloaded_blocks: Vec<SignedBeaconBlock<T::EthSpec>>,
    mut sync_send: mpsc::UnboundedSender<SyncMessage<T::EthSpec>>,
    log: slog::Logger,
) {
    std::thread::spawn(move || {
        match process_id {
            // this a request from the range sync
            ProcessId::RangeBatchId(batch_id) => {
                debug!(log, "Processing batch"; "id" => *batch_id, "blocks" => downloaded_blocks.len());
                let result = match process_blocks(chain, downloaded_blocks.iter(), &log) {
                    Ok(_) => {
                        debug!(log, "Batch processed"; "id" => *batch_id );
                        BatchProcessResult::Success
                    }
                    Err(e) => {
                        debug!(log, "Batch processing failed"; "id" => *batch_id, "error" => e);
                        BatchProcessResult::Failed
                    }
                };

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
            }
            // this a parent lookup request from the sync manager
            ProcessId::ParentLookup(peer_id) => {
                debug!(log, "Processing parent lookup"; "last_peer_id" => format!("{}", peer_id), "blocks" => downloaded_blocks.len());
                // parent blocks are ordered from highest slot to lowest, so we need to process in
                // reverse
                match process_blocks(chain, downloaded_blocks.iter().rev(), &log) {
                    Err(e) => {
                        warn!(log, "Parent lookup failed"; "last_peer_id" => format!("{}", peer_id), "error" => e);
                        sync_send
                        .try_send(SyncMessage::ParentLookupFailed(peer_id))
                        .unwrap_or_else(|_| {
                            // on failure, inform to downvote the peer
                            debug!(
                                log,
                                "Block processor could not inform parent lookup result. Likely shutting down."
                            );
                        });
                    }
                    Ok(_) => {
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
) -> Result<(), String> {
    let mut successful_block_import = false;
    for block in downloaded_blocks {
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
                        // this is a failure if blocks do not have parents
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
