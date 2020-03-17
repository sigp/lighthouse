use super::batch::Batch;
use crate::router::processor::FUTURE_SLOT_TOLERANCE;
use crate::sync::manager::SyncMessage;
use beacon_chain::{BeaconChain, BeaconChainTypes, BlockError};
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
    if let Some(chain) = chain.upgrade() {
        match chain.process_chain_segment(batch.downloaded_blocks.clone()) {
            Ok(roots) => {
                trace!(
                    log, "Imported blocks from network";
                    "count" => roots.len(),
                );
            }
            Err(BlockError::ParentUnknown(parent)) => {
                // blocks should be sequential and all parents should exist
                warn!(
                    log, "Parent block is unknown";
                    "parent_root" => format!("{}", parent),
                );
            }
            Err(BlockError::BlockIsAlreadyKnown) => {
                // this block is already known to us, move to the next
                debug!(
                    log, "Imported a block that is already known";
                );
            }
            Err(BlockError::FutureSlot {
                present_slot,
                block_slot,
            }) => {
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
            }
            Err(BlockError::WouldRevertFinalizedSlot { .. }) => {
                debug!(
                    log, "Finalized or earlier block processed";
                );
                // block reached our finalized slot or was earlier, move to the next block
            }
            Err(BlockError::GenesisBlock) => {
                debug!(
                    log, "Genesis block was processed";
                );
            }
            Err(BlockError::BeaconChainError(e)) => {
                warn!(
                    log, "BlockProcessingFailure";
                    "msg" => "unexpected condition in processing block.",
                    "outcome" => format!("{:?}", e)
                );
            }
            other => {
                warn!(
                    log, "Invalid block received";
                    "msg" => "peer sent invalid block",
                    "outcome" => format!("{:?}", other),
                );
            }
        }
    } else {
        return Ok(()); // terminate early due to dropped beacon chain
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
