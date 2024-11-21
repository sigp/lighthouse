//! Implementation of historic state reconstruction (given complete block history).
use crate::hot_cold_store::{HotColdDB, HotColdDBError};
use crate::metadata::ANCHOR_FOR_ARCHIVE_NODE;
use crate::metrics;
use crate::{Error, ItemStore};
use itertools::{process_results, Itertools};
use slog::{debug, info};
use state_processing::{
    per_block_processing, per_slot_processing, BlockSignatureStrategy, ConsensusContext,
    VerifyBlockRoot,
};
use std::sync::Arc;
use types::EthSpec;

impl<E, Hot, Cold> HotColdDB<E, Hot, Cold>
where
    E: EthSpec,
    Hot: ItemStore<E>,
    Cold: ItemStore<E>,
{
    pub fn reconstruct_historic_states(
        self: &Arc<Self>,
        num_blocks: Option<usize>,
    ) -> Result<(), Error> {
        let mut anchor = self.get_anchor_info();

        // Nothing to do, history is complete.
        if anchor.all_historic_states_stored() {
            return Ok(());
        }

        // Check that all historic blocks are known.
        if anchor.oldest_block_slot != 0 {
            return Err(Error::MissingHistoricBlocks {
                oldest_block_slot: anchor.oldest_block_slot,
            });
        }

        debug!(
            self.log,
            "Starting state reconstruction batch";
            "start_slot" => anchor.state_lower_limit,
        );

        let _t = metrics::start_timer(&metrics::STORE_BEACON_RECONSTRUCTION_TIME);

        // Iterate blocks from the state lower limit to the upper limit.
        let split = self.get_split_info();
        let lower_limit_slot = anchor.state_lower_limit;
        let upper_limit_slot = std::cmp::min(split.slot, anchor.state_upper_limit);

        // If `num_blocks` is not specified iterate all blocks. Add 1 so that we end on an epoch
        // boundary when `num_blocks` is a multiple of an epoch boundary. We want to be *inclusive*
        // of the state at slot `lower_limit_slot + num_blocks`.
        let block_root_iter = self
            .forwards_block_roots_iterator_until(lower_limit_slot, upper_limit_slot - 1, || {
                Err(Error::StateShouldNotBeRequired(upper_limit_slot - 1))
            })?
            .take(num_blocks.map_or(usize::MAX, |n| n + 1));

        // The state to be advanced.
        let mut state = self.load_cold_state_by_slot(lower_limit_slot)?;

        state.build_caches(&self.spec)?;

        process_results(block_root_iter, |iter| -> Result<(), Error> {
            let mut io_batch = vec![];

            let mut prev_state_root = None;

            for ((prev_block_root, _), (block_root, slot)) in iter.tuple_windows() {
                let is_skipped_slot = prev_block_root == block_root;

                let block = if is_skipped_slot {
                    None
                } else {
                    Some(
                        self.get_blinded_block(&block_root)?
                            .ok_or(Error::BlockNotFound(block_root))?,
                    )
                };

                // Advance state to slot.
                per_slot_processing(&mut state, prev_state_root.take(), &self.spec)
                    .map_err(HotColdDBError::BlockReplaySlotError)?;

                // Apply block.
                if let Some(block) = block {
                    let mut ctxt = ConsensusContext::new(block.slot())
                        .set_current_block_root(block_root)
                        .set_proposer_index(block.message().proposer_index());

                    per_block_processing(
                        &mut state,
                        &block,
                        BlockSignatureStrategy::NoVerification,
                        VerifyBlockRoot::True,
                        &mut ctxt,
                        &self.spec,
                    )
                    .map_err(HotColdDBError::BlockReplayBlockError)?;

                    prev_state_root = Some(block.state_root());
                }

                let state_root = prev_state_root
                    .ok_or(())
                    .or_else(|_| state.update_tree_hash_cache())?;

                // Stage state for storage in freezer DB.
                self.store_cold_state(&state_root, &state, &mut io_batch)?;

                let batch_complete =
                    num_blocks.map_or(false, |n_blocks| slot == lower_limit_slot + n_blocks as u64);
                let reconstruction_complete = slot + 1 == upper_limit_slot;

                // Commit the I/O batch if:
                //
                // - The diff/snapshot for this slot is required for future slots, or
                // - The reconstruction batch is complete (we are about to return), or
                // - Reconstruction is complete.
                if self.hierarchy.should_commit_immediately(slot)?
                    || batch_complete
                    || reconstruction_complete
                {
                    info!(
                        self.log,
                        "State reconstruction in progress";
                        "slot" => slot,
                        "remaining" => upper_limit_slot - 1 - slot
                    );

                    self.cold_db.do_atomically(std::mem::take(&mut io_batch))?;

                    // Update anchor.
                    let old_anchor = anchor.clone();

                    if reconstruction_complete {
                        // The two limits have met in the middle! We're done!
                        // Perform one last integrity check on the state reached.
                        let computed_state_root = state.update_tree_hash_cache()?;
                        if computed_state_root != state_root {
                            return Err(Error::StateReconstructionRootMismatch {
                                slot,
                                expected: state_root,
                                computed: computed_state_root,
                            });
                        }

                        self.compare_and_set_anchor_info_with_write(
                            old_anchor,
                            ANCHOR_FOR_ARCHIVE_NODE,
                        )?;

                        return Ok(());
                    } else {
                        // The lower limit has been raised, store it.
                        anchor.state_lower_limit = slot;

                        self.compare_and_set_anchor_info_with_write(old_anchor, anchor.clone())?;
                    }

                    // If this is the end of the batch, return Ok. The caller will run another
                    // batch when there is idle capacity.
                    if batch_complete {
                        debug!(
                            self.log,
                            "Finished state reconstruction batch";
                            "start_slot" => lower_limit_slot,
                            "end_slot" => slot,
                        );
                        return Ok(());
                    }
                }
            }

            // Should always reach the `upper_limit_slot` or the end of the batch and return early
            // above.
            Err(Error::StateReconstructionLogicError)
        })??;

        // Check that the split point wasn't mutated during the state reconstruction process.
        // It shouldn't have been, due to the serialization of requests through the store migrator,
        // so this is just a paranoid check.
        let latest_split = self.get_split_info();
        if split != latest_split {
            return Err(Error::SplitPointModified(latest_split.slot, split.slot));
        }

        Ok(())
    }
}
