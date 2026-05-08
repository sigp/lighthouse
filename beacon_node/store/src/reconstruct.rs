//! Implementation of historic state reconstruction (given complete block history).
use crate::forwards_iter::FrozenForwardsIterator;
use crate::hot_cold_store::{HotColdDB, HotColdDBError};
use crate::metrics;
use crate::{DBColumn, Error, ItemStore};
use itertools::{Itertools, process_results};
use state_processing::{
    BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot, per_block_processing,
    per_slot_processing,
};
use std::sync::Arc;
use tracing::{debug, info};
use types::{EthSpec, Slot};

impl<E, Hot, Cold> HotColdDB<E, Hot, Cold>
where
    E: EthSpec,
    Hot: ItemStore,
    Cold: ItemStore,
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

        // Iterate blocks from the state lower limit to the upper limit.
        let split = self.get_split_info();
        let lower_limit_slot = anchor.state_lower_limit;
        let upper_limit_slot = std::cmp::min(split.slot, anchor.state_upper_limit);

        // If the split is at 0 we can't reconstruct historic states.
        if split.slot == 0 {
            debug!("No state reconstruction possible");
            return Ok(());
        }

        // If `num_blocks` is not specified iterate all blocks. Add 1 so that we end on an epoch
        // boundary when `num_blocks` is a multiple of an epoch boundary. We want to be *inclusive*
        // of the state at slot `lower_limit_slot + num_blocks`.
        let to_slot = num_blocks
            .map(|n| std::cmp::min(lower_limit_slot + n as u64 + 1, upper_limit_slot))
            .unwrap_or(upper_limit_slot);

        let on_commit = |slot: Slot| -> Result<(), Error> {
            info!(
                %slot,
                remaining = %(upper_limit_slot - 1 - slot),
                "State reconstruction in progress"
            );

            // Update anchor.
            let old_anchor = anchor.clone();
            let reconstruction_complete = slot + 1 == upper_limit_slot;

            if reconstruction_complete {
                // The two limits have met in the middle! We're done!
                let new_anchor = old_anchor.as_archive_anchor();
                self.compare_and_set_anchor_info_with_write(old_anchor, new_anchor)?;
            } else {
                // The lower limit has been raised, store it.
                anchor.state_lower_limit = slot;
                self.compare_and_set_anchor_info_with_write(old_anchor, anchor.clone())?;
            }

            Ok(())
        };

        self.reconstruct_historic_states_on_range(lower_limit_slot, to_slot, on_commit)?;

        // Check that the split point wasn't mutated during the state reconstruction process.
        // It shouldn't have been, due to the serialization of requests through the store migrator,
        // so this is just a paranoid check.
        let latest_split = self.get_split_info();
        if split != latest_split {
            return Err(Error::SplitPointModified(latest_split.slot, split.slot));
        }

        Ok(())
    }

    /// Reconstruct historic states for the slot range `(with_state_at_slot, to_slot)`.
    ///
    /// Loads the state at `with_state_at_slot` and replays blocks up to and including slot
    /// `to_slot - 1`, writing all intermediate states to the freezer DB.
    ///
    /// The `BeaconBlockRoots` column must be populated for the range before this is called.
    ///
    /// `on_commit(slot)` is invoked after each atomic commit (whenever the hierarchy says to
    /// commit, plus once at the final slot) so callers can update anchor metadata or log
    /// progress.
    pub fn reconstruct_historic_states_on_range(
        self: &Arc<Self>,
        with_state_at_slot: Slot,
        to_slot: Slot,
        mut on_commit: impl FnMut(Slot) -> Result<(), Error>,
    ) -> Result<(), Error> {
        debug!(
            from_slot = %(with_state_at_slot + 1),
            %to_slot,
            "Starting state reconstruction batch"
        );

        let _t = metrics::start_timer(&metrics::STORE_BEACON_RECONSTRUCTION_TIME);

        // Iterate from `with_state_at_slot` so `tuple_windows` gives us the predecessor block
        // root at each step for skip detection.
        let block_root_iter = FrozenForwardsIterator::new(
            self,
            DBColumn::BeaconBlockRoots,
            with_state_at_slot,
            to_slot,
        )?;

        // The state to be advanced.
        let mut state = self.load_cold_state_by_slot(with_state_at_slot)?;
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

                let batch_complete = slot + 1 == to_slot;

                // Commit the I/O batch if:
                //
                // - The diff/snapshot for this slot is required for future slots, or
                // - The reconstruction batch is complete (we are about to return).
                if self.hierarchy.should_commit_immediately(slot)? || batch_complete {
                    self.cold_db.do_atomically(std::mem::take(&mut io_batch))?;

                    if batch_complete {
                        // Perform one last integrity check on the state reached.
                        let computed_state_root = state.update_tree_hash_cache()?;
                        if computed_state_root != state_root {
                            return Err(Error::StateReconstructionRootMismatch {
                                slot,
                                expected: state_root,
                                computed: computed_state_root,
                            });
                        }
                    }

                    on_commit(slot)?;

                    // If this is the end of the batch, return Ok. The caller will run another
                    // batch when there is idle capacity.
                    if batch_complete {
                        debug!(
                            start_slot = %(with_state_at_slot + 1),
                            end_slot = %slot,
                            "Finished state reconstruction batch"
                        );
                        return Ok(());
                    }
                }
            }

            // Should always reach `to_slot` or the end of the batch and return early above.
            Err(Error::StateReconstructionLogicError)
        })??;

        Ok(())
    }
}
