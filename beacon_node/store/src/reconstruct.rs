//! Implementation of historic state reconstruction (given complete block history).
use crate::hot_cold_store::{HotColdDB, HotColdDBError};
use crate::{Error, ItemStore, KeyValueStore};
use itertools::{process_results, Itertools};
use slog::info;
use state_processing::{per_block_processing, per_slot_processing, BlockSignatureStrategy};
use std::sync::Arc;
use types::{EthSpec, Hash256};

impl<E, Hot, Cold> HotColdDB<E, Hot, Cold>
where
    E: EthSpec,
    Hot: KeyValueStore<E> + ItemStore<E>,
    Cold: KeyValueStore<E> + ItemStore<E>,
{
    pub fn reconstruct_historic_states(self: &Arc<Self>) -> Result<(), Error> {
        let mut anchor = if let Some(anchor) = self.get_anchor_info() {
            anchor
        } else {
            // Nothing to do, history is complete.
            return Ok(());
        };

        // Check that all historic blocks are known.
        if anchor.oldest_block_slot != 0 {
            return Err(Error::MissingHistoricBlocks {
                oldest_block_slot: anchor.oldest_block_slot,
            });
        }

        info!(
            self.log,
            "Beginning historic state reconstruction";
            "start_slot" => anchor.state_lower_limit,
        );

        let slots_per_restore_point = self.config.slots_per_restore_point;

        // Iterate blocks from the state lower limit to the upper limit.
        let lower_limit_slot = anchor.state_lower_limit;
        let split = self.get_split_info();
        let upper_limit_state = self.get_restore_point(
            anchor.state_upper_limit.as_u64() / slots_per_restore_point,
            &split,
        )?;
        let upper_limit_slot = upper_limit_state.slot();

        // Use a dummy root, as we never read the block for the upper limit state.
        let upper_limit_block_root = Hash256::repeat_byte(0xff);

        let block_root_iter = Self::forwards_block_roots_iterator(
            self.clone(),
            lower_limit_slot,
            upper_limit_state,
            upper_limit_block_root,
            &self.spec,
        )?;

        // The state to be advanced.
        let mut state = self
            .load_cold_state_by_slot(lower_limit_slot)?
            .ok_or(HotColdDBError::MissingLowerLimitState(lower_limit_slot))?;

        state.build_all_caches(&self.spec)?;

        process_results(block_root_iter, |iter| -> Result<(), Error> {
            let mut io_batch = vec![];

            let mut prev_state_root = None;

            for ((prev_block_root, _), (block_root, slot)) in iter.tuple_windows() {
                let is_skipped_slot = prev_block_root == block_root;

                let block = if is_skipped_slot {
                    None
                } else {
                    Some(
                        self.get_block(&block_root)?
                            .ok_or(Error::BlockNotFound(block_root))?,
                    )
                };

                // Advance state to slot.
                per_slot_processing(&mut state, prev_state_root.take(), &self.spec)
                    .map_err(HotColdDBError::BlockReplaySlotError)?;

                // Apply block.
                if let Some(block) = block {
                    per_block_processing(
                        &mut state,
                        &block,
                        Some(block_root),
                        BlockSignatureStrategy::NoVerification,
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

                // If the slot lies on an epoch boundary, commit the batch and update the anchor.
                if slot % slots_per_restore_point == 0 || slot + 1 == upper_limit_slot {
                    info!(
                        self.log,
                        "State reconstruction in progress";
                        "slot" => slot,
                        "remaining" => upper_limit_slot - 1 - slot
                    );

                    self.cold_db.do_atomically(std::mem::take(&mut io_batch))?;

                    // Update anchor.
                    let old_anchor = Some(anchor.clone());

                    if slot + 1 == upper_limit_slot {
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

                        self.compare_and_set_anchor_info_with_write(old_anchor, None)?;

                        return Ok(());
                    } else {
                        // The lower limit has been raised, store it.
                        anchor.state_lower_limit = slot;

                        self.compare_and_set_anchor_info_with_write(
                            old_anchor,
                            Some(anchor.clone()),
                        )?;
                    }
                }
            }

            // Should always reach the `upper_limit_slot` and return early above.
            Err(Error::StateReconstructionDidNotComplete)
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
