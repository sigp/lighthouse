use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use slog::{debug, info};
use store::{AnchorInfo, StoreOp};
use types::Slot;

/// Aim to prune blocks around once per week.
pub const BLOCK_PRUNE_BUFFER: Slot = Slot::new(7 * 225 * 32);

/// Prune blocks in batches of this size.
pub const PRUNE_BATCH_SIZE: usize = 1024;

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Delete old blocks from the database when configured.
    // FIXME(sproul): what if no finality?
    pub fn prune_blocks(&self) -> Result<(), BeaconChainError> {
        if self.config.genesis_backfill {
            return Ok(());
        }

        let current_target = *self.oldest_block_target_slot.read();
        let new_target = self
            .config
            .compute_oldest_block_target_slot::<T::EthSpec, _>(&self.slot_clock, &self.spec);

        if current_target + BLOCK_PRUNE_BUFFER >= new_target {
            debug!(
                self.log,
                "Delaying block pruning";
                "slots_until_prune" => current_target + BLOCK_PRUNE_BUFFER - new_target,
            );
            return Ok(());
        }

        let Some(mut current_anchor) = self.store.get_anchor_info() else {
            info!(
                self.log,
                "Cannot prune blocks on archive node";
                "tip" => "re-sync or turn on --genesis-backfill"
            );
            return Ok(());
        };

        // For simplicity, avoid pruning blocks while backfill is on-going.
        if !current_anchor.block_backfill_complete(current_target) {
            debug!(self.log, "Delaying block pruning until backfill complete");
            return Ok(());
        }

        let mut io_batch = Vec::with_capacity(PRUNE_BATCH_SIZE);
        let mut prev_block_root = None;

        for res in
            self.forwards_iter_block_roots_until(current_anchor.oldest_block_slot, new_target - 1)?
        {
            let (block_root, slot) = res?;

            if prev_block_root.map_or(true, |prev| block_root != prev) {
                io_batch.push(StoreOp::DeleteBlock(block_root));
                io_batch.push(StoreOp::DeleteExecutionPayload(block_root));
                prev_block_root = Some(block_root);
            }

            if io_batch.len() >= PRUNE_BATCH_SIZE || slot == new_target - 1 {
                let new_anchor = AnchorInfo {
                    oldest_block_slot: slot + 1,
                    ..current_anchor.clone()
                };
                let anchor_op = self.store.compare_and_set_anchor_info(
                    Some(current_anchor.clone()),
                    Some(new_anchor.clone()),
                )?;
                io_batch.push(StoreOp::KeyValueOp(anchor_op));
                self.store.do_atomically(std::mem::take(&mut io_batch))?;

                debug!(
                    self.log,
                    "Pruned blocks";
                    "from" => current_anchor.oldest_block_slot,
                    "to" => new_anchor.oldest_block_slot
                );
                current_anchor = new_anchor;
            }
        }

        assert_eq!(new_target, current_anchor.oldest_block_slot);

        info!(
            self.log,
            "Pruned old blocks";
            "oldest_block_slot" => current_anchor.oldest_block_slot
        );

        // Update current target in memory.
        *self.oldest_block_target_slot.write() = new_target;

        Ok(())
    }
}
