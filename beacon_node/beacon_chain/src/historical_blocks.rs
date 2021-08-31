use crate::{errors::BeaconChainError as Error, BeaconChain, BeaconChainTypes};
use store::{chunked_vector::BlockRoots, AnchorInfo, ChunkWriter, KeyValueStore};
use types::{Hash256, SignedBeaconBlock, Slot};

#[derive(Debug)]
pub enum HistoricalBlockError {
    MismatchedBlockRoot {
        block_root: Hash256,
        expected_block_root: Hash256,
    },
    BlockOutOfRange {
        slot: Slot,
        oldest_block_slot: Slot,
    },
    NoAnchorInfo,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Store a batch of historical blocks in the database.
    ///
    /// The `blocks` should be given in slot-ascending order with the last block's root
    /// corresponding to the `oldest_block_parent` from the store's `AnchorInfo`.
    ///
    /// The integrity of the hash chain *is* verified. If any block doesn't match the parent root
    /// listed in its successor, then the whole batch will be discarded and `MismatchedBlockRoot`
    /// will be returned.
    ///
    /// To align with sync we allow the last block provided to match the oldest block in the
    /// database. It will be checked (via its parent root) and discarded without further processing.
    ///
    /// This function should not be called concurrently with any other function that mutates
    /// the anchor info (including this function itself). If a concurrent mutation occurs that
    /// would violate consistency then an `AnchorInfoConcurrentMutation` error will be returned.
    pub fn import_historical_block_batch(
        &self,
        blocks: Vec<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<(), Error> {
        let anchor_info = self
            .store
            .get_anchor_info()
            .ok_or(HistoricalBlockError::NoAnchorInfo)?;

        let mut expected_block_root = anchor_info.oldest_block_parent;
        let mut prev_block_slot = anchor_info.oldest_block_slot;
        let mut chunk_writer =
            ChunkWriter::<BlockRoots, _, _>::new(&self.store.cold_db, prev_block_slot.as_usize())?;

        let mut cold_batch = Vec::with_capacity(blocks.len());
        let mut hot_batch = Vec::with_capacity(blocks.len());

        // If the last block's parent is the same as the `oldest_block_parent` then we drop it.
        // This is to align with sync on the first batch supplied. Sync likes to fetch batches of
        // blocks with the last block aligned to an epoch boundary, whereas backfill needs to
        // start from the block *before* a supplied epoch boundary block.
        let blocks_to_import = if let Some((last_block, rest)) = blocks.split_last() {
            if last_block.slot() == prev_block_slot
                && last_block.parent_root() == expected_block_root
            {
                // Skip last block (usually first batch only)
                rest
            } else {
                // Import all (normal case)
                &blocks
            }
        } else {
            // Empty batch.
            return Ok(());
        };

        for block in blocks_to_import.iter().rev() {
            // Check chain integrity.
            let block_root = block.canonical_root();

            if block_root != expected_block_root {
                return Err(HistoricalBlockError::MismatchedBlockRoot {
                    block_root,
                    expected_block_root,
                }
                .into());
            }

            // Store block in the hot database.
            hot_batch.push(self.store.block_as_kv_store_op(&block_root, block));

            // Store block roots, including at all skip slots in the freezer DB.
            for slot in (block.slot().as_usize()..prev_block_slot.as_usize()).rev() {
                chunk_writer.set(slot, block_root, &mut cold_batch)?;
            }

            prev_block_slot = block.slot();
            expected_block_root = block.message().parent_root();
        }
        chunk_writer.write(&mut cold_batch)?;

        // Write the I/O batches to disk, writing the blocks themselves first, as it's better
        // for the hot DB to contain extra blocks than for the cold DB to point to blocks that
        // do not exist.
        self.store.hot_db.do_atomically(hot_batch)?;
        self.store.cold_db.do_atomically(cold_batch)?;

        // Update the anchor.
        let new_anchor = AnchorInfo {
            oldest_block_slot: prev_block_slot,
            oldest_block_parent: expected_block_root,
            ..anchor_info
        };
        self.store
            .compare_and_set_anchor_info(Some(anchor_info), Some(new_anchor))?;

        Ok(())
    }
}
