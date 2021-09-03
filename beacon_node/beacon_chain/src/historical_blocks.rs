use crate::{errors::BeaconChainError as Error, BeaconChain, BeaconChainTypes};
use slog::debug;
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
    PartitionOutOfBounds,
    NoAnchorInfo,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    /// Store a batch of historical blocks in the database.
    ///
    /// The `blocks` should be given in slot-ascending order. One of the blocks should have a block
    /// root corresponding to the `oldest_block_parent` from the store's `AnchorInfo`.
    ///
    /// The integrity of the hash chain *is* verified. If any block doesn't match the parent root
    /// listed in its successor, then the whole batch will be discarded and `MismatchedBlockRoot`
    /// will be returned.
    ///
    /// To align with sync we allow some excess blocks with slots greater than or equal to
    /// `oldest_block_slot` to be provided. They will be ignored without being checked.
    ///
    /// This function should not be called concurrently with any other function that mutates
    /// the anchor info (including this function itself). If a concurrent mutation occurs that
    /// would violate consistency then an `AnchorInfoConcurrentMutation` error will be returned.
    ///
    /// Return the number of blocks successfully imported.
    pub fn import_historical_block_batch(
        &self,
        blocks: Vec<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<usize, Error> {
        let anchor_info = self
            .store
            .get_anchor_info()
            .ok_or(HistoricalBlockError::NoAnchorInfo)?;

        // Take all blocks with slots less than the oldest block slot.
        let num_relevant =
            blocks.partition_point(|block| block.slot() < anchor_info.oldest_block_slot);
        let blocks_to_import = &blocks
            .get(..num_relevant)
            .ok_or(HistoricalBlockError::PartitionOutOfBounds)?;

        if blocks_to_import.len() != blocks.len() {
            debug!(
                self.log,
                "Ignoring some historic blocks";
                "oldest_block_slot" => anchor_info.oldest_block_slot,
                "total_blocks" => blocks.len(),
                "ignored" => blocks.len().saturating_sub(blocks_to_import.len()),
            );
        }

        if blocks_to_import.is_empty() {
            return Ok(0);
        }

        let mut expected_block_root = anchor_info.oldest_block_parent;
        let mut prev_block_slot = anchor_info.oldest_block_slot;
        let mut chunk_writer =
            ChunkWriter::<BlockRoots, _, _>::new(&self.store.cold_db, prev_block_slot.as_usize())?;

        let mut cold_batch = Vec::with_capacity(blocks.len());
        let mut hot_batch = Vec::with_capacity(blocks.len());

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

        Ok(blocks_to_import.len())
    }
}
