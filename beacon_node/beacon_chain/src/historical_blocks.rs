use crate::{errors::BeaconChainError as Error, BeaconChain, BeaconChainTypes};
use store::{chunked_vector::BlockRoots, AnchorInfo, ChunkWriter, KeyValueStore, StoreItem};
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

        let mut io_batch = Vec::with_capacity(blocks.len());

        for block in blocks.iter().rev() {
            // Check chain integrity.
            let block_root = block.canonical_root();

            if block_root != expected_block_root {
                return Err(HistoricalBlockError::MismatchedBlockRoot {
                    block_root,
                    expected_block_root,
                }
                .into());
            }

            // Store block.
            io_batch.push(block.as_kv_store_op(block_root));

            // Store block roots, including at all skip slots.
            for slot in (block.slot().as_usize()..prev_block_slot.as_usize()).rev() {
                chunk_writer.set(slot, block_root, &mut io_batch)?;
            }

            prev_block_slot = block.slot();
            expected_block_root = block.message.parent_root;
        }

        // Write the I/O batch to disk.
        chunk_writer.write(&mut io_batch)?;
        self.store.cold_db.do_atomically(io_batch)?;

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
