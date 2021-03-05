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
    pub fn import_historical_block_batch(
        &self,
        blocks: Vec<SignedBeaconBlock<T::EthSpec>>,
    ) -> Result<(), Error> {
        let anchor_info = if let Some(ref anc) = *self.store.anchor_info.read() {
            anc.clone()
        } else {
            return Err(HistoricalBlockError::NoAnchorInfo.into());
        };

        // Check chain integrity.
        let mut current_block_root = if let Some(last_block) = blocks.last() {
            let block_root = last_block.canonical_root();
            let expected_block_root = anchor_info.oldest_block_parent;

            if block_root != expected_block_root {
                return Err(HistoricalBlockError::MismatchedBlockRoot {
                    block_root,
                    expected_block_root,
                }
                .into());
            }
            block_root
        } else {
            // No blocks to process.
            return Ok(());
        };

        let mut prev_block_slot = anchor_info.oldest_block_slot;
        let mut chunk_writer =
            ChunkWriter::<BlockRoots, _, _>::new(&self.store.cold_db, prev_block_slot.as_usize())?;

        let mut io_batch = Vec::with_capacity(blocks.len());

        for block in blocks.iter().rev() {
            // Store block.
            io_batch.push(block.as_kv_store_op(current_block_root));

            // Store block roots, including at all skip slots.
            for slot in (block.slot().as_usize()..prev_block_slot.as_usize()).rev() {
                chunk_writer.set(slot, current_block_root, &mut io_batch)?;
            }

            prev_block_slot = block.slot();
            // TODO(sproul): work out whether to do verification here or elsewhere
            current_block_root = block.message.parent_root;
        }
        chunk_writer.write(&mut io_batch)?;

        // Write the I/O batch to disk.
        self.store.cold_db.do_atomically(io_batch)?;

        // Update the anchor.
        *self.store.anchor_info.write() = Some(AnchorInfo {
            oldest_block_slot: prev_block_slot,
            oldest_block_parent: current_block_root,
            ..anchor_info
        });
        self.store.store_anchor_info()?;

        Ok(())
    }
}
