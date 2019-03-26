use crate::{ForkChoice, ForkChoiceError};
use db::{stores::BeaconBlockStore, ClientDB};
use std::sync::Arc;
use types::{BeaconBlock, ChainSpec, Hash256, Slot};

pub struct LongestChain<T>
where
    T: ClientDB + Sized,
{
    /// List of head block hashes
    head_block_hashes: Vec<Hash256>,
    /// Block storage access.
    block_store: Arc<BeaconBlockStore<T>>,
}

impl<T> LongestChain<T>
where
    T: ClientDB + Sized,
{
    pub fn new(block_store: Arc<BeaconBlockStore<T>>) -> Self {
        LongestChain {
            head_block_hashes: Vec::new(),
            block_store,
        }
    }
}

impl<T: ClientDB + Sized> ForkChoice for LongestChain<T> {
    fn add_block(
        &mut self,
        block: &BeaconBlock,
        block_hash: &Hash256,
        _: &ChainSpec,
    ) -> Result<(), ForkChoiceError> {
        // add the block hash to head_block_hashes removing the parent if it exists
        self.head_block_hashes
            .retain(|hash| *hash != block.previous_block_root);
        self.head_block_hashes.push(*block_hash);
        Ok(())
    }

    fn add_attestation(
        &mut self,
        _: u64,
        _: &Hash256,
        _: &ChainSpec,
    ) -> Result<(), ForkChoiceError> {
        // do nothing
        Ok(())
    }

    fn find_head(&mut self, _: &Hash256, _: &ChainSpec) -> Result<Hash256, ForkChoiceError> {
        let mut head_blocks: Vec<(usize, BeaconBlock)> = vec![];
        /*
         * Load all the head_block hashes from the DB as SszBeaconBlocks.
         */
        for (index, block_hash) in self.head_block_hashes.iter().enumerate() {
            let block = self
                .block_store
                .get_deserialized(&block_hash)?
                .ok_or_else(|| ForkChoiceError::MissingBeaconBlock(*block_hash))?;
            head_blocks.push((index, block));
        }

        /*
         * Loop through all the head blocks and find the highest slot.
         */
        let highest_slot = head_blocks
            .iter()
            .fold(Slot::from(0u64), |highest, (_, block)| {
                std::cmp::max(block.slot, highest)
            });

        // if we find no blocks, return Error
        if highest_slot == 0 {
            return Err(ForkChoiceError::HeadNotFound);
        }

        /*
         * Loop through all the highest blocks and sort them by highest hash.
         *
         * Ultimately, the index of the head_block hash with the highest slot and highest block
         * hash will be the winner.
         */

        let head_index: Option<usize> =
            head_blocks
                .iter()
                .fold(None, |smallest_index, (index, block)| {
                    if block.slot == highest_slot {
                        if smallest_index.is_none() {
                            return Some(*index);
                        }
                        return Some(std::cmp::min(
                            *index,
                            smallest_index.expect("Cannot be None"),
                        ));
                    }
                    smallest_index
                });

        if head_index.is_none() {
            return Err(ForkChoiceError::HeadNotFound);
        }

        Ok(self.head_block_hashes[head_index.unwrap()])
    }
}
