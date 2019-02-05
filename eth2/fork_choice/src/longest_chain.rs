extern crate db;
extern crate ssz;
extern crate types;

use db::stores::BeaconBlockStore;
use db::{ClientDB, DBError};
use ssz::{Decodable, DecodeError};
use std::sync::Arc;
use types::{BeaconBlock, Hash256};

pub enum ForkChoiceError {
    BadSszInDatabase,
    MissingBlock,
    DBError(String),
}

pub fn longest_chain<T>(
    head_block_hashes: &[Hash256],
    block_store: &Arc<BeaconBlockStore<T>>,
) -> Result<Option<usize>, ForkChoiceError>
where
    T: ClientDB + Sized,
{
    let mut head_blocks: Vec<(usize, BeaconBlock)> = vec![];

    /*
     * Load all the head_block hashes from the DB as SszBeaconBlocks.
     */
    for (index, block_hash) in head_block_hashes.iter().enumerate() {
        let ssz = block_store
            .get(&block_hash)?
            .ok_or(ForkChoiceError::MissingBlock)?;
        let (block, _) = BeaconBlock::ssz_decode(&ssz, 0)?;
        head_blocks.push((index, block));
    }

    /*
     * Loop through all the head blocks and find the highest slot.
     */
    let highest_slot: Option<u64> = None;
    for (_, block) in &head_blocks {
        let slot = block.slot;

        match highest_slot {
            None => Some(slot),
            Some(winning_slot) => {
                if slot > winning_slot {
                    Some(slot)
                } else {
                    Some(winning_slot)
                }
            }
        };
    }

    /*
     * Loop through all the highest blocks and sort them by highest hash.
     *
     * Ultimately, the index of the head_block hash with the highest slot and highest block
     * hash will be the winner.
     */
    match highest_slot {
        None => Ok(None),
        Some(highest_slot) => {
            let mut highest_blocks = vec![];
            for (index, block) in head_blocks {
                if block.slot == highest_slot {
                    highest_blocks.push((index, block))
                }
            }

            highest_blocks.sort_by(|a, b| head_block_hashes[a.0].cmp(&head_block_hashes[b.0]));
            let (index, _) = highest_blocks[0];
            Ok(Some(index))
        }
    }
}

impl From<DecodeError> for ForkChoiceError {
    fn from(_: DecodeError) -> Self {
        ForkChoiceError::BadSszInDatabase
    }
}

impl From<DBError> for ForkChoiceError {
    fn from(e: DBError) -> Self {
        ForkChoiceError::DBError(e.message)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_naive_fork_choice() {
        assert_eq!(2 + 2, 4);
    }
}
