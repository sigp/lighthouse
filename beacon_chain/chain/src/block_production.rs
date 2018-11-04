use super::BeaconChain;
use db::{ClientDB, DBError};
use ssz_helpers::ssz_beacon_block::{SszBeaconBlock, SszBeaconBlockError};
use types::{BeaconBlock, Hash256};

pub enum BlockProductionError {
    UnableToLoadAncestor,
    DBError,
    Cats,
}

pub enum SkipListError {
    UnableToLoadAncestor,
    AncestorSszInvalid,
    MalformedBlock,
    DBError(String),
}

impl<T> BeaconChain<T>
where
    T: ClientDB + Sized,
{
    pub fn produce_block_at_slot(
        &self,
        slot: u64,
        parent_block: &BeaconBlock,
        parent_block_hash: &Hash256,
        randao_reveal: Hash256,
        pow_chain_reference: Hash256,
    ) -> Result<BeaconBlock, BlockProductionErorr> {
        Ok(BeaconBlock {
            slot,
            randao_reveal,
            pow_chain_reference,
        })
        // cats
    }

    pub fn build_skip_list(
        &self,
        parent_block_slot: u64,
        parent_block_hash: &Hash256,
        source_slot: u64,
    ) -> Result<Vec<Hash256>, SkipListError> {
        let mut i = 0;
        let mut vec = vec![];

        while i < 32 {
            let mut target_slot = source_slot.saturating_sub(2_u64.pow(i));

            match parent_block_slot {
                /*
                 * If the parent block slot is higher than the target, find a new parent without
                 * incrementing `i`.
                 */
                slot if slot > target_slot => {
                    let (parent_block_slot, parent_block_hash) = {
                        /*
                         * Read the _present_ parent block from the database and learn its parent,
                         * this will become the _new_ parent block hash.
                         */
                        let new_parent_block_hash = {
                            let ssz = self
                                .store
                                .block
                                .get_serialized_block(&parent_block_hash[..])?
                                .ok_or(SkipListError::UnableToLoadAncestor)?;
                            let ssz_block = SszBeaconBlock::from_slice(&ssz)?;
                            ssz_block
                                .parent_hash()
                                .ok_or(SkipListError::MalformedBlock)?
                        };
                        /*
                         * Using the _new_ parent block hash, read the block from the database and
                         * learn the _new_ parent block slot.
                         */
                        let new_parent_block_slot = {
                            let ssz = self
                                .store
                                .block
                                .get_serialized_block(&parent_block_hash[..])?
                                .ok_or(SkipListError::UnableToLoadAncestor)?;
                            let ssz_block = SszBeaconBlock::from_slice(&ssz)?;
                            ssz_block.slot()
                        };
                        (new_parent_block_slot, new_parent_block_slot)
                    };
                }
                /*
                 * If the block slot matches the target, add its hash to the list and increment
                 * `i`.
                 */
                slot if slot == target_slot => {
                    vec.push(parent_block_hash.clone());
                    i += 1;
                }
                /*
                 * If the block slot is lower than the target slot, push an all-zeros hash into the
                 * list and increment `i`.
                 */
                slot if slot <= target_slot => {
                    vec.push(Hash256::zero());
                    i += 1;
                }
            }
        }
        Ok(vec)
    }
}

impl From<DBError> for SkipListError {
    fn from(e: DBError) -> Self {
        SkipListError::DBError(e.message)
    }
}

impl From<SszBeaconBlockError> for SkipListError {
    fn from(e: SszBeaconBlockError) -> Self {
        SkipListError::AncestorSszInvalid
    }
}
