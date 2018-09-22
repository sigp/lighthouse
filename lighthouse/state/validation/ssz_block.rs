use super::block::SszBlock;
use super::Logger;
use super::db::{
    ClientDB,
    DBError,
};
use super::db::stores::{
    BlockStore,
    PoWChainStore,
    ValidatorStore,
};

pub enum BlockStatus {
    NewBlock,
    KnownBlock,
}

pub enum SszBlockValidationError {
    FutureSlot,
    UnknownPoWChainRef,
    DatabaseError(String),
}

impl From<DBError> for SszBlockValidationError {
    fn from(e: DBError) -> SszBlockValidationError {
        SszBlockValidationError::DatabaseError(e.message)
    }
}

#[allow(dead_code)]
pub fn validate_ssz_block<T>(b: &SszBlock,
                             expected_slot: u64,
                             block_store: &BlockStore<T>,
                             pow_store: &PoWChainStore<T>,
                             _validator_store: &ValidatorStore<T>,
                             _log: &Logger)
    -> Result<BlockStatus, SszBlockValidationError>
    where T: ClientDB + Sized
{
    if block_store.block_exists(&b.block_hash())? {
        return Ok(BlockStatus::KnownBlock);
    }

    if b.slot_number() > expected_slot {
        return Err(SszBlockValidationError::FutureSlot);
    }

    if pow_store.block_hash_exists(b.pow_chain_ref())? == false {
        return Err(SszBlockValidationError::UnknownPoWChainRef);
    }

    // Do validation here
    Ok(BlockStatus::NewBlock)
}
