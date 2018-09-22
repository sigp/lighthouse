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
    SszInvalid,
    FutureSlot,
    UnknownPoWChainRef,
    DatabaseError(String),
}

impl From<DBError> for SszBlockValidationError {
    fn from(e: DBError) -> SszBlockValidationError {
        SszBlockValidationError::DatabaseError(e.message)
    }
}


pub fn validate_ssz_block<T>(b: &SszBlock,
                          expected_slot: u64,
                          block_store: &BlockStore<T>,
                          pow_store: &PoWChainStore<T>,
                          validator_store: &ValidatorStore<T>,
                          log: &Logger)
    -> Result<BlockStatus, SszBlockValidationError>
    where T: Sized + ClientDB
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
