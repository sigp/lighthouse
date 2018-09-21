use super::block::SszBlock;
use super::Logger;
use super::db::{
    BlockStore,
    PoWChainStore,
};

pub enum BlockStatus {
    NewBlock,
    KnownBlock,
    UnknownPoWChainRef,
}

pub enum SszBlockValidationError {
    SszInvalid,
    FutureSlot,
}

macro_rules! valid_if {
    ($cond:expr, $val:expr) => {
        if ($cond)
            return Ok($val);
        }
    };
}

macro_rules! invalid_if {
    ($cond:expr, $val:expr) => {
        if ($cond)
            return Err($val);
        }
    };
}

fn slot_from_time()


pub fn validate_ssz_block(b: &SszBlock,
                          expected_slot: &u64,
                          block_store: &BlockStore,
                          pow_store: &PoWChainStore,
                          log: &Logger)
    -> Result<BlockStatus, SszBlockValidationError>
{
    valid_if!(block_store.block_exists(b.block_hash()),
              BlockStatus::KnownBlock);

    invalid_if!(b.slot_number() > expected_slot,
                SszBlockValidationError::FutureSlot);

    invalid_if!(pow_store.block_hash_exists(b.pow_chain_ref()) == false,
                SszBlockValidationError::UnknownPoWChainRef);

    // Do validation here
    Ok(BlockStatus::NewBlock)
}
