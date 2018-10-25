use super::{
    BeaconChain,
    ClientDB,
};
use super::block_context::{
    BlockValidationContextError,
};
use ssz_helpers::ssz_beacon_block::{
    SszBeaconBlock,
    SszBeaconBlockError,
};
use types::{
    Hash256,
};
use validation::block_validation::{
    BeaconBlockStatus,
    SszBeaconBlockValidationError,
};

pub enum BlockProcessingOutcome {
    BlockAlreadyKnown,
    NewCanonicalBlock,
    NewForkBlock,
}

pub enum BlockProcessingError {
    ContextGenerationError(BlockValidationContextError),
    DeserializationFailed(SszBeaconBlockError),
    ValidationFailed(SszBeaconBlockValidationError),
}

impl<T> BeaconChain<T>
    where T: ClientDB + Sized
{
    pub fn process_block(&mut self, ssz: &[u8], present_slot: u64)
        -> Result<(BlockProcessingOutcome, Hash256), BlockProcessingError>
    {
        /*
         * Generate a SszBlock to read directly from the serialized SSZ.
         */
        let ssz_block = SszBeaconBlock::from_slice(ssz)?;
        let block_hash = Hash256::from(&ssz_block.block_hash()[..]);
        let parent_hash = ssz_block.parent_hash()
            .ok_or(BlockProcessingError::ValidationFailed(
                    SszBeaconBlockValidationError::UnknownParentHash))?;

        /*
         * Generate the context in which to validate this block.
         */
        let validation_context = self.block_validation_context(&ssz_block, present_slot)?;

        /*
         * Validate the block against the context, checking signatures, parent_hashes, etc.
         */
        let (block_status, block) = validation_context.validate_ssz_block(&block_hash, &block)?;

        match block_status {
            /*
             *
             */
            BeaconBlockStatus::KnownBlock => {
                Ok((BlockProcessingOutcome::BlockAlreadyKnown, block_hash))
            }
            BeaconBlockStatus::NewBlock => {
                let head_hash_index = {
                    match self.head_block_hashes.iter().position(|x| *x == Hash256::from(parent_hash)) {
                        Some(i) => i,
                        None => {
                            self.head_block_hashes.push(block_hash);
                            self.head_block_hashes.len() - 1
                        }
                    }
                };

                if head_hash_index == self.canonical_head_block_hash {
                    Ok((BlockProcessingOutcome::NewCanonicalBlock, block_hash))
                } else {
                    Ok((BlockProcessingOutcome::NewForkBlock, block_hash))
                }
            }
        }
    }

    pub fn extend_chain(
        &self,
        block: &Block,
        block_hash: &Hash256,
        head_hash_index: usize)
        -> Result<>
}


impl From<BlockValidationContextError> for BlockProcessingError {
    fn from(e: BlockValidationContextError) -> Self {
        BlockProcessingError::ContextGenerationError(e)
    }
}

impl From<SszBeaconBlockError> for BlockProcessingError {
    fn from(e: SszBeaconBlockError) -> Self {
        BlockProcessingError::DeserializationFailed(e)
    }
}

impl From<SszBeaconBlockValidationError> for BlockProcessingError {
    fn from(e: SszBeaconBlockValidationError) -> Self {
        BlockProcessingError::ValidationFailed(e)
    }
}
