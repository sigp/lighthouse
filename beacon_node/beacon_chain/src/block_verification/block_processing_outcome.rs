use crate::{BeaconChainError, BlockError};
use state_processing::BlockProcessingError;
use types::{Hash256, Slot};

/// This is a legacy object that is being kept around to reduce merge conflicts.
///
/// As soon as this is merged into master, it should be removed as soon as possible.
#[derive(Debug, PartialEq)]
pub enum BlockProcessingOutcome {
    /// Block was valid and imported into the block graph.
    Processed {
        block_root: Hash256,
    },
    InvalidSignature,
    /// The parent block was unknown.
    ParentUnknown(Hash256),
    /// The block slot is greater than the present slot.
    FutureSlot {
        present_slot: Slot,
        block_slot: Slot,
    },
    /// The block state_root does not match the generated state.
    StateRootMismatch {
        block: Hash256,
        local: Hash256,
    },
    /// The block was a genesis block, these blocks cannot be re-imported.
    GenesisBlock,
    /// The slot is finalized, no need to import.
    WouldRevertFinalizedSlot {
        block_slot: Slot,
        finalized_slot: Slot,
    },
    /// Block is already known, no need to re-import.
    BlockIsAlreadyKnown,
    /// The block slot exceeds the MAXIMUM_BLOCK_SLOT_NUMBER.
    BlockSlotLimitReached,
    /// The block could not be applied to the state, it is invalid.
    PerBlockProcessingError(BlockProcessingError),
}

impl BlockProcessingOutcome {
    pub fn shim(
        result: Result<Hash256, BlockError>,
    ) -> Result<BlockProcessingOutcome, BeaconChainError> {
        match result {
            Ok(block_root) => Ok(BlockProcessingOutcome::Processed { block_root }),
            Err(BlockError::BeaconChainError(e)) => Err(e),
            Err(BlockError::InvalidSignature) => Ok(BlockProcessingOutcome::InvalidSignature),
            _ => todo!(),
        }
    }
}
