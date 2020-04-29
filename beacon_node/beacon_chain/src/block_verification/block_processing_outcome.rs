use crate::{BeaconChainError, BlockError};
use state_processing::BlockProcessingError;
use types::{Hash256, Slot};

/// This is a legacy object that is being kept around to reduce merge conflicts.
///
/// TODO: As soon as this is merged into master, it should be removed as soon as possible.
#[derive(Debug, PartialEq)]
pub enum BlockProcessingOutcome {
    /// Block was valid and imported into the block graph.
    Processed {
        block_root: Hash256,
    },
    InvalidSignature,
    /// The proposal signature in invalid.
    ProposalSignatureInvalid,
    /// The `block.proposal_index` is not known.
    UnknownValidator(u64),
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
    /// A block for this proposer and slot has already been observed.
    RepeatProposal {
        proposer: u64,
        slot: Slot,
    },
    /// The block slot exceeds the MAXIMUM_BLOCK_SLOT_NUMBER.
    BlockSlotLimitReached,
    /// The provided block is from an earlier slot than its parent.
    BlockIsNotLaterThanParent {
        block_slot: Slot,
        state_slot: Slot,
    },
    /// The `BeaconBlock` has a `proposer_index` that does not match the index we computed locally.
    ///
    /// The block is invalid.
    IncorrectBlockProposer {
        block: u64,
        local_shuffling: u64,
    },
    /// At least one block in the chain segement did not have it's parent root set to the root of
    /// the prior block.
    NonLinearParentRoots,
    /// The slots of the blocks in the chain segment were not strictly increasing. I.e., a child
    /// had lower slot than a parent.
    NonLinearSlots,
    /// The block could not be applied to the state, it is invalid.
    PerBlockProcessingError(BlockProcessingError),
}

impl BlockProcessingOutcome {
    pub fn shim(
        result: Result<Hash256, BlockError>,
    ) -> Result<BlockProcessingOutcome, BeaconChainError> {
        match result {
            Ok(block_root) => Ok(BlockProcessingOutcome::Processed { block_root }),
            Err(BlockError::ParentUnknown(root)) => Ok(BlockProcessingOutcome::ParentUnknown(root)),
            Err(BlockError::FutureSlot {
                present_slot,
                block_slot,
            }) => Ok(BlockProcessingOutcome::FutureSlot {
                present_slot,
                block_slot,
            }),
            Err(BlockError::StateRootMismatch { block, local }) => {
                Ok(BlockProcessingOutcome::StateRootMismatch { block, local })
            }
            Err(BlockError::GenesisBlock) => Ok(BlockProcessingOutcome::GenesisBlock),
            Err(BlockError::WouldRevertFinalizedSlot {
                block_slot,
                finalized_slot,
            }) => Ok(BlockProcessingOutcome::WouldRevertFinalizedSlot {
                block_slot,
                finalized_slot,
            }),
            Err(BlockError::BlockIsAlreadyKnown) => Ok(BlockProcessingOutcome::BlockIsAlreadyKnown),
            Err(BlockError::RepeatProposal { proposer, slot }) => {
                Ok(BlockProcessingOutcome::RepeatProposal { proposer, slot })
            }
            Err(BlockError::BlockSlotLimitReached) => {
                Ok(BlockProcessingOutcome::BlockSlotLimitReached)
            }
            Err(BlockError::ProposalSignatureInvalid) => {
                Ok(BlockProcessingOutcome::ProposalSignatureInvalid)
            }
            Err(BlockError::UnknownValidator(i)) => Ok(BlockProcessingOutcome::UnknownValidator(i)),
            Err(BlockError::InvalidSignature) => Ok(BlockProcessingOutcome::InvalidSignature),
            Err(BlockError::BlockIsNotLaterThanParent {
                block_slot,
                state_slot,
            }) => Ok(BlockProcessingOutcome::BlockIsNotLaterThanParent {
                block_slot,
                state_slot,
            }),
            Err(BlockError::IncorrectBlockProposer {
                block,
                local_shuffling,
            }) => Ok(BlockProcessingOutcome::IncorrectBlockProposer {
                block,
                local_shuffling,
            }),
            Err(BlockError::NonLinearParentRoots) => {
                Ok(BlockProcessingOutcome::NonLinearParentRoots)
            }
            Err(BlockError::NonLinearSlots) => Ok(BlockProcessingOutcome::NonLinearSlots),
            Err(BlockError::PerBlockProcessingError(e)) => {
                Ok(BlockProcessingOutcome::PerBlockProcessingError(e))
            }
            Err(BlockError::BeaconChainError(e)) => Err(e),
        }
    }
}
