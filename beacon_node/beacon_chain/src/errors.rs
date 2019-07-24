use crate::fork_choice::Error as ForkChoiceError;
use crate::metrics::Error as MetricsError;
use state_processing::BlockProcessingError;
use state_processing::SlotProcessingError;
use types::*;
use state_processing::per_block_processing::errors::{AttestationValidationError, IndexedAttestationValidationError};

macro_rules! easy_from_to {
    ($from: ident, $to: ident) => {
        impl From<$from> for $to {
            fn from(e: $from) -> $to {
                $to::$from(e)
            }
        }
    };
}

#[derive(Debug, PartialEq)]
pub enum BeaconChainError {
    InsufficientValidators,
    BadRecentBlockRoots,
    UnableToReadSlot,
    RevertedFinalizedEpoch {
        previous_epoch: Epoch,
        new_epoch: Epoch,
    },
    BeaconStateError(BeaconStateError),
    DBInconsistent(String),
    DBError(store::Error),
    ForkChoiceError(ForkChoiceError),
    MissingBeaconBlock(Hash256),
    MissingBeaconState(Hash256),
    SlotProcessingError(SlotProcessingError),
    MetricsError(String),
    AttestationValidationError(AttestationValidationError),
    IndexedAttestationValidationError(IndexedAttestationValidationError)
}

easy_from_to!(SlotProcessingError, BeaconChainError);

impl From<MetricsError> for BeaconChainError {
    fn from(e: MetricsError) -> BeaconChainError {
        BeaconChainError::MetricsError(format!("{:?}", e))
    }
}

#[derive(Debug, PartialEq)]
pub enum BlockProductionError {
    UnableToGetBlockRootFromState,
    UnableToReadSlot,
    SlotProcessingError(SlotProcessingError),
    BlockProcessingError(BlockProcessingError),
    BeaconStateError(BeaconStateError),
}

easy_from_to!(BlockProcessingError, BlockProductionError);
easy_from_to!(BeaconStateError, BlockProductionError);
easy_from_to!(SlotProcessingError, BlockProductionError);
easy_from_to!(AttestationValidationError, BeaconChainError);
easy_from_to!(IndexedAttestationValidationError, BeaconChainError);
