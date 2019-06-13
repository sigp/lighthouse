use crate::metrics::Error as MetricsError;
use fork_choice::ForkChoiceError;
use state_processing::BlockProcessingError;
use state_processing::SlotProcessingError;
use types::*;

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
    BeaconStateError(BeaconStateError),
    DBInconsistent(String),
    DBError(store::Error),
    ForkChoiceError(ForkChoiceError),
    MissingBeaconBlock(Hash256),
    MissingBeaconState(Hash256),
    SlotProcessingError(SlotProcessingError),
    MetricsError(String),
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
    BlockProcessingError(BlockProcessingError),
    BeaconStateError(BeaconStateError),
}

easy_from_to!(BlockProcessingError, BlockProductionError);
easy_from_to!(BeaconStateError, BlockProductionError);
