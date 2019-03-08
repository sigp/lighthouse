use fork_choice::ForkChoiceError;
use state_processing::BlockProcessingError;
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
    BeaconStateError(BeaconStateError),
    DBInconsistent(String),
    DBError(String),
    ForkChoiceError(ForkChoiceError),
    MissingBeaconBlock(Hash256),
    MissingBeaconState(Hash256),
}

#[derive(Debug, PartialEq)]
pub enum BlockProductionError {
    UnableToGetBlockRootFromState,
    BlockProcessingError(BlockProcessingError),
}

easy_from_to!(BlockProcessingError, BlockProductionError);
