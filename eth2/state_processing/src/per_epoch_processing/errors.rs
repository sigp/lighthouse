use types::*;

#[derive(Debug, PartialEq)]
pub enum WinningRootError {
    NoWinningRoot,
    BeaconStateError(BeaconStateError),
}

#[derive(Debug, PartialEq)]
pub enum EpochProcessingError {
    UnableToDetermineProducer,
    NoBlockRoots,
    BaseRewardQuotientIsZero,
    NoRandaoSeed,
    BeaconStateError(BeaconStateError),
    InclusionError(InclusionError),
    WinningRootError(WinningRootError),
}

impl From<InclusionError> for EpochProcessingError {
    fn from(e: InclusionError) -> EpochProcessingError {
        EpochProcessingError::InclusionError(e)
    }
}

impl From<BeaconStateError> for EpochProcessingError {
    fn from(e: BeaconStateError) -> EpochProcessingError {
        EpochProcessingError::BeaconStateError(e)
    }
}

impl From<BeaconStateError> for WinningRootError {
    fn from(e: BeaconStateError) -> WinningRootError {
        WinningRootError::BeaconStateError(e)
    }
}
