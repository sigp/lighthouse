use types::{milhouse, BeaconStateError, EpochCacheError, InconsistentFork};

#[derive(Debug, PartialEq)]
pub enum EpochProcessingError {
    UnableToDetermineProducer,
    NoBlockRoots,
    BaseRewardQuotientIsZero,
    NoRandaoSeed,
    PreviousTotalBalanceIsZero,
    InclusionDistanceZero,
    ValidatorStatusesInconsistent,
    DeltasInconsistent,
    DeltaOutOfBounds(usize),
    /// Unable to get the inclusion distance for a validator that should have an inclusion
    /// distance. This indicates an internal inconsistency.
    ///
    /// (validator_index)
    InclusionSlotsInconsistent(usize),
    BeaconStateError(BeaconStateError),
    InclusionError(InclusionError),
    SszTypesError(ssz_types::Error),
    ArithError(safe_arith::ArithError),
    InconsistentStateFork(InconsistentFork),
    InvalidJustificationBit(ssz_types::Error),
    InvalidFlagIndex(usize),
    MilhouseError(milhouse::Error),
    EpochCache(EpochCacheError),
    SinglePassMissingActivationQueue,
    MissingEarliestExitEpoch,
    MissingExitBalanceToConsume,
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

impl From<ssz_types::Error> for EpochProcessingError {
    fn from(e: ssz_types::Error) -> EpochProcessingError {
        EpochProcessingError::SszTypesError(e)
    }
}

impl From<safe_arith::ArithError> for EpochProcessingError {
    fn from(e: safe_arith::ArithError) -> EpochProcessingError {
        EpochProcessingError::ArithError(e)
    }
}

impl From<milhouse::Error> for EpochProcessingError {
    fn from(e: milhouse::Error) -> Self {
        Self::MilhouseError(e)
    }
}

impl From<EpochCacheError> for EpochProcessingError {
    fn from(e: EpochCacheError) -> Self {
        EpochProcessingError::EpochCache(e)
    }
}

#[derive(Debug, PartialEq)]
pub enum InclusionError {
    /// The validator did not participate in an attestation in this period.
    NoAttestationsForValidator,
    BeaconStateError(BeaconStateError),
}

impl From<BeaconStateError> for InclusionError {
    fn from(e: BeaconStateError) -> InclusionError {
        InclusionError::BeaconStateError(e)
    }
}
