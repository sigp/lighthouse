use types::*;

#[derive(Debug, PartialEq)]
pub enum EpochProcessingError {
    UnableToDetermineProducer,
    NoBlockRoots,
    BaseRewardQuotientIsZero,
    NoRandaoSeed,
    PreviousTotalBalanceIsZero,
    InclusionDistanceZero,
    ValidatorStatusesInconsistent,
    /// Unable to get the inclusion distance for a validator that should have an inclusion
    /// distance. This indicates an internal inconsistency.
    ///
    /// (validator_index)
    InclusionSlotsInconsistent(usize),
    BeaconStateError(BeaconStateError),
    InclusionError(InclusionError),
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
