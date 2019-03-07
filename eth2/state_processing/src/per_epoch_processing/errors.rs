use types::*;

#[derive(Debug, PartialEq)]
pub enum EpochProcessingError {
    UnableToDetermineProducer,
    NoBlockRoots,
    BaseRewardQuotientIsZero,
    NoRandaoSeed,
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
