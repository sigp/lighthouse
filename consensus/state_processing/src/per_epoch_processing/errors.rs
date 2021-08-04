use crate::per_epoch_processing::altair::participation_cache::Error as ParticipationCacheError;
use types::{BeaconStateError, InconsistentFork};

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
    ParticipationCache(ParticipationCacheError),
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

impl From<ParticipationCacheError> for EpochProcessingError {
    fn from(e: ParticipationCacheError) -> EpochProcessingError {
        EpochProcessingError::ParticipationCache(e)
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
