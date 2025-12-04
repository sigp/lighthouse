use safe_arith::ArithError;

use crate::state::BeaconStateError;

#[derive(Debug, PartialEq, Clone)]
pub enum LightClientError {
    SszTypesError(ssz_types::Error),
    MilhouseError(milhouse::Error),
    BeaconStateError(BeaconStateError),
    ArithError(ArithError),
    AltairForkNotActive,
    NotEnoughSyncCommitteeParticipants,
    MismatchingPeriods,
    InvalidFinalizedBlock,
    BeaconBlockBodyError,
    InconsistentFork,
}

impl From<ssz_types::Error> for LightClientError {
    fn from(e: ssz_types::Error) -> LightClientError {
        LightClientError::SszTypesError(e)
    }
}

impl From<BeaconStateError> for LightClientError {
    fn from(e: BeaconStateError) -> LightClientError {
        LightClientError::BeaconStateError(e)
    }
}

impl From<ArithError> for LightClientError {
    fn from(e: ArithError) -> LightClientError {
        LightClientError::ArithError(e)
    }
}

impl From<milhouse::Error> for LightClientError {
    fn from(e: milhouse::Error) -> LightClientError {
        LightClientError::MilhouseError(e)
    }
}
