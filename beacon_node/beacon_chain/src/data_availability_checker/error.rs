use kzg::{Error as KzgError, KzgCommitment};
use types::{BeaconStateError, Hash256};

#[derive(Debug)]
pub enum Error {
    Kzg(KzgError),
    KzgNotInitialized,
    KzgVerificationFailed,
    KzgCommitmentMismatch {
        blob_commitment: KzgCommitment,
        block_commitment: KzgCommitment,
    },
    Unexpected,
    SszTypes(ssz_types::Error),
    MissingBlobs,
    BlobIndexInvalid(u64),
    StoreError(store::Error),
    DecodeError(ssz::DecodeError),
    ParentStateMissing(Hash256),
    BlockReplayError(state_processing::BlockReplayError),
    RebuildingStateCaches(BeaconStateError),
    SlotClockError,
}

#[derive(PartialEq, Eq)]
pub enum ErrorCategory {
    /// Internal Errors (not caused by peers)
    Internal,
    /// Errors caused by faulty / malicious peers
    Malicious,
}

impl Error {
    pub fn category(&self) -> ErrorCategory {
        match self {
            Error::KzgNotInitialized
            | Error::SszTypes(_)
            | Error::MissingBlobs
            | Error::StoreError(_)
            | Error::DecodeError(_)
            | Error::Unexpected
            | Error::ParentStateMissing(_)
            | Error::BlockReplayError(_)
            | Error::RebuildingStateCaches(_)
            | Error::SlotClockError => ErrorCategory::Internal,
            Error::Kzg(_)
            | Error::BlobIndexInvalid(_)
            | Error::KzgCommitmentMismatch { .. }
            | Error::KzgVerificationFailed => ErrorCategory::Malicious,
        }
    }
}

impl From<ssz_types::Error> for Error {
    fn from(value: ssz_types::Error) -> Self {
        Self::SszTypes(value)
    }
}

impl From<store::Error> for Error {
    fn from(value: store::Error) -> Self {
        Self::StoreError(value)
    }
}

impl From<ssz::DecodeError> for Error {
    fn from(value: ssz::DecodeError) -> Self {
        Self::DecodeError(value)
    }
}

impl From<state_processing::BlockReplayError> for Error {
    fn from(value: state_processing::BlockReplayError) -> Self {
        Self::BlockReplayError(value)
    }
}

impl From<KzgError> for Error {
    fn from(value: KzgError) -> Self {
        Self::Kzg(value)
    }
}
