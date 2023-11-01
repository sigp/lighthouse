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
    InconsistentBlobBlockRoots {
        block_root: Hash256,
        blob_block_root: Hash256,
    },
    ParentStateMissing(Hash256),
    BlockReplayError(state_processing::BlockReplayError),
    RebuildingStateCaches(BeaconStateError),
}

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
            | Error::RebuildingStateCaches(_) => ErrorCategory::Internal,
            Error::Kzg(_)
            | Error::BlobIndexInvalid(_)
            | Error::KzgCommitmentMismatch { .. }
            | Error::KzgVerificationFailed
            | Error::InconsistentBlobBlockRoots { .. } => ErrorCategory::Malicious,
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
