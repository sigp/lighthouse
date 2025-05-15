use kzg::{Error as KzgError, KzgCommitment};
use types::{BeaconStateError, ColumnIndex};

#[derive(Debug)]
pub enum Error {
    InvalidBlobs(KzgError),
    InvalidColumn(Vec<(ColumnIndex, KzgError)>),
    KzgCommitmentMismatch {
        blob_commitment: KzgCommitment,
        block_commitment: KzgCommitment,
    },
    Unexpected(String),
    MissingBlobs,
    MissingCustodyColumns(Vec<ColumnIndex>),
    BlobIndexInvalid(u64),
    DataColumnIndexInvalid(u64),
    StoreError(store::Error),
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
            Error::StoreError(_)
            | Error::Unexpected(_)
            | Error::BlockReplayError(_)
            | Error::RebuildingStateCaches(_)
            | Error::SlotClockError => ErrorCategory::Internal,
            Error::MissingBlobs
            | Error::MissingCustodyColumns(_)
            | Error::InvalidBlobs { .. }
            | Error::InvalidColumn { .. }
            | Error::BlobIndexInvalid(_)
            | Error::DataColumnIndexInvalid(_)
            | Error::KzgCommitmentMismatch { .. } => ErrorCategory::Malicious,
        }
    }
}

impl From<store::Error> for Error {
    fn from(value: store::Error) -> Self {
        Self::StoreError(value)
    }
}

impl From<state_processing::BlockReplayError> for Error {
    fn from(value: state_processing::BlockReplayError) -> Self {
        Self::BlockReplayError(value)
    }
}
