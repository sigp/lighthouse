use kzg::{Error as KzgError, KzgCommitment};
use types::{BeaconStateError, ColumnIndex, Hash256};

#[derive(Debug)]
pub enum Error {
    InvalidBlobs(KzgError),
    InvalidColumn(ColumnIndex, KzgError),
    ReconstructColumnsError(KzgError),
    KzgNotInitialized,
    KzgCommitmentMismatch {
        blob_commitment: KzgCommitment,
        block_commitment: KzgCommitment,
    },
    UnableToDetermineImportRequirement,
    Unexpected,
    SszTypes(ssz_types::Error),
    MissingBlobs,
    MissingCustodyColumns,
    BlobIndexInvalid(u64),
    DataColumnIndexInvalid(u64),
    StoreError(store::Error),
    DecodeError(ssz::DecodeError),
    ParentStateMissing(Hash256),
    BlockReplayError(state_processing::BlockReplayError),
    RebuildingStateCaches(BeaconStateError),
    SlotClockError,
}

#[derive(PartialEq, Eq)]
pub enum ErrorCategory {
    /// Internal Errors (not caused by peers).
    ///
    /// An internal non-recoverable error is permanent and block processing should not be
    /// re-attempted.
    Internal { recoverable: bool },
    /// Errors caused by faulty / malicious peers.
    ///
    /// Non-recoverable errors are deterministic against the block's root. Re-downloading data
    /// key-ed by block root MUST result in the same non-recoverable error (i.e. invalid parent,
    /// invalid state root, etc).
    ///
    /// The error also indicates which block component index is malicious if applicable.
    Malicious { recoverable: bool, index: usize },
}

impl ErrorCategory {
    // Helper functions for readibility on large match statements
    pub fn internal_non_recoverable() -> Self {
        Self::Internal { recoverable: false }
    }
    pub fn internal_recoverable() -> Self {
        Self::Internal { recoverable: true }
    }
    pub fn malicious_non_recoverable() -> Self {
        Self::Malicious {
            recoverable: false,
            index: 0,
        }
    }
    pub fn malicious_recoverable() -> Self {
        Self::Malicious {
            recoverable: true,
            index: 0,
        }
    }
}

impl Error {
    pub fn category(&self) -> ErrorCategory {
        match self {
            // KZG is only initialized once
            Error::KzgNotInitialized => ErrorCategory::internal_non_recoverable(),
            Error::SszTypes(_) => ErrorCategory::internal_non_recoverable(),
            // A ChainSegment RpcBlock does not include the expected blobs or columns
            Error::MissingBlobs | Error::MissingCustodyColumns => {
                ErrorCategory::internal_recoverable()
            }
            // Assume these errors to be recoverable
            Error::StoreError(_)
            | Error::DecodeError(_)
            | Error::Unexpected
            | Error::ParentStateMissing(_)
            | Error::BlockReplayError(_)
            | Error::UnableToDetermineImportRequirement
            | Error::RebuildingStateCaches(_)
            | Error::SlotClockError => ErrorCategory::internal_recoverable(),
            // BlobIndexInvalid only happens when serving RPC requests for out of bounds blob indices
            Error::BlobIndexInvalid(_) | Error::DataColumnIndexInvalid(_) => {
                ErrorCategory::malicious_non_recoverable()
            }
            // TODO: Is this error recoverable?
            Error::ReconstructColumnsError { .. } => ErrorCategory::internal_recoverable(),
            // Now we check the inclusion proof for blobs and columns so commitments should never
            // missmatch
            Error::KzgCommitmentMismatch { .. } => ErrorCategory::internal_recoverable(),
            Error::InvalidBlobs { .. } => ErrorCategory::malicious_non_recoverable(),
            Error::InvalidColumn(index, _) => ErrorCategory::Malicious {
                recoverable: false,
                index: *index as usize,
            },
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
