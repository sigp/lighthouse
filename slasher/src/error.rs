use crate::config::{Config, DiskConfig};
use std::io;
use types::Epoch;

#[derive(Debug)]
pub enum Error {
    #[cfg(feature = "mdbx")]
    DatabaseMdbxError(mdbx::Error),
    #[cfg(feature = "lmdb")]
    DatabaseLmdbError(lmdb::Error),
    #[cfg(feature = "redb")]
    DatabaseRedbError(redb::Error),
    SlasherDatabaseBackendDisabled,
    MismatchedDatabaseVariant,
    DatabaseIOError(io::Error),
    DatabasePermissionsError(filesystem::Error),
    SszDecodeError(ssz::DecodeError),
    SszTypesError(ssz_types::Error),
    BincodeError(bincode::Error),
    ArithError(safe_arith::ArithError),
    ChunkIndexOutOfBounds(usize),
    IncompatibleSchemaVersion {
        database_schema_version: u64,
        software_schema_version: u64,
    },
    ConfigInvalidChunkSize {
        chunk_size: usize,
        history_length: usize,
    },
    ConfigInvalidHistoryLength {
        history_length: usize,
        max_history_length: usize,
    },
    ConfigInvalidZeroParameter {
        config: Config,
    },
    ConfigIncompatible {
        on_disk_config: DiskConfig,
        config: DiskConfig,
    },
    ConfigMissing,
    DistanceTooLarge,
    DistanceCalculationOverflow,
    /// Missing an attester record that we expected to exist.
    MissingAttesterRecord {
        validator_index: u64,
        target_epoch: Epoch,
    },
    AttesterRecordCorrupt {
        length: usize,
    },
    AttesterKeyCorrupt {
        length: usize,
    },
    ProposerKeyCorrupt {
        length: usize,
    },
    IndexedAttestationIdKeyCorrupt {
        length: usize,
    },
    IndexedAttestationIdCorrupt {
        length: usize,
    },
    MissingIndexedAttestation {
        id: u64,
    },
    MissingAttesterKey,
    MissingProposerKey,
    MissingIndexedAttestationId,
    MissingIndexedAttestationIdKey,
    InconsistentAttestationDataRoot,
    MissingKey,
}

#[cfg(feature = "mdbx")]
impl From<mdbx::Error> for Error {
    fn from(e: mdbx::Error) -> Self {
        match e {
            mdbx::Error::Other(os_error) => Error::from(io::Error::from_raw_os_error(os_error)),
            _ => Error::DatabaseMdbxError(e),
        }
    }
}

#[cfg(feature = "lmdb")]
impl From<lmdb::Error> for Error {
    fn from(e: lmdb::Error) -> Self {
        match e {
            lmdb::Error::Other(os_error) => Error::from(io::Error::from_raw_os_error(os_error)),
            _ => Error::DatabaseLmdbError(e),
        }
    }
}

#[cfg(feature = "redb")]
impl From<redb::TableError> for Error {
    fn from(e: redb::TableError) -> Self {
        Error::DatabaseRedbError(e.into())
    }
}

#[cfg(feature = "redb")]
impl From<redb::TransactionError> for Error {
    fn from(e: redb::TransactionError) -> Self {
        Error::DatabaseRedbError(e.into())
    }
}

#[cfg(feature = "redb")]
impl From<redb::DatabaseError> for Error {
    fn from(e: redb::DatabaseError) -> Self {
        Error::DatabaseRedbError(e.into())
    }
}

#[cfg(feature = "redb")]
impl From<redb::StorageError> for Error {
    fn from(e: redb::StorageError) -> Self {
        Error::DatabaseRedbError(e.into())
    }
}

#[cfg(feature = "redb")]
impl From<redb::CommitError> for Error {
    fn from(e: redb::CommitError) -> Self {
        Error::DatabaseRedbError(e.into())
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::DatabaseIOError(e)
    }
}

impl From<ssz::DecodeError> for Error {
    fn from(e: ssz::DecodeError) -> Self {
        Error::SszDecodeError(e)
    }
}

impl From<ssz_types::Error> for Error {
    fn from(e: ssz_types::Error) -> Self {
        Error::SszTypesError(e)
    }
}

impl From<bincode::Error> for Error {
    fn from(e: bincode::Error) -> Self {
        Error::BincodeError(e)
    }
}

impl From<safe_arith::ArithError> for Error {
    fn from(e: safe_arith::ArithError) -> Self {
        Error::ArithError(e)
    }
}
