use std::io;
use types::{Epoch, Hash256};

#[derive(Debug)]
pub enum Error {
    DatabaseError(lmdb::Error),
    DatabaseIOError(io::Error),
    SszDecodeError(ssz::DecodeError),
    BincodeError(bincode::Error),
    ArithError(safe_arith::ArithError),
    ChunkIndexOutOfBounds(usize),
    ConfigInvalidChunkSize {
        chunk_size: usize,
        history_length: usize,
    },
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
    MissingIndexedAttestation {
        root: Hash256,
    },
}

impl From<lmdb::Error> for Error {
    fn from(e: lmdb::Error) -> Self {
        match e {
            lmdb::Error::Other(os_error) => Error::from(io::Error::from_raw_os_error(os_error)),
            _ => Error::DatabaseError(e),
        }
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
