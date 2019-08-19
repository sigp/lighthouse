use crate::chunked_vector::ChunkError;
use crate::hot_cold_store::HotColdDbError;
use ssz::DecodeError;
use types::BeaconStateError;

#[derive(Debug, PartialEq)]
pub enum Error {
    SszDecodeError(DecodeError),
    VectorChunkError(ChunkError),
    BeaconStateError(BeaconStateError),
    PartialBeaconStateError,
    HotColdDbError(HotColdDbError),
    DBError { message: String },
}

impl From<DecodeError> for Error {
    fn from(e: DecodeError) -> Error {
        Error::SszDecodeError(e)
    }
}

impl From<ChunkError> for Error {
    fn from(e: ChunkError) -> Error {
        Error::VectorChunkError(e)
    }
}

impl From<HotColdDbError> for Error {
    fn from(e: HotColdDbError) -> Error {
        Error::HotColdDbError(e)
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Error {
        Error::BeaconStateError(e)
    }
}

impl From<DBError> for Error {
    fn from(e: DBError) -> Error {
        Error::DBError { message: e.message }
    }
}

#[derive(Debug)]
pub struct DBError {
    pub message: String,
}

impl DBError {
    pub fn new(message: String) -> Self {
        Self { message }
    }
}
