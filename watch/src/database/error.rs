use bls::Error as BlsError;
use diesel::result::{ConnectionError, Error as PgError};
use eth2::SensitiveError;
use r2d2::Error as PoolError;
use std::fmt;
use types::BeaconStateError;

#[derive(Debug)]
pub enum Error {
    BeaconState(BeaconStateError),
    Database(PgError),
    DatabaseCorrupted,
    InvalidSig(BlsError),
    PostgresConnection(ConnectionError),
    Pool(PoolError),
    SensitiveUrl(SensitiveError),
    InvalidRoot,
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BeaconStateError> for Error {
    fn from(e: BeaconStateError) -> Self {
        Error::BeaconState(e)
    }
}

impl From<ConnectionError> for Error {
    fn from(e: ConnectionError) -> Self {
        Error::PostgresConnection(e)
    }
}

impl From<PgError> for Error {
    fn from(e: PgError) -> Self {
        Error::Database(e)
    }
}

impl From<PoolError> for Error {
    fn from(e: PoolError) -> Self {
        Error::Pool(e)
    }
}

impl From<BlsError> for Error {
    fn from(e: BlsError) -> Self {
        Error::InvalidSig(e)
    }
}
