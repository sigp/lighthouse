mod attestation_tests;
mod block_tests;
mod parallel_tests;
mod signed_attestation;
mod signed_block;
mod slashing_database;
mod test_utils;

pub use crate::signed_attestation::{InvalidAttestation, SignedAttestation};
pub use crate::signed_block::{InvalidBlock, SignedBlock};
pub use crate::slashing_database::SlashingDatabase;
use rusqlite::Error as SQLError;
use std::io::{Error as IOError, ErrorKind};
use std::string::ToString;
use types::PublicKey;

impl From<IOError> for NotSafe {
    fn from(error: IOError) -> NotSafe {
        NotSafe::IOError(error.kind())
    }
}

impl From<SQLError> for NotSafe {
    fn from(error: SQLError) -> NotSafe {
        NotSafe::SQLError(error.to_string())
    }
}

impl From<r2d2::Error> for NotSafe {
    fn from(error: r2d2::Error) -> Self {
        NotSafe::SQLPoolError(format!("{:?}", error))
    }
}

impl ToString for NotSafe {
    fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}

#[derive(PartialEq, Debug)]
pub enum NotSafe {
    UnregisteredValidator(PublicKey),
    InvalidBlock(InvalidBlock),
    InvalidAttestation(InvalidAttestation),
    IOError(ErrorKind),
    SQLError(String),
    SQLPoolError(String),
}

#[derive(PartialEq, Debug)]
pub enum Safe {
    /// Casting the exact same data (block or attestation) twice is never slashable.
    SameData,
    /// Incoming data is safe from slashing, and is not a duplicate.
    Valid,
}
