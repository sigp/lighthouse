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
use types::{Hash256, PublicKey};

/// The attestation or block is not safe to sign.
///
/// This could be because it's slashable, or because an error occurred.
#[derive(PartialEq, Debug)]
pub enum NotSafe {
    UnregisteredValidator(PublicKey),
    InvalidBlock(InvalidBlock),
    InvalidAttestation(InvalidAttestation),
    IOError(ErrorKind),
    SQLError(String),
    SQLPoolError(String),
}

/// The attestation or block is safe to sign, and will not cause the signer to be slashed.
#[derive(PartialEq, Debug)]
pub enum Safe {
    /// Casting the exact same data (block or attestation) twice is never slashable.
    SameData,
    /// Incoming data is safe from slashing, and is not a duplicate.
    Valid,
}

/// Safely parse a `Hash256` from the given `column` of an SQLite `row`.
fn hash256_from_row(column: usize, row: &rusqlite::Row) -> rusqlite::Result<Hash256> {
    use rusqlite::{types::Type, Error};

    let bytes: Vec<u8> = row.get(column)?;
    if bytes.len() == 32 {
        Ok(Hash256::from_slice(&bytes))
    } else {
        Err(Error::FromSqlConversionFailure(
            column,
            Type::Blob,
            Box::from(format!("Invalid length for Hash256: {}", bytes.len())),
        ))
    }
}

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
