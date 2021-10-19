mod attestation_tests;
mod block_tests;
pub mod interchange;
pub mod interchange_test;
mod parallel_tests;
mod registration_tests;
mod signed_attestation;
mod signed_block;
mod slashing_database;
pub mod test_utils;

pub use crate::signed_attestation::{InvalidAttestation, SignedAttestation};
pub use crate::signed_block::{InvalidBlock, SignedBlock};
pub use crate::slashing_database::{
    InterchangeError, InterchangeImportOutcome, SlashingDatabase,
    SUPPORTED_INTERCHANGE_FORMAT_VERSION,
};
use rusqlite::Error as SQLError;
use std::io::{Error as IOError, ErrorKind};
use std::string::ToString;
use types::{Hash256, PublicKeyBytes};

/// The filename within the `validators` directory that contains the slashing protection DB.
pub const SLASHING_PROTECTION_FILENAME: &str = "slashing_protection.sqlite";

/// The attestation or block is not safe to sign.
///
/// This could be because it's slashable, or because an error occurred.
#[derive(PartialEq, Debug)]
pub enum NotSafe {
    UnregisteredValidator(PublicKeyBytes),
    InvalidBlock(InvalidBlock),
    InvalidAttestation(InvalidAttestation),
    PermissionsError,
    IOError(ErrorKind),
    SQLError(String),
    SQLPoolError(String),
    ConsistencyError,
}

/// The attestation or block is safe to sign, and will not cause the signer to be slashed.
#[derive(PartialEq, Debug)]
pub enum Safe {
    /// Casting the exact same data (block or attestation) twice is never slashable.
    SameData,
    /// Incoming data is safe from slashing, and is not a duplicate.
    Valid,
}

/// A wrapper for `Hash256` that treats `0x0` as a special null value.
///
/// Notably `SigningRoot(0x0) != SigningRoot(0x0)`. It is `PartialEq` but not `Eq`!
#[derive(Debug, Clone, Copy, Default)]
pub struct SigningRoot(Hash256);

impl PartialEq for SigningRoot {
    fn eq(&self, other: &Self) -> bool {
        !self.is_null() && self.0 == other.0
    }
}

impl From<Hash256> for SigningRoot {
    fn from(hash: Hash256) -> Self {
        SigningRoot(hash)
    }
}

impl Into<Hash256> for SigningRoot {
    fn into(self) -> Hash256 {
        self.0
    }
}

impl SigningRoot {
    fn is_null(&self) -> bool {
        self.0.is_zero()
    }

    fn to_hash256_raw(self) -> Hash256 {
        self.into()
    }

    fn to_hash256(self) -> Option<Hash256> {
        Some(self.0).filter(|_| !self.is_null())
    }
}

/// Safely parse a `SigningRoot` from the given `column` of an SQLite `row`.
fn signing_root_from_row(column: usize, row: &rusqlite::Row) -> rusqlite::Result<SigningRoot> {
    use rusqlite::{types::Type, Error};

    let bytes: Vec<u8> = row.get(column)?;
    if bytes.len() == 32 {
        Ok(SigningRoot::from(Hash256::from_slice(&bytes)))
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
        // Use `Display` impl to print "timed out waiting for connection"
        NotSafe::SQLPoolError(format!("{}", error))
    }
}

impl ToString for NotSafe {
    fn to_string(&self) -> String {
        format!("{:?}", self)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[allow(clippy::eq_op)]
    fn signing_root_partial_eq() {
        let h0 = SigningRoot(Hash256::zero());
        let h1 = SigningRoot(Hash256::repeat_byte(1));
        let h2 = SigningRoot(Hash256::repeat_byte(2));
        assert_ne!(h0, h0);
        assert_ne!(h0, h1);
        assert_ne!(h1, h0);
        assert_eq!(h1, h1);
        assert_ne!(h1, h2);
    }
}
