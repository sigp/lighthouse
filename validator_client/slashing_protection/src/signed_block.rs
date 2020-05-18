use crate::hash256_from_row;
use types::{BeaconBlockHeader, Hash256, SignedRoot, Slot};

/// A block that has previously been signed.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedBlock {
    pub slot: Slot,
    pub signing_root: Hash256,
}

/// Reasons why a block may be slashable.
#[derive(PartialEq, Debug)]
pub enum InvalidBlock {
    DoubleBlockProposal(SignedBlock),
}

impl SignedBlock {
    pub fn new(slot: Slot, signing_root: Hash256) -> Self {
        Self { slot, signing_root }
    }

    pub fn from_header(header: &BeaconBlockHeader, domain: Hash256) -> Self {
        Self {
            slot: header.slot,
            signing_root: header.signing_root(domain),
        }
    }

    /// Parse an SQLite row of `(slot, signing_root)`.
    pub fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        let slot = row.get(0)?;
        let signing_root = hash256_from_row(1, row)?;
        Ok(SignedBlock { slot, signing_root })
    }
}
