use crate::{signing_root_from_row, SigningRoot};
use types::{BeaconBlockHeader, Hash256, SignedRoot, Slot};

/// A block that has previously been signed.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedBlock {
    pub slot: Slot,
    pub signing_root: SigningRoot,
}

/// Reasons why a block may be slashable.
#[derive(PartialEq, Debug)]
pub enum InvalidBlock {
    DoubleBlockProposal(SignedBlock),
    SlotViolatesLowerBound { block_slot: Slot, bound_slot: Slot },
}

impl SignedBlock {
    pub fn new(slot: Slot, signing_root: SigningRoot) -> Self {
        Self { slot, signing_root }
    }

    pub fn from_header(header: &BeaconBlockHeader, domain: Hash256) -> Self {
        Self {
            slot: header.slot,
            signing_root: header.signing_root(domain).into(),
        }
    }

    /// Parse an SQLite row of `(slot, signing_root)`.
    pub fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        let slot = row.get(0)?;
        let signing_root = signing_root_from_row(1, row)?;
        Ok(SignedBlock { slot, signing_root })
    }
}
