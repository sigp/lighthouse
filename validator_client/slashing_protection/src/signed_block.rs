use types::{BeaconBlockHeader, Hash256, Slot};

#[derive(PartialEq, Debug)]
pub enum InvalidBlock {
    DoubleBlockProposal(SignedBlock),
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignedBlock {
    pub slot: Slot,
    pub signing_root: Hash256,
}

impl SignedBlock {
    pub fn new(slot: Slot, signing_root: Hash256) -> Self {
        Self { slot, signing_root }
    }

    pub fn from(header: &BeaconBlockHeader) -> Self {
        Self {
            slot: header.slot,
            signing_root: header.canonical_root(),
        }
    }

    /// Parse an SQLite row of `(slot, signing_root)`.
    pub fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        let slot = row.get(0)?;
        let signing_bytes: Vec<u8> = row.get(1)?;
        Ok(SignedBlock {
            slot,
            signing_root: Hash256::from_slice(&signing_bytes),
        })
    }
}
