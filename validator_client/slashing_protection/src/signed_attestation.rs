use std::convert::From;
use tree_hash::TreeHash;
use types::{AttestationData, Epoch, Hash256};

#[derive(Clone, Debug, PartialEq)]
pub struct SignedAttestation {
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub signing_root: Hash256,
}

impl SignedAttestation {
    pub fn new(source_epoch: Epoch, target_epoch: Epoch, signing_root: Hash256) -> Self {
        Self {
            source_epoch,
            target_epoch,
            signing_root,
        }
    }

    /// Create a `SignedAttestation` from an SQLite row of `(source, target, signing_root)`.
    pub fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        let source = row.get(0)?;
        let target = row.get(1)?;
        let signing_root: Vec<u8> = row.get(2)?;
        Ok(SignedAttestation::new(
            source,
            target,
            Hash256::from_slice(&signing_root[..]),
        ))
    }
}

impl From<&AttestationData> for SignedAttestation {
    fn from(attestation: &AttestationData) -> Self {
        Self {
            source_epoch: attestation.source.epoch,
            target_epoch: attestation.target.epoch,
            signing_root: attestation.tree_hash_root(),
        }
    }
}

#[derive(PartialEq, Debug)]
pub enum InvalidAttestation {
    DoubleVote(SignedAttestation),
    NewSurroundsPrev { prev: SignedAttestation },
    PrevSurroundsNew { prev: SignedAttestation },
}
