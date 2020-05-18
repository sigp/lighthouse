use crate::hash256_from_row;
use types::{AttestationData, Epoch, Hash256, SignedRoot};

/// An attestation that has previously been signed.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedAttestation {
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub signing_root: Hash256,
}

/// Reasons why an attestation may be slashable (or invalid).
#[derive(PartialEq, Debug)]
pub enum InvalidAttestation {
    /// The attestation has the same target epoch as an attestation from the DB (enclosed).
    DoubleVote(SignedAttestation),
    /// The attestation surrounds an existing attestation from the database (`prev`).
    NewSurroundsPrev { prev: SignedAttestation },
    /// The attestation is surrounded by an existing attestation from the database (`prev`).
    PrevSurroundsNew { prev: SignedAttestation },
    /// The attestation is invalid because its source epoch is greater than its target epoch.
    SourceExceedsTarget,
}

impl SignedAttestation {
    pub fn new(source_epoch: Epoch, target_epoch: Epoch, signing_root: Hash256) -> Self {
        Self {
            source_epoch,
            target_epoch,
            signing_root,
        }
    }

    /// Create a `SignedAttestation` from attestation data and a domain.
    pub fn from_attestation(attestation: &AttestationData, domain: Hash256) -> Self {
        Self {
            source_epoch: attestation.source.epoch,
            target_epoch: attestation.target.epoch,
            signing_root: attestation.signing_root(domain),
        }
    }

    /// Create a `SignedAttestation` from an SQLite row of `(source, target, signing_root)`.
    pub fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        let source = row.get(0)?;
        let target = row.get(1)?;
        let signing_root = hash256_from_row(2, row)?;
        Ok(SignedAttestation::new(source, target, signing_root))
    }
}
