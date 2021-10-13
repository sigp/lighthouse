use crate::{signing_root_from_row, SigningRoot};
use types::{AttestationData, Epoch, Hash256, SignedRoot};

/// An attestation that has previously been signed.
#[derive(Clone, Debug, PartialEq)]
pub struct SignedAttestation {
    pub source_epoch: Epoch,
    pub target_epoch: Epoch,
    pub signing_root: SigningRoot,
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
    /// The attestation is invalid because its source epoch is less than the lower bound on source
    /// epochs for this validator.
    SourceLessThanLowerBound {
        source_epoch: Epoch,
        bound_epoch: Epoch,
    },
    /// The attestation is invalid because its target epoch is less than or equal to the lower
    /// bound on target epochs for this validator.
    TargetLessThanOrEqLowerBound {
        target_epoch: Epoch,
        bound_epoch: Epoch,
    },
}

impl SignedAttestation {
    pub fn new(source_epoch: Epoch, target_epoch: Epoch, signing_root: SigningRoot) -> Self {
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
            signing_root: attestation.signing_root(domain).into(),
        }
    }

    /// Create a `SignedAttestation` from an SQLite row of `(source, target, signing_root)`.
    pub fn from_row(row: &rusqlite::Row) -> rusqlite::Result<Self> {
        let source = row.get(0)?;
        let target = row.get(1)?;
        let signing_root = signing_root_from_row(2, row)?;
        Ok(SignedAttestation::new(source, target, signing_root))
    }
}
