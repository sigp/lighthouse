#![deny(missing_debug_implementations)]
#![cfg_attr(
    not(any(feature = "mdbx", feature = "lmdb", feature = "redb")),
    allow(unused, clippy::drop_non_drop)
)]

mod array;
mod attestation_queue;
mod attester_record;
mod batch_stats;
mod block_queue;
pub mod config;
mod database;
mod error;
pub mod metrics;
mod migrate;
mod slasher;
pub mod test_utils;

pub use crate::slasher::Slasher;
pub use attestation_queue::{AttestationBatch, AttestationQueue, SimpleBatch};
pub use attester_record::{AttesterRecord, CompactAttesterRecord, IndexedAttesterRecord};
pub use block_queue::BlockQueue;
pub use config::{Config, DatabaseBackend, DatabaseBackendOverride};
pub use database::{
    IndexedAttestationId, SlasherDB,
    interface::{Database, Environment, RwTransaction},
};
pub use error::Error;

use tracing::error;
use types::{
    AttesterSlashing, AttesterSlashingBase, AttesterSlashingElectra, AttesterSlashingGloas,
};
use types::{EthSpec, IndexedAttestation, ProposerSlashing};

#[derive(Debug, PartialEq)]
pub enum AttesterSlashingStatus<E: EthSpec> {
    NotSlashable,
    /// A weird outcome that can occur when we go to lookup an attestation by its target
    /// epoch for a surround slashing, but find a different attestation -- indicating that
    /// the validator has already been caught double voting.
    AlreadyDoubleVoted,
    DoubleVote(Box<IndexedAttestation<E>>),
    SurroundsExisting(Box<IndexedAttestation<E>>),
    SurroundedByExisting(Box<IndexedAttestation<E>>),
}

#[derive(Debug, PartialEq)]
pub enum ProposerSlashingStatus {
    NotSlashable,
    DoubleVote(Box<ProposerSlashing>),
}

impl<E: EthSpec> AttesterSlashingStatus<E> {
    pub fn into_slashing(
        self,
        new_attestation: &IndexedAttestation<E>,
    ) -> Option<AttesterSlashing<E>> {
        use AttesterSlashingStatus::*;

        // The surrounding attestation must be in `attestation_1` to be valid.
        match self {
            NotSlashable => None,
            AlreadyDoubleVoted => None,
            DoubleVote(existing) | SurroundedByExisting(existing) => {
                match (&*existing, new_attestation) {
                    (IndexedAttestation::Base(existing_att), IndexedAttestation::Base(new)) => {
                        Some(AttesterSlashing::Base(AttesterSlashingBase {
                            attestation_1: existing_att.clone(),
                            attestation_2: new.clone(),
                        }))
                    }
                    // A slashing involving a gloas attestation type must return an
                    // `AttesterSlashingGloas` type.
                    (IndexedAttestation::Gloas(_), _) | (_, IndexedAttestation::Gloas(_)) => {
                        Some(AttesterSlashing::Gloas(AttesterSlashingGloas {
                            attestation_1: existing.clone().to_gloas(),
                            attestation_2: new_attestation.clone().to_gloas(),
                        }))
                    }
                    // A slashing involving an electra attestation type must return an `AttesterSlashingElectra` type
                    (_, _) => electra_slashing(&existing, new_attestation),
                }
            }
            SurroundsExisting(existing) => match (&*existing, new_attestation) {
                (IndexedAttestation::Base(existing_att), IndexedAttestation::Base(new)) => {
                    Some(AttesterSlashing::Base(AttesterSlashingBase {
                        attestation_1: new.clone(),
                        attestation_2: existing_att.clone(),
                    }))
                }
                // A slashing involving a gloas attestation type must return an
                // `AttesterSlashingGloas` type.
                (IndexedAttestation::Gloas(_), _) | (_, IndexedAttestation::Gloas(_)) => {
                    Some(AttesterSlashing::Gloas(AttesterSlashingGloas {
                        attestation_1: new_attestation.clone().to_gloas(),
                        attestation_2: existing.clone().to_gloas(),
                    }))
                }
                // A slashing involving an electra attestation type must return an `AttesterSlashingElectra` type
                (_, _) => electra_slashing(new_attestation, &existing),
            },
        }
    }
}

/// Build an Electra-typed attester slashing, logging an error if conversion fails.
///
/// Conversion failure should be unreachable: `to_electra` can only fail for Gloas attestations,
/// which `into_slashing` handles before reaching this function.
fn electra_slashing<E: EthSpec>(
    attestation_1: &IndexedAttestation<E>,
    attestation_2: &IndexedAttestation<E>,
) -> Option<AttesterSlashing<E>> {
    let to_electra = |attestation: &IndexedAttestation<E>| {
        attestation
            .clone()
            .to_electra()
            .inspect_err(
                |e| error!(error = ?e, "Failed to convert attestation for Electra slashing"),
            )
            .ok()
    };
    Some(AttesterSlashing::Electra(AttesterSlashingElectra {
        attestation_1: to_electra(attestation_1)?,
        attestation_2: to_electra(attestation_2)?,
    }))
}
