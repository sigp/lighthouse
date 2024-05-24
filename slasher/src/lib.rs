#![deny(missing_debug_implementations)]
#![cfg_attr(
    not(any(feature = "mdbx", feature = "lmdb")),
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
    interface::{Database, Environment, RwTransaction},
    IndexedAttestationId, SlasherDB,
};
pub use error::Error;

use types::{AttesterSlashing, AttesterSlashingBase, AttesterSlashingElectra};
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
    ) -> Result<Option<AttesterSlashing<E>>, String> {
        use AttesterSlashingStatus::*;

        // The surrounding attestation must be in `attestation_1` to be valid.
        Ok(match self {
            NotSlashable => None,
            AlreadyDoubleVoted => None,
            DoubleVote(existing) | SurroundedByExisting(existing) => match *existing {
                IndexedAttestation::Base(existing_att) => {
                    Some(AttesterSlashing::Base(AttesterSlashingBase {
                        attestation_1: existing_att,
                        attestation_2: new_attestation
                            .as_base()
                            .map_err(|e| format!("{e:?}"))?
                            .clone(),
                    }))
                }
                IndexedAttestation::Electra(existing_att) => {
                    Some(AttesterSlashing::Electra(AttesterSlashingElectra {
                        attestation_1: existing_att,
                        // A double vote should never convert, a surround vote where the surrounding
                        // vote is electra may convert.
                        attestation_2: new_attestation
                            .clone()
                            .to_electra()
                            .map_err(|e| format!("{e:?}"))?,
                    }))
                }
            },
            SurroundsExisting(existing) => {
                match new_attestation {
                    IndexedAttestation::Base(new_attestation) => {
                        Some(AttesterSlashing::Base(AttesterSlashingBase {
                            attestation_1: existing
                                .as_base()
                                .map_err(|e| format!("{e:?}"))?
                                .clone(),
                            attestation_2: new_attestation.clone(),
                        }))
                    }
                    IndexedAttestation::Electra(new_attestation) => {
                        Some(AttesterSlashing::Electra(AttesterSlashingElectra {
                            attestation_1: existing.to_electra().map_err(|e| format!("{e:?}"))?,
                            // A double vote should never convert, a surround vote where the surrounding
                            // vote is electra may convert.
                            attestation_2: new_attestation.clone(),
                        }))
                    }
                }
            }
        })
    }
}
