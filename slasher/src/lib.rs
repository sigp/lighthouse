#![deny(missing_debug_implementations)]

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
mod utils;

pub use crate::slasher::Slasher;
pub use attestation_queue::{AttestationBatch, AttestationQueue, SimpleBatch};
pub use attester_record::{AttesterRecord, CompactAttesterRecord, IndexedAttesterRecord};
pub use block_queue::BlockQueue;
pub use config::Config;
pub use database::{IndexedAttestationId, SlasherDB};
pub use error::Error;

use types::{AttesterSlashing, EthSpec, IndexedAttestation, ProposerSlashing};

/// LMDB-to-MDBX compatibility shims.
pub type Environment = mdbx::Environment<mdbx::NoWriteMap>;
pub type RwTransaction<'env> = mdbx::Transaction<'env, mdbx::RW, mdbx::NoWriteMap>;

#[derive(Clone, Debug, Eq, PartialEq)]
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

#[derive(Clone, Debug, Eq, PartialEq)]
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
            DoubleVote(existing) | SurroundedByExisting(existing) => Some(AttesterSlashing {
                attestation_1: *existing,
                attestation_2: new_attestation.clone(),
            }),
            SurroundsExisting(existing) => Some(AttesterSlashing {
                attestation_1: new_attestation.clone(),
                attestation_2: *existing,
            }),
        }
    }
}
