#![deny(missing_debug_implementations)]

mod array;
mod attestation_queue;
mod attester_record;
pub mod config;
mod database;
mod error;
mod slasher;
mod slasher_server;

pub use crate::attester_record::AttesterRecord;
pub use crate::slasher::Slasher;
pub use attestation_queue::AttestationQueue;
pub use config::Config;
pub use database::SlasherDB;
pub use error::Error;
pub use slasher_server::SlasherServer;

use types::{AttesterSlashing, EthSpec, IndexedAttestation};

#[derive(Debug, PartialEq)]
pub enum SlashingStatus<E: EthSpec> {
    NotSlashable,
    DoubleVote(Box<IndexedAttestation<E>>),
    SurroundsExisting(Box<IndexedAttestation<E>>),
    SurroundedByExisting(Box<IndexedAttestation<E>>),
}

impl<E: EthSpec> SlashingStatus<E> {
    pub fn into_slashing(
        self,
        new_attestation: &IndexedAttestation<E>,
    ) -> Option<AttesterSlashing<E>> {
        use SlashingStatus::*;

        match self {
            NotSlashable => None,
            DoubleVote(existing) | SurroundsExisting(existing) | SurroundedByExisting(existing) => {
                Some(AttesterSlashing {
                    attestation_1: *existing,
                    attestation_2: new_attestation.clone(),
                })
            }
        }
    }
}
