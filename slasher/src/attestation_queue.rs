use crate::{AttesterRecord, Config};
use parking_lot::Mutex;
use std::collections::BTreeSet;
use std::sync::Arc;
use types::{EthSpec, IndexedAttestation};

/// Staging area for attestations received from the network.
///
/// To be added to the database in batches, for efficiency and to prevent data races.
#[derive(Debug, Default)]
pub struct AttestationQueue<E: EthSpec> {
    /// All attestations (unique) for storage on disk.
    pub queue: Mutex<AttestationBatch<E>>,
}

/// Attestations grouped by validator index range.
#[derive(Debug)]
pub struct GroupedAttestations<E: EthSpec> {
    pub subqueues: Vec<AttestationBatch<E>>,
}

/// A queue of attestations for a range of validator indices.
#[derive(Debug, Default)]
pub struct AttestationBatch<E: EthSpec> {
    pub attestations: Vec<Arc<(IndexedAttestation<E>, AttesterRecord)>>,
}

impl<E: EthSpec> AttestationBatch<E> {
    pub fn len(&self) -> usize {
        self.attestations.len()
    }

    pub fn is_empty(&self) -> bool {
        self.attestations.is_empty()
    }

    /// Group the attestations by validator index.
    pub fn group_by_validator_index(self, config: &Config) -> GroupedAttestations<E> {
        let mut grouped_attestations = GroupedAttestations { subqueues: vec![] };

        for attestation in self.attestations {
            let subqueue_ids = attestation
                .0
                .attesting_indices
                .iter()
                .map(|validator_index| config.validator_chunk_index(*validator_index))
                .collect::<BTreeSet<_>>();

            if let Some(max_subqueue_id) = subqueue_ids.iter().next_back() {
                if *max_subqueue_id >= grouped_attestations.subqueues.len() {
                    grouped_attestations
                        .subqueues
                        .resize_with(max_subqueue_id + 1, AttestationBatch::default);
                }
            }

            for subqueue_id in subqueue_ids {
                grouped_attestations.subqueues[subqueue_id]
                    .attestations
                    .push(attestation.clone());
            }
        }

        grouped_attestations
    }
}

impl<E: EthSpec> AttestationQueue<E> {
    /// Add an attestation to the queue.
    pub fn queue(&self, attestation: IndexedAttestation<E>) {
        let attester_record = AttesterRecord::from(attestation.clone());
        self.queue
            .lock()
            .attestations
            .push(Arc::new((attestation, attester_record)));
    }

    pub fn dequeue(&self) -> AttestationBatch<E> {
        std::mem::take(&mut self.queue.lock())
    }

    pub fn requeue(&self, batch: AttestationBatch<E>) {
        self.queue.lock().attestations.extend(batch.attestations);
    }

    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
