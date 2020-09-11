use crate::AttesterRecord;
use parking_lot::Mutex;
use std::collections::BTreeSet;
use std::sync::Arc;
use types::{EthSpec, IndexedAttestation};

/// Staging area for attestations received from the network.
///
/// To be added to the database in batches, for efficiency and to prevent data races.
#[derive(Debug)]
pub struct AttestationQueue<E: EthSpec> {
    snapshot: Mutex<AttestationQueueSnapshot<E>>,
    validators_per_chunk: usize,
}

#[derive(Debug)]
pub struct AttestationQueueSnapshot<E: EthSpec> {
    /// All attestations (unique) for storage on disk.
    pub attestations_to_store: Vec<Arc<(IndexedAttestation<E>, AttesterRecord)>>,
    /// Attestations group by validator index range.
    pub subqueues: Vec<SubQueue<E>>,
}

/// A queue of attestations for a range of validator indices.
#[derive(Debug, Default)]
pub struct SubQueue<E: EthSpec> {
    pub attestations: Vec<Arc<(IndexedAttestation<E>, AttesterRecord)>>,
}

impl<E: EthSpec> SubQueue<E> {
    /// Empty the queue.
    pub fn take(&mut self) -> Self {
        SubQueue {
            attestations: std::mem::replace(&mut self.attestations, vec![]),
        }
    }

    pub fn len(&self) -> usize {
        self.attestations.len()
    }
}

impl<E: EthSpec> AttestationQueue<E> {
    pub fn new(validators_per_chunk: usize) -> Self {
        Self {
            snapshot: Mutex::new(AttestationQueueSnapshot {
                attestations_to_store: vec![],
                subqueues: vec![],
            }),
            validators_per_chunk,
        }
    }

    /// Add an attestation to all relevant queues, creating them if necessary.
    pub fn queue(&self, attestation: IndexedAttestation<E>) {
        // FIXME(sproul): this burdens the beacon node with extra hashing :\
        let attester_record = AttesterRecord::from(attestation.clone());

        let subqueue_ids = attestation
            .attesting_indices
            .iter()
            .map(|validator_index| *validator_index as usize / self.validators_per_chunk)
            .collect::<BTreeSet<_>>();

        let arc_tuple = Arc::new((attestation, attester_record));

        let mut snapshot = self.snapshot.lock();
        snapshot.attestations_to_store.push(arc_tuple.clone());

        if let Some(max_subqueue_id) = subqueue_ids.iter().max() {
            if *max_subqueue_id >= snapshot.subqueues.len() {
                snapshot
                    .subqueues
                    .resize_with(max_subqueue_id + 1, SubQueue::default);
            }
        }

        for subqueue_id in subqueue_ids {
            snapshot.subqueues[subqueue_id]
                .attestations
                .push(arc_tuple.clone());
        }
    }

    pub fn get_snapshot(&self) -> AttestationQueueSnapshot<E> {
        let mut snapshot = self.snapshot.lock();
        AttestationQueueSnapshot {
            attestations_to_store: std::mem::replace(&mut snapshot.attestations_to_store, vec![]),
            subqueues: snapshot.subqueues.iter_mut().map(SubQueue::take).collect(),
        }
    }

    /// Return `(num_queues, num_attestations)`.
    pub fn stats(&self) -> (usize, usize) {
        let snapshot = self.snapshot.lock();
        let num_queues = snapshot.subqueues.len();
        let num_attestations = snapshot.subqueues.iter().map(SubQueue::len).sum();
        (num_queues, num_attestations)
    }
}
