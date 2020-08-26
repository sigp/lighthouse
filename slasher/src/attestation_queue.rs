use parking_lot::{Mutex, RwLock};
use std::collections::BTreeSet;
use std::sync::Arc;
use types::{EthSpec, IndexedAttestation};

/// Staging area for attestations received from the network.
///
/// To be added to the database in batches, for efficiency and to prevent data races.
#[derive(Debug)]
pub struct AttestationQueue<E: EthSpec> {
    /// All attestations (unique) for storage on disk.
    attestations_to_store: Mutex<Vec<Arc<IndexedAttestation<E>>>>,
    /// Attestations group by validator index range.
    pub(crate) subqueues: RwLock<Vec<SubQueue<E>>>,
    pub(crate) validators_per_chunk: usize,
}

/// A queue of attestations for a range of validator indices.
#[derive(Debug)]
pub struct SubQueue<E: EthSpec> {
    pub(crate) attestations: Mutex<Vec<Arc<IndexedAttestation<E>>>>,
}

impl<E: EthSpec> SubQueue<E> {
    pub fn new() -> Self {
        SubQueue {
            attestations: Mutex::new(vec![]),
        }
    }

    /// Empty the queue.
    pub fn take(&self) -> Vec<Arc<IndexedAttestation<E>>> {
        std::mem::replace(&mut self.attestations.lock(), vec![])
    }

    pub fn len(&self) -> usize {
        self.attestations.lock().len()
    }
}

impl<E: EthSpec> AttestationQueue<E> {
    pub fn new(validators_per_chunk: usize) -> Self {
        Self {
            attestations_to_store: Mutex::new(vec![]),
            subqueues: RwLock::new(vec![]),
            validators_per_chunk,
        }
    }

    /// Add an attestation to all relevant queues, creating them if necessary.
    pub fn queue(&self, attestation: IndexedAttestation<E>) {
        let attestation = Arc::new(attestation);

        self.attestations_to_store.lock().push(attestation.clone());

        let subqueue_ids = attestation
            .attesting_indices
            .iter()
            .map(|validator_index| *validator_index as usize / self.validators_per_chunk)
            .collect::<BTreeSet<_>>();

        if let Some(max_subqueue_id) = subqueue_ids.iter().max() {
            if *max_subqueue_id >= self.subqueues.read().len() {
                self.subqueues
                    .write()
                    .resize_with(max_subqueue_id + 1, SubQueue::new);
            }
        }

        for subqueue_id in subqueue_ids {
            let subqueues_lock = self.subqueues.read();
            subqueues_lock[subqueue_id]
                .attestations
                .lock()
                .push(attestation.clone());
        }
    }

    pub fn get_attestations_to_store(&self) -> Vec<Arc<IndexedAttestation<E>>> {
        std::mem::replace(&mut self.attestations_to_store.lock(), vec![])
    }

    /// Return `(num_queues, num_attestations)`.
    pub fn stats(&self) -> (usize, usize) {
        let subqueues = self.subqueues.read();
        let num_queues = subqueues.len();
        let num_attestations = subqueues.iter().map(SubQueue::len).sum();
        (num_queues, num_attestations)
    }
}
