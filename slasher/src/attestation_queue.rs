use crate::{AttesterRecord, Config, IndexedAttesterRecord};
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::{Arc, Weak};
use types::{EthSpec, Hash256, IndexedAttestation};

/// Staging area for attestations received from the network.
///
/// Attestations are not grouped by validator index at this stage so that they can be easily
/// filtered for timeliness.
#[derive(Debug, Default)]
pub struct AttestationQueue<E: EthSpec> {
    pub queue: Mutex<SimpleBatch<E>>,
}

pub type SimpleBatch<E> = Vec<Arc<IndexedAttesterRecord<E>>>;

/// Attestations dequeued from the queue and in preparation for processing.
///
/// This struct is responsible for mapping validator indices to attestations and performing
/// de-duplication to remove redundant attestations.
#[derive(Debug, Default)]
pub struct AttestationBatch<E: EthSpec> {
    /// Map from (`validator_index`, `attestation_data_hash`) to indexed attester record.
    ///
    /// This mapping is used for de-duplication, see:
    ///
    /// https://github.com/sigp/lighthouse/issues/2112
    pub attesters: BTreeMap<(u64, Hash256), Arc<IndexedAttesterRecord<E>>>,

    /// Vec of all unique indexed attester records.
    ///
    /// The weak references account for the fact that some records might prove useless after
    /// de-duplication.
    pub attestations: Vec<Weak<IndexedAttesterRecord<E>>>,
}

/// Attestations grouped by validator index range.
#[derive(Debug)]
pub struct GroupedAttestations<E: EthSpec> {
    pub subqueues: Vec<SimpleBatch<E>>,
}

impl<E: EthSpec> AttestationBatch<E> {
    /// Add an attestation to the queue.
    pub fn queue(&mut self, indexed_record: Arc<IndexedAttesterRecord<E>>) {
        self.attestations.push(Arc::downgrade(&indexed_record));

        let attestation_data_hash = indexed_record.record.attestation_data_hash;

        for &validator_index in indexed_record.indexed.attesting_indices_iter() {
            self.attesters
                .entry((validator_index, attestation_data_hash))
                .and_modify(|existing_entry| {
                    // If the new record is for the same attestation data but with more bits set
                    // then replace the existing record so that we might avoid storing the
                    // smaller indexed attestation. Single-bit attestations will usually be removed
                    // completely by this process, and aggregates will only be retained if they
                    // are not redundant with respect to a larger aggregate seen in the same batch.
                    if existing_entry.indexed.attesting_indices_len()
                        < indexed_record.indexed.attesting_indices_len()
                    {
                        *existing_entry = indexed_record.clone();
                    }
                })
                .or_insert_with(|| indexed_record.clone());
        }
    }

    /// Group the attestations by validator chunk index.
    pub fn group_by_validator_chunk_index(self, config: &Config) -> GroupedAttestations<E> {
        let mut grouped_attestations = GroupedAttestations { subqueues: vec![] };

        for ((validator_index, _), indexed_record) in self.attesters {
            let subqueue_id = config.validator_chunk_index(validator_index);

            if subqueue_id >= grouped_attestations.subqueues.len() {
                grouped_attestations
                    .subqueues
                    .resize_with(subqueue_id + 1, SimpleBatch::default);
            }

            grouped_attestations.subqueues[subqueue_id].push(indexed_record);
        }

        grouped_attestations
    }
}

impl<E: EthSpec> AttestationQueue<E> {
    pub fn queue(&self, attestation: IndexedAttestation<E>) {
        let attester_record = AttesterRecord::from(attestation.clone());
        let indexed_record = IndexedAttesterRecord::new(attestation, attester_record);
        self.queue.lock().push(indexed_record);
    }

    pub fn dequeue(&self) -> SimpleBatch<E> {
        std::mem::take(&mut self.queue.lock())
    }

    pub fn requeue(&self, batch: SimpleBatch<E>) {
        self.queue.lock().extend(batch);
    }

    pub fn len(&self) -> usize {
        self.queue.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
