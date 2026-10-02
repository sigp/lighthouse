use crate::{AttesterRecord, Config, IndexedAttesterRecord};
use parking_lot::Mutex;
use std::collections::{BTreeMap, HashSet};
use std::sync::{Arc, Weak};
use tracing::warn;
use tree_hash::TreeHash;
use types::{EthSpec, Hash256, IndexedAttestation};

/// Hard cap on validator indices accepted by the slasher.
///
/// Any attestation referencing a validator index above this limit is silently dropped during
/// grouping. This is a defence-in-depth measure to prevent pathological memory allocation if an
/// attestation with a bogus index somehow reaches the slasher. The value (2^23 = 8,388,608)
/// provides generous headroom above the current mainnet validator set (~2M).
const MAX_VALIDATOR_INDEX: u64 = 8_388_608;

/// Map from (`validator_index`, `attestation_data_hash`) to indexed attester record.
type AttesterMap<E> = BTreeMap<(u64, Hash256), Arc<IndexedAttesterRecord<E>>>;

/// Staging area for attestations received from the network.
///
/// Deduplicates on insert by `(validator_index, attestation_data_hash)`, see:
///
/// https://github.com/sigp/lighthouse/issues/10086
#[derive(Debug, Default)]
pub struct AttestationQueue<E: EthSpec> {
    queue: Mutex<AttesterMap<E>>,
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

/// Insert `indexed_record` into a `(validator_index, attestation_data_hash)` map, keeping the
/// record with more attesting indices when an entry already exists.
fn insert_indexed_record<E: EthSpec>(
    attesters: &mut BTreeMap<(u64, Hash256), Arc<IndexedAttesterRecord<E>>>,
    indexed_record: Arc<IndexedAttesterRecord<E>>,
) {
    let attestation_data_hash = indexed_record.record.attestation_data_hash;

    for &validator_index in indexed_record.indexed.attesting_indices_iter() {
        attesters
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

impl<E: EthSpec> AttestationBatch<E> {
    /// Add an attestation to the queue.
    pub fn queue(&mut self, indexed_record: Arc<IndexedAttesterRecord<E>>) {
        self.attestations.push(Arc::downgrade(&indexed_record));
        insert_indexed_record(&mut self.attesters, indexed_record);
    }

    /// Group the attestations by validator chunk index.
    pub fn group_by_validator_chunk_index(self, config: &Config) -> GroupedAttestations<E> {
        let mut grouped_attestations = GroupedAttestations { subqueues: vec![] };

        for ((validator_index, _), indexed_record) in self.attesters {
            if validator_index >= MAX_VALIDATOR_INDEX {
                warn!(
                    validator_index,
                    "Dropping slasher attestation with out-of-range validator index"
                );
                break;
            }

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
        insert_indexed_record(&mut self.queue.lock(), indexed_record);
    }

    pub fn dequeue(&self) -> SimpleBatch<E> {
        unique_records(std::mem::take(&mut *self.queue.lock()))
    }

    pub fn requeue(&self, batch: SimpleBatch<E>) {
        let mut queue = self.queue.lock();
        for indexed_record in batch {
            insert_indexed_record(&mut queue, indexed_record);
        }
    }

    /// Number of unique indexed attester records currently staged.
    pub fn len(&self) -> usize {
        unique_record_count(&self.queue.lock())
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns `true` if every attesting validator already has this attestation data staged.
    pub fn is_redundant(&self, attestation: &IndexedAttestation<E>) -> bool {
        let mut indices = attestation.attesting_indices_iter().peekable();
        if indices.peek().is_none() {
            return false;
        }

        let attestation_data_hash = attestation.data().tree_hash_root();
        let queue = self.queue.lock();
        indices
            .all(|&validator_index| queue.contains_key(&(validator_index, attestation_data_hash)))
    }
}

/// Collect unique `IndexedAttesterRecord`s from a dedup map.
fn unique_records<E: EthSpec>(attesters: AttesterMap<E>) -> SimpleBatch<E> {
    let mut seen = HashSet::with_capacity(attesters.len());
    let mut out = Vec::with_capacity(attesters.len());
    for record in attesters.into_values() {
        if seen.insert(record.record.indexed_attestation_hash) {
            out.push(record);
        }
    }
    out
}

fn unique_record_count<E: EthSpec>(attesters: &AttesterMap<E>) -> usize {
    let mut seen = HashSet::with_capacity(attesters.len());
    for record in attesters.values() {
        seen.insert(record.record.indexed_attestation_hash);
    }
    seen.len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::indexed_att_electra;

    #[test]
    fn duplicate_single_is_redundant_and_does_not_grow_queue() {
        let queue = AttestationQueue::default();
        let att = indexed_att_electra(vec![1], 0, 1, 1);

        queue.queue(att.clone());
        assert_eq!(queue.len(), 1);
        assert!(queue.is_redundant(&att));

        queue.queue(att.clone());
        assert_eq!(queue.len(), 1);
        assert!(queue.is_redundant(&att));
    }

    #[test]
    fn different_attestation_data_are_not_redundant() {
        let queue = AttestationQueue::default();
        let att_a = indexed_att_electra(vec![1], 0, 1, 1);
        let att_b = indexed_att_electra(vec![1], 0, 1, 2);

        queue.queue(att_a.clone());
        assert_eq!(queue.len(), 1);
        assert!(queue.is_redundant(&att_a));
        assert!(!queue.is_redundant(&att_b));

        queue.queue(att_b.clone());
        assert_eq!(queue.len(), 2);
        assert!(queue.is_redundant(&att_b));
    }

    #[test]
    fn larger_aggregate_replaces_smaller_for_same_data() {
        let queue = AttestationQueue::default();
        let single = indexed_att_electra(vec![1], 0, 1, 1);
        let aggregate = indexed_att_electra(vec![1, 2], 0, 1, 1);

        queue.queue(single);
        assert_eq!(queue.len(), 1);

        queue.queue(aggregate.clone());
        assert_eq!(queue.len(), 1);
        assert!(queue.is_redundant(&aggregate));
        assert!(queue.is_redundant(&indexed_att_electra(vec![1], 0, 1, 1)));
        assert!(queue.is_redundant(&indexed_att_electra(vec![2], 0, 1, 1)));
    }

    #[test]
    fn partial_overlap_is_not_fully_redundant() {
        let queue = AttestationQueue::default();
        let first = indexed_att_electra(vec![1], 0, 1, 1);
        let second = indexed_att_electra(vec![1, 2], 0, 1, 1);

        queue.queue(first);
        assert!(!queue.is_redundant(&second));

        queue.queue(second.clone());
        assert_eq!(queue.len(), 1);
        assert!(queue.is_redundant(&second));
    }

    #[test]
    fn requeue_deduplicates() {
        let queue = AttestationQueue::default();
        let att = indexed_att_electra(vec![7], 0, 1, 9);
        let record = IndexedAttesterRecord::new(att.clone(), AttesterRecord::from(att.clone()));

        queue.requeue(vec![record.clone(), record]);
        assert_eq!(queue.len(), 1);
        assert!(queue.is_redundant(&att));
    }

    #[test]
    fn empty_attesting_indices_is_not_redundant() {
        let queue = AttestationQueue::default();
        let empty = indexed_att_electra(Vec::<u64>::new(), 0, 1, 1);
        assert!(!queue.is_redundant(&empty));
    }
}
