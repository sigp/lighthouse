use super::prover_scheduler::{Attempt, committee_window};
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, metrics};
use operation_pool::CompactIndexedAttestationPq;
use slot_clock::SlotClock;
use ssz::ProgressiveBitList;
use state_processing::pq;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};
use tracing::debug;
use tree_hash::TreeHash;
use types::{
    AttestationData, AttestationPq, BeaconState, ChainSpec, EthSpec, Hash256, SingleAttestationPq,
    Slot, XmssSignature,
};

const RETAIN_SLOTS: u64 = 3;

type Key = (Slot, Hash256, u64);

#[derive(Clone)]
struct CommitteeInputs {
    data: AttestationData,
    committee_index: u64,
    committee_len: usize,
    signatures: BTreeMap<usize, (u64, XmssSignature)>,
}

#[derive(Default)]
pub(crate) struct SignaturePool<E: EthSpec> {
    raw: BTreeMap<Key, Arc<CommitteeInputs>>,
    seen: BTreeSet<Key>,
    proven: BTreeMap<Key, Arc<CompactIndexedAttestationPq<E>>>,
    closed_committees: BTreeSet<(Slot, u64)>,
}

impl<E: EthSpec> SignaturePool<E> {
    pub(crate) fn prune(&mut self, now: Slot) {
        let earliest = now.saturating_sub(RETAIN_SLOTS - 1);
        self.raw.retain(|(slot, _, _), _| *slot >= now);
        self.seen.retain(|(slot, _, _)| *slot >= now);
        self.proven.retain(|(slot, _, _), _| *slot >= earliest);
        self.closed_committees.retain(|(slot, _)| *slot >= now);
    }

    fn insert(
        &mut self,
        now: Slot,
        attestation: &SingleAttestationPq,
        bits: &ProgressiveBitList,
    ) -> Option<usize> {
        self.prune(now);
        let slot = attestation.data.slot;
        let committee = attestation.committee_index;
        if slot < now || self.closed_committees.contains(&(slot, committee)) {
            return None;
        }
        let position = bits.iter().position(|bit| bit)?;
        let key = (slot, attestation.data.tree_hash_root(), committee);
        if !self.raw.contains_key(&key) {
            if self.seen.contains(&key) {
                return None;
            }
            let first_key = (slot, Hash256::ZERO, 0);
            let max_groups = E::max_committees_per_slot_pq().saturating_mul(4);
            if self
                .seen
                .range(first_key..)
                .take_while(|(entry_slot, _, _)| *entry_slot == slot)
                .take(max_groups)
                .count()
                == max_groups
            {
                return None;
            }
        }
        self.seen.insert(key);
        let inputs = self.raw.entry(key).or_insert_with(|| {
            Arc::new(CommitteeInputs {
                data: attestation.data.clone(),
                committee_index: committee,
                committee_len: bits.len(),
                signatures: BTreeMap::new(),
            })
        });
        if inputs.committee_len != bits.len() || inputs.signatures.contains_key(&position) {
            return None;
        }
        Arc::make_mut(inputs).signatures.insert(
            position,
            (attestation.attester_index, attestation.signature.clone()),
        );
        self.best(slot, committee)
            .map(|(_, inputs)| inputs.signatures.len())
    }

    fn best(&self, slot: Slot, committee: u64) -> Option<(Key, &Arc<CommitteeInputs>)> {
        self.raw
            .range((slot, Hash256::ZERO, 0)..)
            .take_while(|((entry_slot, _, _), _)| *entry_slot == slot)
            .filter(|((_, _, index), _)| *index == committee)
            .max_by_key(|(_, inputs)| inputs.signatures.len())
            .map(|(key, inputs)| (*key, inputs))
    }

    fn take(&mut self, key: Key) -> Option<Arc<CommitteeInputs>> {
        let inputs = self.raw.remove(&key)?;
        self.closed_committees.insert((key.0, key.2));
        Some(inputs)
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub(crate) fn insert_pq_signature(
        &self,
        attestation: &SingleAttestationPq,
        bits: &ProgressiveBitList,
    ) {
        let Some(provers) = &self.pq_provers else {
            return;
        };
        let Some(now) = self.slot_clock.now_duration() else {
            return;
        };
        let Some(slot) = self.slot_clock.slot_of(now) else {
            return;
        };
        let vote_slot = attestation.data.slot;
        let committee = attestation.committee_index;
        let debug_window = self
            .config
            .pq_aggregate_all
            .then(|| self.pq_committee_window(vote_slot))
            .flatten();
        if provers
            .scheduler
            .accept_committee_input(now, vote_slot, committee, debug_window)
            && let Some(priority) = self.pq_signatures.lock().insert(slot, attestation, bits)
        {
            provers
                .scheduler
                .committee_changed(vote_slot, committee, priority);
        }
    }

    pub(super) fn pq_committee_window(
        &self,
        slot: Slot,
    ) -> Option<super::prover_scheduler::Window> {
        Some(committee_window(
            self.slot_clock.start_of(slot)?,
            self.spec.get_attestation_due::<T::EthSpec>(slot),
            self.spec.get_aggregate_attestation_due::<T::EthSpec>(slot),
        ))
    }

    pub fn pq_aggregate(
        &self,
        slot: Slot,
        data_root: Hash256,
        committee: u64,
    ) -> Option<Arc<CompactIndexedAttestationPq<T::EthSpec>>> {
        self.pq_signatures
            .lock()
            .proven
            .get(&(slot, data_root, committee))
            .cloned()
    }

    pub(super) fn prove_pq_committee(
        &self,
        job: Attempt,
        slot: Slot,
        committee: u64,
    ) -> Result<(), BeaconChainError> {
        let Some(provers) = &self.pq_provers else {
            return Ok(());
        };
        let input = self
            .pq_signatures
            .lock()
            .best(slot, committee)
            .map(|(key, inputs)| (key, Arc::clone(inputs)));
        let Some((key, input)) = input else {
            provers.scheduler.skip(job);
            return Ok(());
        };
        let mut state = self.head_beacon_state_cloned();
        state.build_all_committee_caches(&self.spec)?;
        let (attestation, indices, statement, signatures) = input.prepare(&state, &self.spec)?;
        let Some(now) = self.slot_clock.now_duration() else {
            return Ok(());
        };
        let Some(active) = provers.scheduler.start(now, job) else {
            return Ok(());
        };
        let remaining = {
            let mut pool = self.pq_signatures.lock();
            if pool.take(key).is_none() {
                active.release_unused();
                return Ok(());
            }
            pool.best(slot, committee)
                .map_or(0, |(_, input)| input.signatures.len())
        };
        provers
            .scheduler
            .committee_changed(slot, committee, remaining);
        let _timer = metrics::start_timer(&metrics::PQ_PROVE_SECONDS);
        metrics::observe(&metrics::PQ_PROVE_SIGNERS, signatures.len() as f64);
        let proof = active
            .run(|| {
                provers
                    .aggregate
                    .prove(std::slice::from_ref(&statement), &[signatures])
            })
            .map_err(BeaconChainError::PqProverError)?;
        metrics::observe(&metrics::PQ_PROOF_BYTES, proof.len() as f64);
        let Some(now) = self.slot_clock.now_duration() else {
            return Ok(());
        };
        if !provers.scheduler.committee_result_is_current(now, job) {
            metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
            debug!(%slot, committee, "Discarded an expired or reassigned PQ committee proof");
            return Ok(());
        }
        let aggregate = Arc::new(CompactIndexedAttestationPq {
            attestation,
            attesting_indices: indices,
            statement,
            proof: proof.into_bytes().try_into()?,
        });
        if self.op_pool.insert_pq_attestation(
            slot.epoch(T::EthSpec::slots_per_epoch()),
            Arc::clone(&aggregate),
        ) {
            provers.scheduler.aggregate_changed();
        }
        self.pq_signatures.lock().proven.insert(key, aggregate);
        Ok(())
    }
}

impl CommitteeInputs {
    fn prepare<E: EthSpec>(
        &self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
    ) -> Result<
        (
            AttestationPq<E>,
            Vec<u64>,
            pq_prover::Statement,
            Vec<XmssSignature>,
        ),
        BeaconChainError,
    > {
        let committee = state.get_beacon_committee(self.data.slot, self.committee_index)?;
        if committee.committee.len() != self.committee_len {
            return Err(types::BeaconStateError::InvalidBitfield.into());
        }
        let mut aggregation_bits = ProgressiveBitList::with_capacity(self.committee_len);
        let mut committee_bits = types::CommitteeBitsPq::<E>::default();
        committee_bits.set(self.committee_index as usize, true)?;
        let mut indices = Vec::new();
        let mut signatures = Vec::new();
        for (&position, (index, signature)) in &self.signatures {
            if committee.committee.get(position).copied() == Some(*index as usize) {
                aggregation_bits.set(position, true)?;
                indices.push(*index);
                signatures.push(signature.clone());
            }
        }
        if signatures.is_empty() {
            return Err(types::BeaconStateError::EmptyCommittee.into());
        }
        let statement = pq::attestation_statement(state, &self.data, &indices, spec)?;
        Ok((
            AttestationPq {
                aggregation_bits,
                committee_bits,
                data: self.data.clone(),
            },
            indices,
            statement,
            signatures,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::{Checkpoint, Spec};

    fn attestation(slot: Slot, index: u64, root: Hash256) -> SingleAttestationPq {
        SingleAttestationPq {
            committee_index: 0,
            attester_index: index,
            data: AttestationData {
                slot,
                index: 0,
                beacon_block_root: root,
                source: Checkpoint::default(),
                target: Checkpoint::default(),
            },
            signature: XmssSignature::empty(),
        }
    }

    #[test]
    fn raw_signatures_deduplicate_and_close_after_dispatch() {
        let mut pool = SignaturePool::<Spec>::default();
        let slot = Slot::new(3);
        let mut bits = ProgressiveBitList::with_capacity(2);
        bits.set(1, true).unwrap();
        let attestation = attestation(slot, 123, Hash256::ZERO);
        assert_eq!(pool.insert(slot, &attestation, &bits), Some(1));
        assert_eq!(pool.insert(slot, &attestation, &bits), None);
        let job = pool.take(pool.best(slot, 0).unwrap().0).unwrap();
        assert_eq!(job.signatures.get(&1).map(|(index, _)| *index), Some(123));
        assert_eq!(pool.insert(slot, &attestation, &bits), None);
        assert!(pool.raw.is_empty());
    }

    #[test]
    fn raw_signatures_bound_distinct_data_per_slot() {
        let mut pool = SignaturePool::<Spec>::default();
        let slot = Slot::new(3);
        let mut bits = ProgressiveBitList::with_capacity(1);
        bits.set(0, true).unwrap();
        let capacity = Spec::max_committees_per_slot_pq() * 4;
        for root in 0..=capacity {
            let hash = Hash256::with_last_byte(root as u8);
            pool.insert(slot, &attestation(slot, root as u64, hash), &bits);
        }
        assert_eq!(pool.raw.len(), capacity);
        pool.prune(slot + 3);
        assert!(pool.raw.is_empty());
    }
}
