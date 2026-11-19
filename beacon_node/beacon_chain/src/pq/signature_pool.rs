use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, metrics};
use operation_pool::CompactIndexedAttestationPq;
use pq_prover::ProverBackend;
use slot_clock::SlotClock;
use ssz::ProgressiveBitList;
use state_processing::pq;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use tokio::time::{Instant, sleep, timeout_at};
use tracing::{debug, warn};
use tree_hash::TreeHash;
use types::{
    AttestationData, AttestationPq, BeaconState, ChainSpec, EthSpec, ForkName, Hash256,
    SingleAttestationPq, Slot, XmssSignature,
};

const RETAIN_SLOTS: u64 = 3;

type Key = (Slot, Hash256, u64);

struct CommitteeInputs {
    data: AttestationData,
    committee_index: u64,
    committee_len: usize,
    signatures: BTreeMap<usize, (u64, XmssSignature)>,
}

#[derive(Default)]
pub(crate) struct SignaturePool<E: EthSpec> {
    subscriptions: BTreeSet<(Slot, u64)>,
    raw: BTreeMap<Key, CommitteeInputs>,
    proven: BTreeMap<Key, Arc<CompactIndexedAttestationPq<E>>>,
    /// Once the collection cutoff has passed, the job owns this slot's inputs.
    sealed_slot: Option<Slot>,
}

impl<E: EthSpec> SignaturePool<E> {
    fn prune(&mut self, now: Slot) {
        let earliest = now.saturating_sub(RETAIN_SLOTS - 1);
        self.raw.retain(|(slot, _, _), _| *slot >= earliest);
        self.proven.retain(|(slot, _, _), _| *slot >= earliest);
        self.subscriptions.retain(|(slot, _)| *slot >= now);
    }

    pub(crate) fn subscribe(&mut self, now: Slot, slot: Slot, committee: u64) {
        self.prune(now);
        if slot >= now
            && slot <= now.saturating_add(E::slots_per_epoch().saturating_mul(2))
            && committee < E::max_committees_per_slot_pq() as u64
        {
            self.subscriptions.insert((slot, committee));
        }
    }

    pub(crate) fn insert(
        &mut self,
        now: Slot,
        aggregate_all: bool,
        attestation: &SingleAttestationPq,
        bits: &ProgressiveBitList,
    ) {
        self.prune(now);
        let slot = attestation.data.slot;
        let committee = attestation.committee_index;
        if slot < now || self.sealed_slot.is_some_and(|sealed| slot <= sealed) {
            return;
        }
        if !aggregate_all && !self.subscriptions.contains(&(slot, committee)) {
            return;
        }
        let Some(position) = bits.iter().position(|bit| bit) else {
            return;
        };
        let key = (slot, attestation.data.tree_hash_root(), committee);
        if !self.raw.contains_key(&key) {
            let first_key = (slot, Hash256::ZERO, 0);
            let max_groups = E::max_committees_per_slot_pq().saturating_mul(4);
            if self
                .raw
                .range(first_key..)
                .take_while(|((entry_slot, _, _), _)| *entry_slot == slot)
                .take(max_groups)
                .count()
                == max_groups
            {
                return;
            }
        }
        let inputs = self.raw.entry(key).or_insert_with(|| CommitteeInputs {
            data: attestation.data.clone(),
            committee_index: committee,
            committee_len: bits.len(),
            signatures: BTreeMap::new(),
        });
        if inputs.committee_len == bits.len() {
            inputs
                .signatures
                .entry(position)
                .or_insert_with(|| (attestation.attester_index, attestation.signature.clone()));
        }
    }

    fn seal(&mut self, slot: Slot) -> Vec<(Key, CommitteeInputs)> {
        self.prune(slot);
        if self.sealed_slot.is_some_and(|sealed| slot <= sealed) {
            return Vec::new();
        }
        self.sealed_slot = Some(slot);
        let later = self
            .raw
            .split_off(&(slot.saturating_add(1u64), Hash256::ZERO, 0));
        std::mem::replace(&mut self.raw, later)
            .into_iter()
            .filter(|((entry_slot, _, _), _)| *entry_slot == slot)
            .collect()
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn register_pq_aggregation_duty(&self, slot: Slot, committee: u64, validator_index: u64) {
        if self.spec.fork_name_at_slot::<T::EthSpec>(slot) != ForkName::Pq {
            return;
        }
        let Some(now) = self.slot_clock.now() else {
            return;
        };
        if slot < now || slot > now.saturating_add(T::EthSpec::slots_per_epoch().saturating_mul(2))
        {
            return;
        }
        let head = self.head_snapshot();
        let required_epoch = slot
            .epoch(T::EthSpec::slots_per_epoch())
            .saturating_sub(self.spec.min_seed_lookahead.as_u64());
        let eligible = if required_epoch > head.beacon_state.current_epoch() {
            let mut state = head.beacon_state.clone();
            state_processing::state_advance::partial_state_advance(
                &mut state,
                Some(head.beacon_state_root()),
                required_epoch.start_slot(T::EthSpec::slots_per_epoch()),
                self.builder_onboarding_cache.as_deref(),
                &self.spec,
            )
            .is_ok()
                && pq::is_aggregator(&state, slot, committee, validator_index) == Ok(true)
        } else {
            pq::is_aggregator(&head.beacon_state, slot, committee, validator_index) == Ok(true)
        };
        if eligible {
            self.pq_signatures.lock().subscribe(now, slot, committee);
        }
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

    pub fn start_pq_aggregation(self: &Arc<Self>) {
        if !self.spec.is_pq_scheduled() {
            return;
        }
        let chain = Arc::clone(self);
        self.task_executor.spawn(
            async move {
                loop {
                    let Some(wait) = chain.slot_clock.duration_to_next_slot() else {
                        return;
                    };
                    sleep(wait).await;
                    let Some(slot) = chain.slot_clock.now() else {
                        continue;
                    };
                    if chain.spec.fork_name_at_slot::<T::EthSpec>(slot) != ForkName::Pq {
                        continue;
                    }
                    chain.prove_pq_slot(slot).await;
                }
            },
            "pq_aggregation",
        );
    }

    async fn prove_pq_slot(self: &Arc<Self>, slot: Slot) {
        let Some(slot_start) = self.slot_clock.start_of(slot) else {
            return;
        };
        let attestation_due = self.spec.get_attestation_due::<T::EthSpec>(slot);
        let aggregate_due = self.spec.get_aggregate_attestation_due::<T::EthSpec>(slot);
        let window = aggregate_due.saturating_sub(attestation_due);
        let collection_cutoff = slot_start + attestation_due + window / 2;
        let Some(now) = self.slot_clock.now_duration() else {
            return;
        };
        sleep(collection_cutoff.saturating_sub(now)).await;
        let inputs = self.pq_signatures.lock().seal(slot);
        if inputs.is_empty() {
            return;
        }
        let deadline = slot_start + aggregate_due;
        let Some(remaining) = self
            .slot_clock
            .now_duration()
            .and_then(|now| deadline.checked_sub(now))
        else {
            metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
            return;
        };
        let deadline = Instant::now() + remaining;
        let Some(provers) = &self.pq_provers else {
            return;
        };
        let Ok(permit) = provers.proving.clone().try_acquire_owned() else {
            metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
            return;
        };
        let backend = provers.aggregate.clone();
        let chain = Arc::clone(self);
        let job = self.task_executor.spawn_blocking_handle(
            move || {
                let _permit = permit;
                let mut state = chain.head_beacon_state_cloned();
                if let Err(error) = state.build_all_committee_caches(&chain.spec) {
                    warn!(
                        ?slot,
                        ?error,
                        "Unable to build PQ aggregation committee cache"
                    );
                    return;
                }
                // Larger groups are preferred when this machine cannot prove every
                // committee before the cutoff.
                let mut inputs = inputs;
                inputs.sort_by_key(|(_, input)| std::cmp::Reverse(input.signatures.len()));
                for (key, inputs) in inputs {
                    if Instant::now() >= deadline {
                        break;
                    }
                    match inputs.prove(&state, &chain.spec, backend.as_ref()) {
                        Ok(aggregate) if Instant::now() < deadline => {
                            let aggregate = Arc::new(aggregate);
                            chain.op_pool.insert_pq_attestation(
                                slot.epoch(T::EthSpec::slots_per_epoch()),
                                Arc::clone(&aggregate),
                            );
                            chain.pq_signatures.lock().proven.insert(key, aggregate);
                        }
                        Ok(_) => break,
                        Err(error) => {
                            debug!(?error, ?slot, "Unable to prove PQ committee aggregate")
                        }
                    }
                }
            },
            "pq_prove_committees",
        );
        if let Some(job) = job
            && timeout_at(deadline, job).await.is_err()
        {
            metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
        }
    }
}

impl CommitteeInputs {
    fn prove<E: EthSpec>(
        self,
        state: &BeaconState<E>,
        spec: &ChainSpec,
        backend: &dyn ProverBackend,
    ) -> Result<CompactIndexedAttestationPq<E>, BeaconChainError> {
        let committee = state.get_beacon_committee(self.data.slot, self.committee_index)?;
        if committee.committee.len() != self.committee_len {
            return Err(types::BeaconStateError::InvalidBitfield.into());
        }
        let mut aggregation_bits = ProgressiveBitList::with_capacity(self.committee_len);
        let mut committee_bits = types::CommitteeBitsPq::<E>::default();
        committee_bits.set(self.committee_index as usize, true)?;
        let mut indices = Vec::new();
        let mut signatures = Vec::new();
        for (position, (index, signature)) in self.signatures {
            if committee.committee.get(position).copied() == Some(index as usize) {
                aggregation_bits.set(position, true)?;
                indices.push(index);
                signatures.push(signature);
            }
        }
        if signatures.is_empty() {
            return Err(types::BeaconStateError::EmptyCommittee.into());
        }
        let statement = pq::attestation_statement(state, &self.data, &indices, spec)?;
        let _timer = metrics::start_timer(&metrics::PQ_PROVE_SECONDS);
        metrics::observe(&metrics::PQ_PROVE_SIGNERS, signatures.len() as f64);
        let proof = backend
            .prove(&[statement], &[signatures])
            .map_err(BeaconChainError::PqProverError)?;
        metrics::observe(&metrics::PQ_PROOF_BYTES, proof.as_bytes().len() as f64);
        Ok(CompactIndexedAttestationPq {
            attestation: AttestationPq {
                aggregation_bits,
                committee_bits,
                data: self.data,
            },
            attesting_indices: indices,
            proof: proof.as_bytes().to_vec().try_into()?,
        })
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
    fn raw_signatures_require_a_subscription_and_seal_once() {
        let mut pool = SignaturePool::<Spec>::default();
        let slot = Slot::new(3);
        let mut bits = ProgressiveBitList::with_capacity(2);
        bits.set(1, true).unwrap();
        let attestation = attestation(slot, 123, Hash256::ZERO);
        pool.insert(slot, false, &attestation, &bits);
        assert!(pool.raw.is_empty());
        pool.subscribe(slot, slot, 0);
        pool.insert(slot, false, &attestation, &bits);
        pool.insert(slot, false, &attestation, &bits);
        let jobs = pool.seal(slot);
        let [(_, job)] = jobs.as_slice() else {
            panic!("expected one proving job")
        };
        assert_eq!(job.signatures.len(), 1);
        assert_eq!(job.signatures.get(&1).map(|(index, _)| *index), Some(123));
        pool.insert(slot, true, &attestation, &bits);
        assert!(pool.seal(slot).is_empty());
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
            pool.insert(slot, true, &attestation(slot, root as u64, hash), &bits);
        }
        assert_eq!(pool.raw.len(), capacity);
        assert!(pool.seal(slot + 3).is_empty());
        assert!(pool.raw.is_empty());
    }
}
