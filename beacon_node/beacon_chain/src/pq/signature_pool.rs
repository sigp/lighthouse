use super::{
    measurement::{Job, ns, proof_id},
    prover_scheduler::{Attempt, Window},
};
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, metrics};
use operation_pool::CompactIndexedAttestationPq;
use serde_json::json;
use slot_clock::SlotClock;
use ssz::ProgressiveBitList;
use state_processing::pq;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
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
pub(super) struct CommitteeInputs {
    data: AttestationData,
    committee_index: u64,
    committee_len: usize,
    signatures: BTreeMap<usize, (u64, XmssSignature, Duration)>,
}

#[derive(Default)]
pub(crate) struct SignaturePool<E: EthSpec> {
    raw: BTreeMap<Key, Arc<CommitteeInputs>>,
    seen: BTreeSet<Key>,
    proven: BTreeMap<(Key, u64), Arc<CompactIndexedAttestationPq<E>>>,
}

impl<E: EthSpec> SignaturePool<E> {
    pub(crate) fn prune(&mut self, now: Slot) {
        let earliest = now.saturating_sub(RETAIN_SLOTS - 1);
        self.raw.retain(|(slot, _, _), _| *slot >= now);
        self.seen.retain(|(slot, _, _)| *slot >= now);
        self.proven.retain(|((slot, _, _), _), _| *slot >= earliest);
    }

    pub(super) fn insert(
        &mut self,
        now: Slot,
        received_at: Duration,
        attestation: &SingleAttestationPq,
        bits: &ProgressiveBitList,
    ) -> Option<usize> {
        self.prune(now);
        let slot = attestation.data.slot;
        let committee = attestation.committee_index;
        if slot < now || committee as usize >= E::max_committees_per_slot_pq() {
            return None;
        }
        let position = bits.iter().position(|bit| bit)?;
        let key = (slot, attestation.data.tree_hash_root(), committee);
        if !self.raw.contains_key(&key) {
            if self.seen.contains(&key) {
                return None;
            }
            let first_key = (slot, Hash256::ZERO, 0);
            let max_groups = 4;
            if self
                .seen
                .range(first_key..)
                .take_while(|(entry_slot, _, _)| *entry_slot == slot)
                .filter(|(_, _, index)| *index == committee)
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
            (
                attestation.attester_index,
                attestation.signature.clone(),
                received_at,
            ),
        );
        self.best(slot, committee)
            .map(|(_, inputs)| inputs.signatures.len())
    }

    pub(super) fn best(&self, slot: Slot, committee: u64) -> Option<(Key, &Arc<CommitteeInputs>)> {
        self.raw
            .range((slot, Hash256::ZERO, 0)..)
            .take_while(|((entry_slot, _, _), _)| *entry_slot == slot)
            .filter(|((_, _, index), _)| *index == committee)
            .max_by_key(|(_, inputs)| inputs.signatures.len())
            .map(|(key, inputs)| (*key, inputs))
    }

    // Keep collecting for later aggregator positions. Each job reads an immutable cutoff view.
    fn best_at(
        &self,
        slot: Slot,
        committee: u64,
        cutoff: Duration,
    ) -> Option<(Key, Arc<CommitteeInputs>)> {
        let (key, inputs) = self
            .raw
            .iter()
            .filter(|((entry_slot, _, index), _)| *entry_slot == slot && *index == committee)
            .max_by_key(|(_, inputs)| {
                inputs
                    .signatures
                    .values()
                    .filter(|(_, _, received)| *received <= cutoff)
                    .count()
            })?;
        let mut inputs = (**inputs).clone();
        inputs
            .signatures
            .retain(|_, (_, _, received)| *received <= cutoff);
        (!inputs.signatures.is_empty()).then(|| (*key, Arc::new(inputs)))
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
        // Retain bounded current-slot inputs even before a local duty is discovered. A reorg
        // or delayed subscription can then use the correct pre-cutoff snapshot instead of
        // collecting after its cutoff. Only subscribed/verified gossip reaches this pool.
        // Raw inputs expire on the next slot; verified near-future gossip can also be
        // retained within the gossip clock disparity. Each committee has at most four
        // vote-data groups and one signature per validated position per group.
        let last_position = types::consts::pq::AGGREGATORS_PER_COMMITTEE.saturating_sub(1);
        let Some(last_window) = self.pq_committee_window_at(vote_slot, last_position) else {
            return;
        };
        if now >= last_window.start {
            return;
        }
        provers
            .scheduler
            .accept_committee_input(now, vote_slot, committee, debug_window);
        if let Some(priority) = self
            .pq_signatures
            .lock()
            .insert(slot, now, attestation, bits)
        {
            provers
                .scheduler
                .committee_changed(now, vote_slot, committee, priority);
        }
    }

    pub(super) fn pq_committee_window(
        &self,
        slot: Slot,
    ) -> Option<super::prover_scheduler::Window> {
        self.pq_committee_window_at(slot, 0)
    }

    pub(super) fn pq_committee_window_at(&self, slot: Slot, position: u64) -> Option<Window> {
        let start = self.slot_clock.start_of(slot)?;
        Some(Window {
            start: start.saturating_add(self.spec.get_pq_aggregation_cutoff(position)),
            end: start.saturating_add(self.spec.get_pq_aggregate_due(position)),
        })
    }

    pub fn pq_aggregate(
        &self,
        slot: Slot,
        data_root: Hash256,
        committee: u64,
        position: u64,
    ) -> Option<Arc<CompactIndexedAttestationPq<T::EthSpec>>> {
        self.pq_signatures
            .lock()
            .proven
            .get(&((slot, data_root, committee), position))
            .cloned()
    }

    pub(super) fn prove_pq_committee(
        &self,
        job: Attempt,
        slot: Slot,
        committee: u64,
        position: u64,
        trace: &Job<T::EthSpec>,
    ) -> Result<(), BeaconChainError> {
        let Some(provers) = &self.pq_provers else {
            return Ok(());
        };
        let input = if job.experiment().is_some() {
            self.pq_measurement
                .committee_input(job, slot, committee)
                .map(|input| (None, input))
        } else {
            self.pq_signatures
                .lock()
                .best_at(slot, committee, job.cutoff())
                .map(|(key, inputs)| (Some(key), inputs))
        };
        if job.experiment().is_none()
            && let Some(recorder) = pq_measurement::global()
        {
            let collected = recorder.point();
            let signers = input
                .as_ref()
                .map_or(0, |(_, input)| input.signatures.len());
            pq_measurement::duty::details(
                &pq_measurement::duty::committee_key(slot.as_u64(), committee, position),
                json!({
                    "collection_closed":collected,"available_signers":signers,"selected_signers":signers
                }),
            );
        }
        let Some((key, input)) = input else {
            if job.experiment().is_none() {
                pq_measurement::duty::complete(
                    &pq_measurement::duty::committee_key(slot.as_u64(), committee, position),
                    "no_inputs",
                    "no_inputs",
                    false,
                );
            }
            trace.emit(
                "job_outcome",
                "no_inputs",
                self.slot_clock.now_duration().unwrap_or_default(),
                || json!({}),
            );
            provers.scheduler.skip(job);
            return Ok(());
        };
        let mut state = self.head_beacon_state_cloned();
        state.build_all_committee_caches(&self.spec)?;
        let (attestation, indices, statement, signatures) = input.prepare(&state, &self.spec)?;
        let Some(now) = self.slot_clock.now_duration() else {
            return Ok(());
        };
        // Several local aggregators may have identical cutoff inputs. Reuse our own
        // completed proof, while keeping each position's independent broadcast time.
        if let Some(key) = key {
            let cached = self
                .pq_signatures
                .lock()
                .proven
                .range((key, 0)..=(key, u64::MAX))
                .find(|(_, entry)| entry.statement == statement && entry.attestation == attestation)
                .map(|(_, entry)| Arc::clone(entry));
            if let Some(cached) = cached {
                if provers.scheduler.committee_result_is_current(now, job) {
                    self.pq_signatures
                        .lock()
                        .proven
                        .insert((key, position), cached);
                    trace.emit(
                        "candidate_ready",
                        "reused",
                        now,
                        || json!({"committee": committee, "aggregator_position": position}),
                    );
                    provers.scheduler.skip(job);
                }
                return Ok(());
            }
        }
        let Some(active) = provers.scheduler.start(now, job) else {
            return Ok(());
        };
        trace.emit("experiment_selected", "selected", now, || {
            use tree_hash::TreeHash;
            json!({
                "committee": committee, "aggregator_position": position, "signature_count": signatures.len(),
                "committee_size": input.committee_len,
                "unique_claims": statement.pubkeys.len(),
                "vote_data_root": input.data.tree_hash_root(),
            })
        });
        let _timer = metrics::start_timer(&metrics::PQ_PROVE_SECONDS);
        metrics::observe(&metrics::PQ_PROVE_SIGNERS, signatures.len() as f64);
        let common = pq_measurement::global().and_then(|_| {
            self.common_committee_plan(
                job,
                slot,
                committee,
                position,
                input.committee_len,
                state.get_committee_count_at_slot(slot).ok()? as u64,
                signatures.len(),
            )
        });
        let proof = active
            .run_observed(
                trace,
                job.experiment(),
                || self.slot_clock.now_duration(),
                || {
                    provers
                        .aggregate
                        .prove(std::slice::from_ref(&statement), &[signatures])
                },
            )
            .map_err(BeaconChainError::PqProverError)?;
        metrics::observe(&metrics::PQ_PROOF_BYTES, proof.len() as f64);
        let Some(now) = self.slot_clock.now_duration() else {
            return Ok(());
        };
        if !provers.scheduler.committee_result_is_current(now, job) {
            if let Some(common) = &common {
                let late = self
                    .pq_committee_window_at(slot, position)
                    .is_some_and(|window| now >= window.end);
                common.discard(
                    if late { "discarded_late" } else { "cancelled" },
                    if late { "deadline" } else { "reorg" },
                );
            }
            metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
            debug!(%slot, committee, "Discarded an expired or reassigned PQ committee proof");
            trace.emit("job_outcome", "expired_or_reassigned", now, || json!({}));
            return Ok(());
        }
        if let Some(experiment) = job.experiment() {
            let verify_start = std::time::Instant::now();
            let valid = provers
                .aggregate
                .verify(std::slice::from_ref(&statement), &proof)
                .inspect_err(|_| {
                    if let Some(common) = &common {
                        common.discard("failed", "backend_error");
                    }
                })
                .map_err(BeaconChainError::PqProverError)?;
            let verification = verify_start.elapsed();
            trace.latency("verification", verification);
            let verified_at = self.slot_clock.now_duration().unwrap_or(now);
            if !valid
                || !provers
                    .scheduler
                    .committee_result_is_current(verified_at, job)
            {
                if let Some(common) = &common {
                    if !valid {
                        common.discard("failed", "invalid");
                    } else {
                        common.discard("cancelled", "other");
                    }
                }
                trace.emit(
                    "job_outcome",
                    if valid {
                        "expired_or_reassigned"
                    } else {
                        "invalid_proof"
                    },
                    verified_at,
                    || json!({}),
                );
                return Ok(());
            }
            self.pq_measurement
                .committee_completed(slot, committee, experiment);
            if let Some(common) = &common {
                common.ready("committee");
            }
            trace.emit("candidate_ready", "ready", verified_at, || {
                json!({
                    "committee": committee, "private": true, "claims": statement.pubkeys.len(),
                    "verification_duration_ns": ns(verification),
                    "proof_id": proof_id(proof.as_bytes()),
                })
            });
            return Ok(());
        }
        let aggregate = Arc::new(CompactIndexedAttestationPq {
            attestation,
            attesting_indices: indices,
            statement,
            proof: proof.into_bytes().try_into().inspect_err(|_| {
                if let Some(common) = &common {
                    common.discard("failed", "invalid");
                }
            })?,
        });
        if self.op_pool.insert_pq_attestation(
            slot.epoch(T::EthSpec::slots_per_epoch()),
            Arc::clone(&aggregate),
        ) {
            provers.scheduler.aggregate_changed();
        }
        if let Some(key) = key {
            let measured_proof = pq_measurement::global().map(|_| aggregate.proof.to_vec());
            let publication_id = trace.detailed().then(|| proof_id(&aggregate.proof));
            self.pq_signatures
                .lock()
                .proven
                .insert((key, position), aggregate);
            if let Some(common) = &common
                && let Some(operation) = common.ready("committee")
                && let Some(proof) = measured_proof
            {
                pq_measurement::duty::remember_result(&proof, operation);
            }
            trace.emit(
                "candidate_ready",
                "ready",
                self.slot_clock.now_duration().unwrap_or(now),
                || {
                    json!({
                        "committee": committee, "proof_id": publication_id,
                        "verification_policy": "backend_claims",
                    })
                },
            );
        }
        Ok(())
    }
}

impl CommitteeInputs {
    #[cfg(test)]
    pub(super) fn signature_count(&self) -> usize {
        self.signatures.len()
    }

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
        for (&position, (index, signature, _)) in &self.signatures {
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
    fn staggered_cutoffs_keep_late_signatures_for_later_positions() {
        let mut pool = SignaturePool::<Spec>::default();
        let slot = Slot::new(3);
        let mut bits = ProgressiveBitList::with_capacity(2);
        bits.set(0, true).unwrap();
        let first = attestation(slot, 123, Hash256::ZERO);
        assert_eq!(
            pool.insert(slot, Duration::from_secs(4), &first, &bits),
            Some(1)
        );
        assert_eq!(
            pool.insert(slot, Duration::from_secs(4), &first, &bits),
            None
        );
        let early = pool.best_at(slot, 0, Duration::from_secs(5)).unwrap().1;
        bits.set(0, false).unwrap();
        bits.set(1, true).unwrap();
        let late = attestation(slot, 124, Hash256::ZERO);
        assert_eq!(
            pool.insert(slot, Duration::from_secs(6), &late, &bits),
            Some(2)
        );
        assert_eq!(early.signatures.len(), 1);
        assert_eq!(
            pool.best_at(slot, 0, Duration::from_secs(5))
                .unwrap()
                .1
                .signatures
                .len(),
            1
        );
        assert_eq!(
            pool.best_at(slot, 0, Duration::from_secs(6))
                .unwrap()
                .1
                .signatures
                .len(),
            2
        );
    }

    #[test]
    fn late_and_reassigned_duties_use_only_their_cutoff_inputs() {
        use crate::pq::prover_scheduler::{ProverScheduler, Window};
        let mut pool = SignaturePool::<Spec>::default();
        let scheduler = Arc::new(ProverScheduler::<Spec>::default());
        let slot = Slot::new(3);
        let mut bits = ProgressiveBitList::with_capacity(2);
        bits.set(0, true).unwrap();
        pool.insert(
            slot,
            Duration::from_millis(40_000),
            &attestation(slot, 0, Hash256::ZERO),
            &bits,
        );
        bits.set(0, false).unwrap();
        bits.set(1, true).unwrap();
        pool.insert(
            slot,
            Duration::from_millis(41_200),
            &attestation(slot, 1, Hash256::ZERO),
            &bits,
        );
        // Position zero is first learned after its cutoff, but has pre-cutoff inputs.
        scheduler.replace(
            Duration::from_millis(41_300),
            BTreeMap::from([(
                (slot, 0, 0),
                Window {
                    start: Duration::from_millis(40_800),
                    end: Duration::from_millis(43_200),
                },
            )]),
            BTreeMap::new(),
            0,
        );
        let old = scheduler.next(Duration::from_millis(41_300)).unwrap();
        assert_eq!(
            pool.best_at(slot, 0, old.cutoff())
                .unwrap()
                .1
                .signatures
                .len(),
            1
        );
        // A new head assigns position one. Its later cutoff admits the second signature.
        scheduler.head_changed();
        scheduler.replace(
            Duration::from_millis(41_500),
            BTreeMap::from([(
                (slot, 0, 1),
                Window {
                    start: Duration::from_millis(41_400),
                    end: Duration::from_millis(43_800),
                },
            )]),
            BTreeMap::new(),
            1,
        );
        assert!(
            scheduler
                .start(Duration::from_millis(41_500), old)
                .is_none()
        );
        let new = scheduler.next(Duration::from_millis(41_500)).unwrap();
        assert_eq!(
            pool.best_at(slot, 0, new.cutoff())
                .unwrap()
                .1
                .signatures
                .len(),
            2
        );
        pool.prune(slot + 1);
        assert!(pool.best_at(slot, 0, new.cutoff()).is_none());
    }

    #[test]
    fn raw_signatures_bound_distinct_data_per_slot() {
        let mut pool = SignaturePool::<Spec>::default();
        let slot = Slot::new(3);
        let mut bits = ProgressiveBitList::with_capacity(1);
        bits.set(0, true).unwrap();
        let capacity = 4;
        for root in 0..=capacity {
            let hash = Hash256::with_last_byte(root as u8);
            pool.insert(
                slot,
                Duration::ZERO,
                &attestation(slot, root as u64, hash),
                &bits,
            );
        }
        assert_eq!(pool.raw.len(), capacity);
        pool.prune(slot + 3);
        assert!(pool.raw.is_empty());
    }
}
