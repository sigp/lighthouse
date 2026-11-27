//! Materialize proof requests and validate completed PQ proposal bundles.

use super::{
    measurement::{Job, ns, proof_id},
    prover_scheduler::{Attempt, Work},
};
use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes,
    block_production::pq::attestation_packing::{Packing, ProposalView, participation},
    metrics,
};
use pq_prover::{Proof, ProverBackend, Statement};
use serde_json::json;
use slot_clock::SlotClock;
use state_processing::{
    pq::MIN_ATTESTATION_INCLUSION_DELAY_PQ, state_advance::complete_state_advance,
};
use std::sync::Arc;
use tracing::debug;
use types::{AttestationPq, AttestationProof, BeaconState, EthSpec, ExecutionRequestsPq, Slot};

pub(crate) struct PreparedAttestations<E: EthSpec> {
    pub(crate) attestations: Vec<AttestationPq<E>>,
    pub(crate) statements: Vec<Statement>,
    pub(crate) proof: AttestationProof<E>,
    pub(crate) participation: u64,
    pub(super) single_committee: bool,
    pub(super) standalone: bool,
}

impl<E: EthSpec> PreparedAttestations<E> {
    pub(crate) fn finish(packing: Packing<E>, proof: Proof) -> Result<Self, BeaconChainError> {
        Ok(Self {
            attestations: packing.attestations,
            statements: packing.statements,
            proof: proof.into_bytes().try_into()?,
            participation: packing.participation,
            single_committee: packing.single_committee,
            standalone: packing.children.len() == 1,
        })
    }

    pub(crate) fn for_proposal(&self) -> (Vec<AttestationPq<E>>, AttestationProof<E>) {
        (self.attestations.clone(), self.proof.clone())
    }
}

pub(crate) fn merge<E: EthSpec>(
    backend: &dyn ProverBackend,
    packing: &Packing<E>,
) -> Result<Proof, pq_prover::Error> {
    let _timer = metrics::start_timer(&metrics::PQ_MERGE_SECONDS);
    metrics::observe(&metrics::PQ_MERGE_CHILDREN, packing.children.len() as f64);
    metrics::observe(&metrics::PQ_MERGE_ROUNDS, 1.0);
    backend.merge_for_statements(
        &packing.children,
        &packing.statements,
        E::max_stark_proof_size(),
    )
}

pub(crate) fn reuse<E: EthSpec>(packing: &Packing<E>) -> Option<Proof> {
    let [(statements, proof)] = packing.children.as_slice() else {
        return None;
    };
    (statements == &packing.statements && !proof.is_empty()).then(|| proof.clone())
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    fn speculative_pq_state(
        &self,
        slot: Slot,
    ) -> Result<
        Option<(
            BeaconState<T::EthSpec>,
            Option<ExecutionRequestsPq<T::EthSpec>>,
        )>,
        BeaconChainError,
    > {
        let head = self.canonical_head.cached_head();
        self.speculative_pq_state_from_head(slot, &head)
    }

    pub(crate) fn speculative_pq_state_from_head(
        &self,
        slot: Slot,
        head: &crate::canonical_head::CachedHead<T::EthSpec>,
    ) -> Result<
        Option<(
            BeaconState<T::EthSpec>,
            Option<ExecutionRequestsPq<T::EthSpec>>,
        )>,
        BeaconChainError,
    > {
        let parent = head.head_block_root();
        let parent_state_root = head.head_state_root();
        let parent_status = head.head_payload_status();
        if head.head_slot() >= slot
            || head
                .head_slot()
                .saturating_add(T::EthSpec::slots_per_epoch())
                < slot
        {
            return Ok(None);
        }
        let full = self
            .canonical_head
            .fork_choice_read_lock()
            .should_build_on_full(&parent, parent_status, slot)?;
        let requests = if full {
            let Some(envelope) = head.snapshot.execution_envelope.as_ref() else {
                return Ok(None);
            };
            Some((&envelope.execution_requests).into())
        } else {
            None
        };
        let Some((state_root, mut state)) =
            self.store
                .get_advanced_hot_state(parent, slot, parent_state_root)?
        else {
            return Ok(None);
        };
        complete_state_advance(
            &mut state,
            Some(state_root),
            slot,
            self.builder_onboarding_cache.as_deref(),
            &self.spec,
        )?;
        state.build_all_committee_caches(&self.spec)?;
        state.apply_pending_mutations()?;
        Ok(Some((state, requests)))
    }

    #[cfg(test)]
    pub(super) fn prepare_pq_attestations(
        &self,
        job: Attempt,
        slot: Slot,
    ) -> Result<(), BeaconChainError> {
        let now = self.slot_clock.now_duration().unwrap_or_default();
        let trace = self.pq_measurement.job(job, now);
        self.prepare_pq_attestations_with_trace(job, slot, &trace)
    }

    pub(super) fn prepare_pq_attestations_with_trace(
        &self,
        job: Attempt,
        slot: Slot,
        trace: &Job<T::EthSpec>,
    ) -> Result<(), BeaconChainError> {
        let Some(provers) = &self.pq_provers else {
            return Ok(());
        };
        let scheduler = &provers.scheduler;
        let mut observed_head = scheduler.head_revision();
        let Some(before_preparation) = self.slot_clock.now_duration() else {
            return Ok(());
        };
        let latest = slot.saturating_sub(MIN_ATTESTATION_INCLUSION_DELAY_PQ);
        let (input, frozen) = if job.experiment().is_some() {
            let Some((candidates, frozen)) =
                self.pq_measurement
                    .proposal_inputs(job, latest, before_preparation)
            else {
                trace.emit(
                    "job_outcome",
                    "missing_input_snapshot",
                    before_preparation,
                    || json!({}),
                );
                scheduler.skip(job);
                return Ok(());
            };
            (Some(candidates), frozen)
        } else {
            (None, None)
        };
        let context = if let Some(frozen) = &frozen {
            observed_head = frozen.head_revision;
            self.speculative_pq_state_from_head(slot, &frozen.head)?
        } else {
            self.speculative_pq_state(slot)?
        };
        let Some((state, parent)) = context else {
            trace.emit("job_outcome", "missing_context", before_preparation, || {
                json!({})
            });
            scheduler.skip(job);
            return Ok(());
        };
        let view = ProposalView::new(&state, &self.spec, parent.as_ref())?.with_reward_cache()?;
        let candidates = input.unwrap_or_else(|| self.op_pool.pq_attestation_candidates(latest));
        let baseline = scheduler.ready(job);
        let reference = provers.aggregate.name() == "reference";
        let Some(now) = self.slot_clock.now_duration() else {
            return Ok(());
        };
        let mut packing =
            if job.work() == Work::Initial(slot) || scheduler.improvement_can_merge(now, job) {
                view.select(&candidates, baseline.as_deref(), false, reference)
            } else {
                None
            };

        // A better single child can replace a previously reused candidate without a merge.
        if packing.is_none()
            && let Some(base) = baseline.as_ref().filter(|base| base.standalone)
            && let Some(credits) = view.bundle_credits(&base.attestations, &base.statements)
            && let Some(candidate) = view.select(&candidates, None, true, reference)
            && candidate.participation > participation(credits)
        {
            packing = Some(candidate);
        }
        let Some(packing) = packing else {
            trace.emit(
                "job_outcome",
                "no_useful_inputs",
                now,
                || json!({"available_inputs": candidates.len()}),
            );
            debug!(%slot, work = ?job.work(), "No useful compatible PQ proof inputs");
            scheduler.skip(job);
            return Ok(());
        };

        let predecessor = trace
            .detailed()
            .then(|| baseline.as_ref().map(|base| proof_id(&base.proof)))
            .flatten();
        trace.emit("experiment_selected", "selected", self.slot_clock.now_duration().unwrap_or(now), || json!({
            "available_inputs": candidates.len(),
            "input_proof_count": packing.children.len(),
            "input_proof_ids": packing.children.iter().map(|(_, proof)| proof_id(proof.as_bytes())).collect::<Vec<_>>(),
            "predecessor_proof_id": predecessor,
            "records": packing.attestations.len(),
            "distinct_messages": packing.statements.iter().map(|statement| statement.message)
                .collect::<std::collections::BTreeSet<_>>().len(),
            "unique_claims": packing.unique_claims, "participation": packing.participation, "gain": packing.gained,
            "input_cutoff_wall_ns": frozen.as_ref().map(|input| ns(input.cutoff)),
            "input_captured_wall_ns": frozen.as_ref().map(|input| ns(input.captured_at)),
            "selection_head_root": frozen.as_ref().map(|input| input.head.head_block_root()),
        }));
        debug!(%slot, gained = packing.gained, children = packing.children.len(), "Packed PQ proposal participation");
        let mut merged = false;
        let common = pq_measurement::global().and_then(|_| {
            self.common_merge_plan(
                slot,
                job.experiment().is_some(),
                packing
                    .attestations
                    .iter()
                    .map(|attestation| attestation.data.slot.as_u64())
                    .collect::<std::collections::BTreeSet<_>>()
                    .into_iter()
                    .collect(),
            )
        });
        if let Some(common) = &common {
            common.messages(packing.statements.iter().zip(&packing.attestations).map(
                |(statement, attestation)| (statement.message, attestation.data.slot.as_u64()),
            ));
        }
        let proof = if let Some(proof) = reuse(&packing) {
            trace.emit("job_outcome", "reused", now, || {
                json!({
                    "proof_id": proof_id(proof.as_bytes()),
                })
            });
            proof
        } else {
            let Some(now) = self.slot_clock.now_duration() else {
                return Ok(());
            };
            let Some(active) = scheduler.start(now, job) else {
                trace.emit("job_outcome", "admission_changed", now, || json!({}));
                return Ok(());
            };
            merged = true;
            active
                .run_observed(
                    trace,
                    job.experiment(),
                    || self.slot_clock.now_duration(),
                    || merge(provers.aggregate.as_ref(), &packing),
                )
                .map_err(BeaconChainError::PqProverError)?
        };
        let verify_start = std::time::Instant::now();
        let verified = provers
            .aggregate
            .verify(&packing.statements, &proof)
            .inspect_err(|_| {
                if let Some(common) = &common {
                    common.discard("failed", "backend_error");
                }
            })
            .map_err(BeaconChainError::PqProverError)?;
        let verification = verify_start.elapsed();
        trace.latency("verification", verification);
        let verified_at = self.slot_clock.now_duration().unwrap_or(now);
        if !verified {
            if let Some(common) = &common {
                common.discard("failed", "invalid");
            }
            trace.emit("job_outcome", "invalid_proof", verified_at, || json!({}));
            scheduler.skip(job);
            return Ok(());
        }

        let mut prepared = PreparedAttestations::finish(packing, proof).inspect_err(|_| {
            if let Some(common) = &common {
                common.discard("failed", "invalid");
            }
        })?;
        let checked_head = scheduler.head_revision();
        if checked_head != observed_head {
            if let Some(common) = &common {
                common.unfinished_reason("reorg");
            }
            let Some((state, parent)) = self.speculative_pq_state(slot)? else {
                return Ok(());
            };
            let view =
                ProposalView::new(&state, &self.spec, parent.as_ref())?.with_reward_cache()?;
            let Some(credits) = view.bundle_credits(&prepared.attestations, &prepared.statements)
            else {
                return Ok(());
            };
            prepared.participation = participation(credits);
            if let Some(base) = baseline {
                let Some(previous) = view.bundle_credits(&base.attestations, &base.statements)
                else {
                    return Ok(());
                };
                if prepared.participation <= participation(previous) {
                    return Ok(());
                }
            }
        }
        let available = trace.detailed().then(|| {
            (
                proof_id(&prepared.proof),
                prepared.participation,
                prepared.attestations.len(),
            )
        });
        let measured_proof = pq_measurement::global().map(|_| prepared.proof.to_vec());
        if let Some(installed) = scheduler.save_candidate(
            || self.slot_clock.now_duration(),
            job,
            checked_head,
            Arc::new(prepared),
            merged,
        ) {
            if let Some(common) = &common
                && let Some(operation) = common.ready("proposal")
                && let Some(proof) = measured_proof
            {
                pq_measurement::duty::remember_result(&proof, operation);
            }
            trace.latency("ready", trace.queue_wait());
            trace.emit("candidate_ready", "ready", installed, || {
                json!({
                    "proof_id": available.as_ref().map(|(id, _, _)| id),
                    "participation": available.as_ref().map(|(_, value, _)| value),
                    "records": available.as_ref().map(|(_, _, value)| value),
                    "predecessor_proof_id": predecessor,
                    "recursive_depth": job.depth().saturating_add(u64::from(merged)),
                    "backend_call": merged,
                    "verified_wall_ns": ns(verified_at),
                    "verification_duration_ns": ns(verification),
                })
            });
        } else {
            if let Some(common) = &common {
                let late = self
                    .slot_clock
                    .now_duration()
                    .zip(self.slot_clock.start_of(slot))
                    .is_some_and(|(now, start)| now >= start);
                common.discard(
                    if late { "discarded_late" } else { "cancelled" },
                    if late { "deadline" } else { "reorg" },
                );
            }
            trace.emit("job_outcome", "expired_or_reassigned", verified_at, || {
                json!({})
            });
        }
        Ok(())
    }
}

#[cfg(all(test, feature = "spec-minimal", not(debug_assertions)))]
mod tests {
    use super::*;
    use crate::{
        pq::prover_scheduler::{ProposalDuties, proposal_window},
        test_utils::{BeaconChainHarness, EphemeralHarnessType},
    };
    use operation_pool::CompactIndexedAttestationPq;
    use state_processing::pq;
    use std::{collections::BTreeMap, time::Duration};
    use types::{ForkName, MinimalEthSpec, SignedBeaconBlock};

    #[tokio::test]
    async fn early_prover_prepares_from_current_head_two_slots_ahead() {
        type E = MinimalEthSpec;
        let spec = Arc::new(ForkName::Pq.make_genesis_spec(E::default_spec()));
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(Arc::clone(&spec))
            .deterministic_keypairs(E::slots_per_epoch() as usize)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();
        let chain = &harness.chain;
        let target = Slot::new(2);
        let head = harness.get_current_state();
        let voters = (0..E::slots_per_epoch() as usize).collect::<Vec<_>>();
        let ((block, _), _) = harness.make_pq_block(head.clone(), target, &voters).await;
        let SignedBeaconBlock::Pq(block) = &*block else {
            panic!("expected PQ fixture");
        };
        let attestation = block.message.body.attestations.get(0).unwrap().clone();

        let mut state = head;
        complete_state_advance(&mut state, None, target, None, &spec).unwrap();
        state.build_all_committee_caches(&spec).unwrap();
        let statement = pq::attestation_statements(&state, &attestation, &spec)
            .unwrap()
            .remove(0);
        let attesting_indices = pq::committee_attesters(&state, &attestation)
            .unwrap()
            .remove(0);
        let proof = block.message.body.proof.clone();
        assert!(chain.op_pool.insert_pq_attestation(
            state.current_epoch(),
            Arc::new(CompactIndexedAttestationPq {
                attestation: attestation.clone(),
                attesting_indices,
                proof: proof.clone(),
                statement,
            })
        ));

        let scheduler = &chain.pq_provers.as_ref().unwrap().scheduler;
        let start = chain.slot_clock.start_of(target).unwrap();
        let (window, forecast) = proposal_window(
            chain.slot_clock.start_of(Slot::new(0)).unwrap(),
            start,
            chain.slot_clock.slot_duration(),
        );
        chain.slot_clock.advance_time(Duration::from_secs(8));
        let now = chain.slot_clock.now_duration().unwrap();
        let duties: ProposalDuties =
            BTreeMap::from([(target, (window, forecast, block.message.proposer_index))]);
        scheduler.replace(now, BTreeMap::new(), duties, scheduler.head_revision());
        let job = scheduler.next(now).unwrap();
        assert_eq!(job.work(), Work::Initial(target));
        chain.prepare_pq_attestations(job, target).unwrap();
        let ready = scheduler
            .snapshot(target, start, start, chain.slot_clock.slot_duration())
            .unwrap();
        assert_eq!(ready.attestations, vec![attestation]);
        assert_eq!(ready.proof, proof);
        let view = ProposalView::new(&state, &spec, None).unwrap();
        assert!(view.bundle_is_valid(&ready.attestations, &ready.statements));
    }
}
