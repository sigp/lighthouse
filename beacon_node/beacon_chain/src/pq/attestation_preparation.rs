//! Materialize proof requests and validate completed PQ proposal bundles.

use super::prover_scheduler::{Attempt, Work};
use crate::{
    BeaconChain, BeaconChainError, BeaconChainTypes,
    block_production::pq::attestation_packing::{Packing, ProposalView, participation},
    metrics,
};
use pq_prover::{Proof, ProverBackend, Statement};
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

    pub(super) fn prepare_pq_attestations(
        &self,
        job: Attempt,
        slot: Slot,
    ) -> Result<(), BeaconChainError> {
        let Some(provers) = &self.pq_provers else {
            return Ok(());
        };
        let scheduler = &provers.scheduler;
        let observed_head = scheduler.head_revision();
        let Some((state, parent)) = self.speculative_pq_state(slot)? else {
            scheduler.skip(job);
            return Ok(());
        };
        let view = ProposalView::new(&state, &self.spec, parent.as_ref())?.with_reward_cache()?;
        let candidates = self
            .op_pool
            .pq_attestation_candidates(slot.saturating_sub(MIN_ATTESTATION_INCLUSION_DELAY_PQ));
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
            debug!(%slot, work = ?job.work(), "No useful compatible PQ proof inputs");
            scheduler.skip(job);
            return Ok(());
        };

        debug!(%slot, gained = packing.gained, children = packing.children.len(), "Packed PQ proposal participation");
        let proof = if let Some(proof) = reuse(&packing) {
            proof
        } else {
            let Some(now) = self.slot_clock.now_duration() else {
                return Ok(());
            };
            let Some(active) = scheduler.start(now, job) else {
                return Ok(());
            };
            active
                .run(|| merge(provers.aggregate.as_ref(), &packing))
                .map_err(BeaconChainError::PqProverError)?
        };
        if !provers
            .aggregate
            .verify(&packing.statements, &proof)
            .map_err(BeaconChainError::PqProverError)?
        {
            scheduler.skip(job);
            return Ok(());
        }

        let mut prepared = PreparedAttestations::finish(packing, proof)?;
        let checked_head = scheduler.head_revision();
        if checked_head != observed_head {
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
        if let Some(now) = self.slot_clock.now_duration() {
            scheduler.save(now, job, checked_head, Arc::new(prepared));
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
