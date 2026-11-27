use serde_json::json;
pub(crate) mod attestation_packing;

use super::{BlockProductionState, gloas::get_execution_payload_gloas};
use crate::graffiti_calculator::GraffitiSettings;
use crate::pq::{
    attestation_preparation::{PreparedAttestations, merge, reuse},
    prover_scheduler::fallback_deadline,
};
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, BlockProductionError, metrics};
use attestation_packing::ProposalView;
use execution_layer::BlockProposalContentsGloas;
use slot_clock::SlotClock;
use ssz::Encode;
use state_processing::{
    BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot,
    pq::{self, MIN_ATTESTATION_INCLUSION_DELAY_PQ},
    state_advance::complete_state_advance,
};
use std::sync::Arc;
use tokio::time::{Instant, timeout_at};
use tracing::{debug, warn};
use tree_hash::TreeHash;
use types::{
    Address, AttestationPq, AttestationProof, BeaconBlock, BeaconBlockPq, BeaconState, BlobsList,
    EmptyBlock, EthSpec, ExecutionPayloadBidGloas, ExecutionPayloadEnvelopePq, ExecutionRequestsPq,
    ForkName, KzgProofs, SignedBeaconBlock, SignedExecutionPayloadBidPq, Slot, Uint256, VrfProof,
    XmssSignature, consts::gloas::BUILDER_INDEX_SELF_BUILD,
};

pub struct PqBlockContents<E: EthSpec> {
    pub block: BeaconBlock<E>,
    pub envelope: ExecutionPayloadEnvelopePq<E>,
    pub kzg_proofs: KzgProofs<E>,
    pub blobs: BlobsList<E>,
    pub payload_value: Uint256,
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub async fn produce_block_pq(
        self: &Arc<Self>,
        slot: Slot,
        randao_reveal: VrfProof,
        graffiti: GraffitiSettings,
    ) -> Result<PqBlockContents<T::EthSpec>, BlockProductionError> {
        self.common_proposal_known(slot, None);
        metrics::inc_counter(&metrics::BLOCK_PRODUCTION_REQUESTS);
        let _timer = metrics::start_timer(&metrics::BLOCK_PRODUCTION_TIMES);
        let graffiti = self.graffiti_calculator.get_graffiti(graffiti).await;
        let chain = Arc::clone(self);
        let (state, mut block, parent_requests, should_build_on_full, parent_envelope) = self
            .task_executor
            .spawn_blocking_handle(
                move || {
                    let BlockProductionState {
                        mut state,
                        state_root,
                        parent_root,
                        parent_payload_status,
                        parent_envelope,
                    } = chain.load_state_for_block_production(slot)?;
                    let should_build_on_full = chain
                        .canonical_head
                        .fork_choice_read_lock()
                        .should_build_on_full(&parent_root, parent_payload_status, slot)?;
                    let parent_requests = if should_build_on_full {
                        parent_envelope
                            .as_ref()
                            .map(|envelope| (&envelope.execution_requests).into())
                            .ok_or(BlockProductionError::MissingParentExecutionPayload)?
                    } else {
                        ExecutionRequestsPq::default()
                    };
                    complete_state_advance(
                        &mut state,
                        state_root,
                        slot,
                        chain.builder_onboarding_cache.as_deref(),
                        &chain.spec,
                    )?;
                    state.build_all_committee_caches(&chain.spec)?;
                    state.apply_pending_mutations()?;
                    let proposer_index = state.get_beacon_proposer_index(slot, &chain.spec)?;
                    let key = state.get_validator(proposer_index)?;
                    if state.fork_name_unchecked() != ForkName::Pq
                        || !pq::is_valid_vrf_proof(&randao_reveal, slot, key.vrf_root)
                    {
                        return Err(BlockProductionError::InvalidBlockVariant(
                            "Invalid PQ RANDAO reveal or fork".into(),
                        ));
                    }
                    let mut block = BeaconBlockPq::empty(&chain.spec);
                    block.slot = slot;
                    block.proposer_index = proposer_index as u64;
                    block.parent_root = parent_root;
                    block.body.eth1_data = state.eth1_data().clone();
                    block.body.randao_reveal = randao_reveal;
                    block.body.graffiti = graffiti;
                    block.body.proposer_slashings = ssz_types::ProgressiveVariableList::new(
                        chain.op_pool.get_pq_proposer_slashings(&state, &chain.spec),
                    )
                    .map_err(BlockProductionError::SszTypesError)?;
                    Ok((
                        state,
                        block,
                        parent_requests,
                        should_build_on_full,
                        parent_envelope,
                    ))
                },
                "pq_prepare_block",
            )
            .ok_or(BlockProductionError::ShuttingDown)?
            .await
            .map_err(BlockProductionError::TokioJoin)??;

        let ready = self.pq_provers.as_ref().and_then(|provers| {
            let now = self.slot_clock.now_duration()?;
            let ready = provers.scheduler.snapshot(
                slot,
                now,
                self.slot_clock.start_of(slot)?,
                self.slot_clock.slot_duration(),
            );
            self.pq_measurement.production_snapshot(
                slot,
                now,
                ready.as_deref(),
                provers.scheduler.active_job(),
            );
            ready
        });
        let state = Arc::new(state);
        let parent_bid = state.latest_execution_payload_bid()?;
        let parent_hash = if should_build_on_full {
            parent_bid.block_hash()
        } else {
            parent_bid.parent_block_hash()
        };
        let execution_layer = self
            .execution_layer
            .as_ref()
            .ok_or(BlockProductionError::ExecutionLayerMissing)?;
        let gas_limit = execution_layer
            .get_proposer_gas_limit(block.proposer_index)
            .await;
        let build_execution_payload = async {
            let chain = Arc::clone(self);
            let payload_state = Arc::clone(&state);
            let (parent_root, proposer) = (block.parent_root, block.proposer_index);
            let handle = self
                .task_executor
                .spawn_blocking_handle(
                    move || {
                        get_execution_payload_gloas(
                            chain,
                            &payload_state,
                            parent_root,
                            parent_hash,
                            parent_envelope.filter(|_| should_build_on_full),
                            proposer,
                            slot,
                            gas_limit,
                        )
                    },
                    "pq_execution_attributes",
                )
                .ok_or(BlockProductionError::ShuttingDown)?
                .await
                .map_err(BlockProductionError::TokioJoin)??;
            handle
                .await
                .map_err(BlockProductionError::TokioJoin)?
                .ok_or(BlockProductionError::ShuttingDown)?
        };
        let (payload, ((attestations, proof), selection_time)) =
            tokio::join!(build_execution_payload, async {
                let bundle = self
                    .pq_proposal_attestations(
                        Arc::clone(&state),
                        should_build_on_full.then(|| parent_requests.clone()),
                        ready,
                    )
                    .await;
                (
                    bundle,
                    pq_measurement::global().map(|recorder| recorder.point()),
                )
            },);
        if let Some(recorder) = pq_measurement::global() {
            let mut claims = std::collections::BTreeMap::<u64, usize>::new();
            for attestation in &attestations {
                *claims.entry(attestation.data.slot.as_u64()).or_default() +=
                    attestation.aggregation_bits.num_set_bits();
            }
            pq_measurement::duty::details(
                &pq_measurement::duty::proposal_key(slot.as_u64()),
                json!({
                    "selection_time":selection_time.unwrap_or_else(||recorder.point()),"parent_root":format!("{:#x}",block.parent_root),
                    "selected_operations":pq_measurement::duty::result(&proof).into_iter().collect::<Vec<_>>(),
                    "reused_messages":pq_measurement::duty::message(&proof).into_iter().collect::<Vec<_>>(),"attestation_records":attestations.len(),
                    "claims_by_slot":claims.into_iter().map(|(slot,claims)|json!({"slot":slot,"claims":claims})).collect::<Vec<_>>()
                }),
            );
        }
        let BlockProposalContentsGloas {
            payload,
            payload_value,
            blob_kzg_commitments,
            blobs_and_proofs,
            execution_requests,
            ..
        } = payload?;
        let execution_requests = ExecutionRequestsPq::from(&execution_requests);
        block.body.signed_execution_payload_bid = SignedExecutionPayloadBidPq {
            message: ExecutionPayloadBidGloas {
                parent_block_hash: parent_hash,
                parent_block_root: block.parent_root,
                block_hash: payload.block_hash,
                prev_randao: payload.prev_randao,
                fee_recipient: Address::ZERO,
                gas_limit: payload.gas_limit,
                builder_index: BUILDER_INDEX_SELF_BUILD,
                slot,
                value: 0,
                execution_payment: 0,
                blob_kzg_commitments,
                execution_requests_root: execution_requests.tree_hash_root(),
            },
            signature: XmssSignature::empty(),
        };
        block.body.attestations = ssz_types::ProgressiveVariableList::new(attestations)
            .map_err(BlockProductionError::SszTypesError)?;
        block.body.proof = proof;
        block.body.parent_execution_requests = parent_requests;

        let chain = Arc::clone(self);
        self.task_executor
            .spawn_blocking_handle(
                move || {
                    let mut state = Arc::unwrap_or_clone(state);
                    let signed = SignedBeaconBlock::from_block(
                        BeaconBlock::Pq(block),
                        XmssSignature::empty(),
                    )?;
                    let block_size = signed.ssz_bytes_len();
                    metrics::observe(&metrics::BLOCK_SIZE, block_size as f64);
                    if block_size > chain.config.max_network_size {
                        return Err(BlockProductionError::BlockTooLarge(block_size));
                    }
                    state_processing::per_block_processing(
                        &mut state,
                        &signed,
                        BlockSignatureStrategy::VerifyRandao,
                        VerifyBlockRoot::True,
                        &mut ConsensusContext::new(slot),
                        &chain.spec,
                    )?;
                    let (mut block, _) = signed.deconstruct();
                    *block.state_root_mut() = state.update_tree_hash_cache()?;
                    let envelope = ExecutionPayloadEnvelopePq {
                        payload,
                        execution_requests,
                        builder_index: BUILDER_INDEX_SELF_BUILD,
                        beacon_block_root: block.canonical_root(),
                        parent_beacon_block_root: block.parent_root(),
                    };
                    let (blobs, kzg_proofs) = blobs_and_proofs;
                    metrics::inc_counter(&metrics::BLOCK_PRODUCTION_SUCCESSES);
                    Ok(PqBlockContents {
                        block,
                        envelope,
                        kzg_proofs,
                        blobs,
                        payload_value,
                    })
                },
                "pq_complete_block",
            )
            .ok_or(BlockProductionError::ShuttingDown)?
            .await
            .map_err(BlockProductionError::TokioJoin)?
    }

    async fn pq_proposal_attestations(
        self: &Arc<Self>,
        state: Arc<BeaconState<T::EthSpec>>,
        parent_requests: Option<ExecutionRequestsPq<T::EthSpec>>,
        ready: Option<Arc<PreparedAttestations<T::EthSpec>>>,
    ) -> (Vec<AttestationPq<T::EthSpec>>, AttestationProof<T::EthSpec>) {
        let slot = state.slot();
        let Some((start, now)) = self
            .slot_clock
            .start_of(slot)
            .zip(self.slot_clock.now_duration())
        else {
            return Default::default();
        };
        let deadline = fallback_deadline(start, self.spec.get_attestation_due::<T::EthSpec>(slot));
        let fallback_at = Instant::now() + deadline.saturating_sub(now);
        let chain = Arc::clone(self);
        // The ready path must be allowed to finish its local validation even when the
        // fallback proving deadline has passed. It never calls the prover.
        let Some(validation) = self.task_executor.spawn_blocking_handle(
            move || {
                if let Some(ready) = ready.as_deref()
                    && let Ok(view) = ProposalView::new(&state, &chain.spec, parent_requests.as_ref())
                    && view.bundle_is_valid(&ready.attestations, &ready.statements)
                {
                    debug!(%slot, records = ready.attestations.len(), "Using prepared PQ proposal proof");
                    return Ok(ready.for_proposal());
                }
                debug!(%slot, ready = ready.is_some(), "PQ proposal proof cache miss");
                Err((state, parent_requests))
            },
            "pq_validate_proposal_attestations",
        ) else { return Default::default(); };
        let (state, parent_requests) = match validation.await {
            Ok(Ok(hit)) => return hit,
            Ok(Err(miss)) => miss,
            Err(_) => return Default::default(),
        };

        let chain = Arc::clone(self);
        let Some(job) = self.task_executor.spawn_blocking_handle(
            move || {
                let Some(provers) = &chain.pq_provers else {
                    return Ok(Default::default());
                };
                let view = ProposalView::new(&state, &chain.spec, parent_requests.as_ref())?
                    .with_reward_cache()?;
                let candidates = chain.op_pool.pq_attestation_candidates(
                    slot.saturating_sub(MIN_ATTESTATION_INCLUSION_DELAY_PQ),
                );
                let reference = provers.aggregate.name() == "reference";
                let Some(packing) = view.select(&candidates, None, false, reference) else {
                    return Ok(Default::default());
                };
                if let Some(proof) = reuse(&packing) {
                    return PreparedAttestations::finish(packing, proof)
                        .map(|bundle| (bundle.for_proposal(),None));
                }
                let Some(now) = chain.slot_clock.now_duration() else {
                    return Ok(Default::default());
                };
                let Some(active) = provers.scheduler.start_fallback(now, slot, deadline) else {
                    let single = view.select(&candidates, None, true, reference);
                    if let Some((packing, proof)) =
                        single.and_then(|packing| reuse(&packing).map(|proof| (packing, proof)))
                    {
                        return PreparedAttestations::finish(packing, proof)
                            .map(|bundle| (bundle.for_proposal(),None));
                    }
                    return Ok(Default::default());
                };
                let trace = chain.pq_measurement.fallback_job(slot, now, deadline);
                let common=pq_measurement::global().and_then(|_|chain.common_merge_plan(slot,false,packing.attestations.iter()
                    .map(|a|a.data.slot.as_u64()).collect::<std::collections::BTreeSet<_>>().into_iter().collect()));
                if let Some(common)=&common {
                    common.messages(packing.statements.iter().zip(&packing.attestations).map(|(statement,attestation)|(statement.message,attestation.data.slot.as_u64())));
                }
                trace.emit("experiment_selected", "selected", now, || json!({
                    "available_inputs": candidates.len(), "input_proof_count": packing.children.len(),
                    "records": packing.attestations.len(), "unique_claims": packing.unique_claims,
                    "participation": packing.participation, "gain": packing.gained,
                }));
                let proof = active
                    .run_observed(&trace, None, || chain.slot_clock.now_duration(), || merge(provers.aggregate.as_ref(), &packing))
                    .map_err(BeaconChainError::PqProverError)?;
                let bundle=PreparedAttestations::finish(packing, proof).inspect_err(|_| {if let Some(common)=&common {common.discard("failed","invalid");}})?;
                let completion=common.as_ref().and_then(pq_measurement::proof::Plan::take_completion);
                Ok((bundle.for_proposal(),completion))
            },
            "pq_proposal_fallback",
        ) else {
            return Default::default();
        };
        match timeout_at(fallback_at, job).await {
            Ok(Ok(Ok((bundle, completion)))) => {
                if let Some(completion) = completion
                    && let Some(operation) = completion.ready("proposal")
                {
                    pq_measurement::duty::remember_result(&bundle.1, operation);
                }
                bundle
            }
            Ok(Ok(Err(error))) => {
                warn!(%slot, ?error, "Unable to prepare fallback PQ proposal proof");
                Default::default()
            }
            _ => {
                metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
                Default::default()
            }
        }
    }
}
