use super::{BlockProductionState, gloas::get_execution_payload_gloas};
use crate::graffiti_calculator::GraffitiSettings;
use crate::{BeaconChain, BeaconChainError, BeaconChainTypes, BlockProductionError, metrics};
use execution_layer::BlockProposalContentsGloas;
use operation_pool::CompactIndexedAttestationPq;
use pq_prover::{Proof, Statement};
use slot_clock::SlotClock;
use ssz::{Encode, ProgressiveBitList};
use state_processing::{
    BlockSignatureStrategy, ConsensusContext, VerifyBlockRoot, VerifySignatures,
    common::get_attestation_participation_flag_indices,
    per_block_processing::{
        apply_parent_execution_payload_pq, verify_attestation_for_block_inclusion,
    },
    pq::{self, MIN_ATTESTATION_INCLUSION_DELAY_PQ},
    state_advance::complete_state_advance,
};
use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};
use tokio::time::{Instant, timeout_at};
use tracing::warn;
use tree_hash::TreeHash;
use types::{
    Address, AttestationPq, AttestationProof, AttestationRef, BeaconBlock, BeaconBlockPq,
    BeaconState, BlobsList, ChainSpec, EmptyBlock, Epoch, EthSpec, ExecutionPayloadBidGloas,
    ExecutionPayloadEnvelopePq, ExecutionRequestsPq, ForkName, KzgProofs, RelativeEpoch,
    SignedBeaconBlock, SignedExecutionPayloadBidPq, Slot, Uint256, VrfProof, XmssSignature,
    consts::{altair::PARTICIPATION_FLAG_WEIGHTS, gloas::BUILDER_INDEX_SELF_BUILD},
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
            let payload_state = state.clone();
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
        let (payload, (attestations, proof)) = tokio::join!(
            build_execution_payload,
            self.merge_pq_attestations(&state, &parent_requests, should_build_on_full),
        );
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
                    let mut state = state;
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

    async fn merge_pq_attestations(
        &self,
        state: &BeaconState<T::EthSpec>,
        parent_requests: &ExecutionRequestsPq<T::EthSpec>,
        should_build_on_full: bool,
    ) -> (Vec<AttestationPq<T::EthSpec>>, AttestationProof<T::EthSpec>) {
        let slot = state.slot();
        let candidates = self
            .op_pool
            .pq_attestation_candidates(slot.saturating_sub(MIN_ATTESTATION_INCLUSION_DELAY_PQ));
        if candidates.is_empty() {
            return Default::default();
        }
        let Some(provers) = self.pq_provers.as_ref() else {
            return Default::default();
        };
        let remaining = self
            .slot_clock
            .start_of(slot)
            .zip(self.slot_clock.now_duration())
            .and_then(|(start, now)| {
                (start
                    + self
                        .spec
                        .get_attestation_due::<T::EthSpec>(slot)
                        .mul_f64(0.75))
                .checked_sub(now)
            });
        let Some(remaining) = remaining else {
            metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
            return Default::default();
        };
        let Ok(permit) = provers.proving.clone().try_acquire_owned() else {
            metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
            return Default::default();
        };
        let deadline = Instant::now() + remaining;
        let backend = provers.aggregate.clone();
        let (mut state, spec, parent_requests) =
            (state.clone(), self.spec.clone(), parent_requests.clone());
        let Some(job) = self.task_executor.spawn_blocking_handle(
            move || {
                let _permit = permit;
                if should_build_on_full {
                    apply_parent_execution_payload_pq(&mut state, &parent_requests, &spec)
                        .map_err(BeaconChainError::PrepareProposerFailed)?;
                }
                let (attestations, children) = select_attestations(&state, &spec, candidates)?;
                if Instant::now() >= deadline {
                    return Ok(None);
                }
                let _timer = metrics::start_timer(&metrics::PQ_MERGE_SECONDS);
                metrics::observe(&metrics::PQ_MERGE_CHILDREN, children.len() as f64);
                #[cfg(unix)]
                metrics::observe(
                    &metrics::PQ_MERGE_ROUNDS,
                    pq_prover::merge_plan(children.len()).0 as f64,
                );
                let proof = backend
                    .merge(&children)
                    .map_err(BeaconChainError::PqProverError)?;
                let proof = proof
                    .as_bytes()
                    .to_vec()
                    .try_into()
                    .map_err(BeaconChainError::SszTypesError)?;
                Ok::<_, BeaconChainError>(Some((attestations, proof)))
            },
            "pq_merge_attestations",
        ) else {
            return Default::default();
        };
        match timeout_at(deadline, job).await {
            Ok(Ok(Ok(Some(merged)))) => merged,
            Ok(Ok(Err(error))) => {
                warn!(?slot, ?error, "Unable to merge PQ attestations");
                Default::default()
            }
            _ => {
                metrics::inc_counter(&metrics::PQ_PROOF_DEADLINE_MISSES);
                Default::default()
            }
        }
    }
}

type Participation = (Epoch, u64, usize);
type CommitteeProof = (Vec<Statement>, Proof);

#[derive(Default)]
struct Candidate<E: EthSpec> {
    committees: BTreeMap<u64, Arc<CompactIndexedAttestationPq<E>>>,
    gains: BTreeMap<Participation, u64>,
}

fn select_attestations<E: EthSpec>(
    state: &BeaconState<E>,
    spec: &ChainSpec,
    candidates: Vec<Arc<CompactIndexedAttestationPq<E>>>,
) -> Result<(Vec<AttestationPq<E>>, Vec<CommitteeProof>), BeaconChainError> {
    let mut groups = BTreeMap::<_, Candidate<E>>::new();
    let mut context = ConsensusContext::new(state.slot());
    for entry in candidates {
        let attestation = &entry.attestation;
        let data = &attestation.data;
        let Some(committee) = attestation.committee_index() else {
            continue;
        };
        if verify_attestation_for_block_inclusion(
            state,
            AttestationRef::Pq(attestation),
            &mut context,
            VerifySignatures::False,
            spec,
        )
        .is_err()
        {
            continue;
        }
        // Use this branch's committee order to check that the cached proof
        // still covers the same participants after a reorganization.
        let mut indices = pq::committee_attesters(state, attestation)?
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        indices.sort_unstable();
        let mut verified_indices = entry.attesting_indices.clone();
        verified_indices.sort_unstable();
        if indices != verified_indices {
            continue;
        }
        let parent_slot = state.latest_block_header().slot;
        let delay = state.slot().as_u64().saturating_sub(data.slot.as_u64());
        let flags = get_attestation_participation_flag_indices(
            state,
            data,
            Some(parent_slot),
            delay,
            spec,
        )?;
        let participation = if RelativeEpoch::from_epoch(state.current_epoch(), data.target.epoch)
            == Ok(RelativeEpoch::Current)
        {
            state.current_epoch_participation()?
        } else {
            state.previous_epoch_participation()?
        };
        let group = groups.entry(data.tree_hash_root()).or_default();
        for index in indices {
            let validator = state.get_validator(index as usize)?;
            for flag in flags.iter().copied() {
                if participation
                    .get(index as usize)
                    .is_some_and(|flags| flags.has_flag(flag).unwrap_or(false))
                {
                    continue;
                }
                if let Some(weight) = PARTICIPATION_FLAG_WEIGHTS.get(flag) {
                    group.gains.insert(
                        (data.target.epoch, index, flag),
                        validator.effective_balance.saturating_mul(*weight),
                    );
                }
            }
        }
        group.committees.insert(committee, entry);
    }

    let mut covered = HashSet::new();
    let mut attestations = Vec::new();
    let mut children = Vec::new();
    for _ in 0..E::max_attestations_pq() {
        let score = |candidate: &Candidate<E>| {
            candidate
                .gains
                .iter()
                .filter(|(key, _)| !covered.contains(*key))
                .fold(0u64, |sum, (_, weight)| sum.saturating_add(*weight))
        };
        let Some((key, candidate)) = groups.iter().max_by_key(|(_, candidate)| score(candidate))
        else {
            break;
        };
        if score(candidate) == 0 {
            break;
        }
        let key = *key;
        let Some(group) = groups.remove(&key) else {
            break;
        };
        covered.extend(group.gains.keys().copied());
        let Some(data) = group
            .committees
            .values()
            .next()
            .map(|entry| entry.attestation.data.clone())
        else {
            continue;
        };
        let mut bits = Vec::new();
        let mut committee_bits = types::CommitteeBitsPq::<E>::default();
        for (committee, entry) in group.committees {
            committee_bits.set(committee as usize, true)?;
            bits.extend(entry.attestation.aggregation_bits.iter());
            children.push((
                pq::attestation_statements(state, &entry.attestation, spec)?,
                Proof::from_bytes(entry.proof.to_vec()),
            ));
        }
        let mut aggregation_bits = ProgressiveBitList::with_capacity(bits.len());
        for (index, bit) in bits.into_iter().enumerate() {
            if bit {
                aggregation_bits.set(index, true)?;
            }
        }
        attestations.push(AttestationPq {
            data,
            aggregation_bits,
            committee_bits,
        });
    }
    Ok((attestations, children))
}
