//! Local PQ block production for the harness. All signatures use the real XMSS backend.

use super::*;
use pq_prover::{ProverBackend, ReferenceBackend};
use state_processing::pq::{
    self, LEAF_OFFSET_BEACON_PROPOSER, LEAF_OFFSET_PAYLOAD_ENVELOPE,
    MIN_ATTESTATION_INCLUSION_DELAY_PQ,
};
use types::consts::gloas::BUILDER_INDEX_SELF_BUILD;
use types::kzg_ext::ProgressiveKzgCommitments;

pub(super) use genesis::pq::PqGenesisKeys;

pub(super) fn pq_genesis_keys<E: EthSpec>(
    keypairs: &[Keypair],
    spec: &ChainSpec,
) -> Option<Arc<Vec<PqGenesisKeys>>> {
    (spec.fork_name_at_slot::<E>(spec.genesis_slot) == ForkName::Pq).then(|| {
        Arc::new(
            keypairs
                .par_iter()
                .map(|key| PqGenesisKeys::from_bls(&key.sk))
                .collect(),
        )
    })
}

impl<E: EthSpec, Hot: ItemStore, Cold: ItemStore>
    BeaconChainHarness<BaseHarnessType<E, Hot, Cold>>
{
    /// Produce an authenticated PQ block on the empty execution branch, including votes for
    /// the slot exactly two slots before the block. This exercises the consensus transition
    /// without the gossip attestation pool or the production proposer services.
    pub async fn make_pq_block(
        &self,
        state: BeaconState<E>,
        slot: Slot,
        validators: &[usize],
    ) -> (SignedBlockContentsTuple<E>, BeaconState<E>) {
        self.make_pq_block_with_bid(state, slot, validators, None, Default::default())
            .await
    }

    pub async fn make_pq_block_with_bid(
        &self,
        state: BeaconState<E>,
        slot: Slot,
        validators: &[usize],
        revealed_parent: Option<ExecutionBlockHash>,
        blob_kzg_commitments: ProgressiveKzgCommitments<E>,
    ) -> (SignedBlockContentsTuple<E>, BeaconState<E>) {
        let keys = self.pq_keys.clone().expect("PQ harness keys");
        let spec = self.spec.clone();
        let validators = validators.iter().copied().collect();
        tokio::task::spawn_blocking(move || {
            make_pq_block(
                state,
                slot,
                &validators,
                &keys,
                &spec,
                revealed_parent,
                blob_kzg_commitments,
            )
        })
        .await
        .expect("PQ harness block production should run")
    }

    pub fn make_pq_envelope(
        &self,
        block: &SignedBeaconBlock<E>,
        state: &BeaconState<E>,
    ) -> SignedExecutionPayloadEnvelopePq<E> {
        let bid = block
            .message()
            .body()
            .signed_execution_payload_bid()
            .unwrap();
        let slot = block.slot();
        let message = ExecutionPayloadEnvelopePq {
            payload: ExecutionPayloadGloas {
                parent_hash: bid.message().parent_block_hash(),
                block_hash: bid.message().block_hash(),
                prev_randao: bid.message().prev_randao(),
                gas_limit: bid.message().gas_limit(),
                timestamp: state_processing::per_block_processing::compute_timestamp_at_slot(
                    state, slot, &self.spec,
                )
                .unwrap(),
                slot_number: slot,
                withdrawals: state
                    .payload_expected_withdrawals()
                    .unwrap()
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .try_into()
                    .unwrap(),
                ..Default::default()
            },
            builder_index: bid.message().builder_index(),
            execution_requests: ExecutionRequestsPq::default(),
            beacon_block_root: block.canonical_root(),
            parent_beacon_block_root: block.parent_root(),
        };
        let domain = self.spec.get_domain(
            state.current_epoch(),
            Domain::BeaconBuilder,
            &state.fork(),
            state.genesis_validators_root(),
        );
        let leaf = pq::slot_leaf_index(slot, LEAF_OFFSET_PAYLOAD_ENVELOPE).unwrap();
        SignedExecutionPayloadEnvelopePq {
            signature: self.sign_pq_test_message(
                block.message().proposer_index() as usize,
                leaf,
                message.signing_root(domain),
            ),
            message,
        }
    }

    pub fn sign_pq_block(
        &self,
        block: BeaconBlock<E>,
        state: &BeaconState<E>,
        leaf: u64,
    ) -> SignedBeaconBlock<E> {
        let keys = self.pq_keys.as_ref().expect("PQ harness keys");
        sign_pq_block(block, state, leaf, keys, &self.spec)
    }

    pub fn sign_pq_test_message(
        &self,
        validator_index: usize,
        leaf: u64,
        message: Hash256,
    ) -> XmssSignature {
        self.pq_keys.as_ref().expect("PQ harness keys")[validator_index]
            .xmss
            .sign(&message.0, leaf.try_into().expect("XMSS leaf"))
            .expect("PQ test signature")
    }
}

fn make_pq_block<E: EthSpec>(
    mut state: BeaconState<E>,
    slot: Slot,
    validators: &HashSet<usize>,
    keys: &[PqGenesisKeys],
    spec: &ChainSpec,
    revealed_parent: Option<ExecutionBlockHash>,
    blob_kzg_commitments: ProgressiveKzgCommitments<E>,
) -> (SignedBlockContentsTuple<E>, BeaconState<E>) {
    complete_state_advance(&mut state, None, slot, None, spec).expect("advance PQ state");
    state.build_caches(spec).expect("build PQ caches");
    let parent_root = *state.get_block_root(slot - 1).expect("PQ block parent");
    let proposer_index = state
        .get_beacon_proposer_index(slot, spec)
        .expect("proposer");
    let mut block = BeaconBlockPq::<E, FullPayload<E>>::empty(spec);
    block.slot = slot;
    block.parent_root = parent_root;
    block.proposer_index = proposer_index as u64;
    block.body.eth1_data = state.eth1_data().clone();
    block.body.randao_reveal = keys[proposer_index].vrf.proof(slot).expect("VRF proof");

    let prev_randao = *state
        .get_randao_mix(state.current_epoch())
        .expect("RANDAO mix");
    let execution_block_hash = ExecutionBlockHash::from_root(
        ethereum_hashing::hash32_concat(parent_root.as_slice(), &slot.as_u64().to_le_bytes())
            .into(),
    );
    block.body.signed_execution_payload_bid = SignedExecutionPayloadBidPq {
        message: ExecutionPayloadBidGloas {
            parent_block_hash: revealed_parent
                .unwrap_or_else(|| *state.latest_block_hash().expect("execution parent")),
            parent_block_root: parent_root,
            block_hash: execution_block_hash,
            prev_randao,
            builder_index: BUILDER_INDEX_SELF_BUILD,
            slot,
            execution_requests_root: ExecutionRequestsPq::<E>::default().tree_hash_root(),
            blob_kzg_commitments,
            ..Default::default()
        },
        signature: XmssSignature::empty(),
    };

    if slot.as_u64() >= MIN_ATTESTATION_INCLUSION_DELAY_PQ && !validators.is_empty() {
        let vote_slot = slot - MIN_ATTESTATION_INCLUSION_DELAY_PQ;
        let (attestation, proof) = make_pq_attestation(&state, vote_slot, validators, keys, spec);
        if let Some(attestation) = attestation {
            block
                .body
                .attestations
                .push(attestation)
                .expect("one attestation fits");
            block.body.proof = proof;
        }
    }

    let block = SignedBeaconBlock::Pq(SignedBeaconBlockPq {
        message: block,
        signature: XmssSignature::empty(),
    });
    per_block_processing(
        &mut state,
        &block,
        BlockSignatureStrategy::VerifyRandao,
        VerifyBlockRoot::True,
        &mut ConsensusContext::new(slot),
        spec,
    )
    .expect("apply PQ block");
    let SignedBeaconBlock::Pq(mut block) = block else {
        unreachable!("PQ harness just built a PQ block");
    };
    block.message.state_root = state.canonical_root().expect("hash PQ post state");

    let leaf = pq::slot_leaf_index(slot, LEAF_OFFSET_BEACON_PROPOSER).expect("proposer leaf");
    let signed = sign_pq_block(BeaconBlock::Pq(block.message), &state, leaf, keys, spec);
    ((Arc::new(signed), None), state)
}

fn make_pq_attestation<E: EthSpec>(
    state: &BeaconState<E>,
    slot: Slot,
    validators: &HashSet<usize>,
    keys: &[PqGenesisKeys],
    spec: &ChainSpec,
) -> (Option<AttestationPq<E>>, AttestationProof<E>) {
    let epoch = slot.epoch(E::slots_per_epoch());
    let source = if epoch == state.current_epoch() {
        state.current_justified_checkpoint()
    } else {
        state.previous_justified_checkpoint()
    };
    let target = Checkpoint {
        epoch,
        root: *state.get_block_root_at_epoch(epoch).expect("target root"),
    };
    let mut data = AttestationData {
        slot,
        index: 0,
        beacon_block_root: *state.get_block_root(slot).expect("head block root"),
        source,
        target,
    };
    if !state.is_attestation_same_slot(&data).expect("same slot") {
        let vote_block_slot = state_processing::common::get_latest_block_slot(
            state,
            slot,
            state.latest_block_header().slot,
        )
        .expect("attested block slot");
        let availability_index = vote_block_slot.as_usize() % E::slots_per_historical_root();
        data.index = u64::from(
            state
                .execution_payload_availability()
                .unwrap()
                .get(availability_index)
                .unwrap(),
        );
    }
    let mut attestation = AttestationPq::<E> {
        data,
        aggregation_bits: ssz::ProgressiveBitList::with_capacity(0),
        committee_bits: BitVector::new(),
    };
    let mut bits = Vec::new();
    for committee in state
        .get_beacon_committees_at_slot(slot)
        .expect("beacon committees")
    {
        if committee
            .committee
            .iter()
            .any(|index| validators.contains(index))
        {
            attestation
                .committee_bits
                .set(committee.index as usize, true)
                .expect("committee bit");
            bits.extend(
                committee
                    .committee
                    .iter()
                    .map(|index| validators.contains(index)),
            );
        }
    }
    if bits.is_empty() {
        return (None, AttestationProof::<E>::default());
    }
    attestation.aggregation_bits = ssz::ProgressiveBitList::with_capacity(bits.len());
    for (position, bit) in bits.into_iter().enumerate() {
        attestation
            .aggregation_bits
            .set(position, bit)
            .expect("aggregation bit");
    }

    let groups = pq::committee_attesters(state, &attestation).expect("attester groups");
    let statements =
        pq::attestation_statements(state, &attestation, spec).expect("proof statements");
    let signatures = statements
        .iter()
        .zip(groups)
        .map(|(statement, group)| {
            group
                .into_iter()
                .map(|index| {
                    let key = &keys[index as usize].xmss;
                    key.sign(&statement.message, statement.leaf_index.try_into().unwrap())
                        .expect("XMSS attestation signature")
                })
                .collect()
        })
        .collect::<Vec<_>>();
    let proof = ReferenceBackend
        .prove(&statements, &signatures)
        .expect("reference attestation proof");
    (
        Some(attestation),
        AttestationProof::<E>::new(proof.into_bytes()).expect("bounded proof"),
    )
}

fn sign_pq_block<E: EthSpec>(
    block: BeaconBlock<E>,
    state: &BeaconState<E>,
    leaf: u64,
    keys: &[PqGenesisKeys],
    spec: &ChainSpec,
) -> SignedBeaconBlock<E> {
    let domain = spec.get_domain(
        block.epoch(),
        Domain::BeaconProposer,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let signature = keys[block.proposer_index() as usize]
        .xmss
        .sign(&block.signing_root(domain).0, leaf.try_into().unwrap())
        .expect("PQ proposer signature");
    SignedBeaconBlock::from_block(block, signature).expect("PQ signed block")
}

#[cfg(all(test, feature = "spec-minimal", not(debug_assertions)))]
mod early_prover_tests {
    use super::*;
    use crate::{
        block_production::pq::attestation_packing::ProposalView,
        pq::attestation_preparation::{PreparedAttestations, merge, reuse},
    };
    use operation_pool::CompactIndexedAttestationPq;

    #[tokio::test]
    async fn early_prover_packs_overlap_and_preserves_authenticated_claims() {
        type E = MinimalEthSpec;
        let spec = Arc::new(ForkName::Pq.make_genesis_spec(E::default_spec()));
        let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
            .spec(spec.clone())
            .deterministic_keypairs(3 * E::slots_per_epoch() as usize)
            .fresh_ephemeral_store()
            .mock_execution_layer()
            .build();

        let slot = Slot::new(2);
        let vote_slot = Slot::new(0);
        let mut state = harness.get_current_state();
        complete_state_advance(&mut state, None, slot, None, &spec).unwrap();
        state.build_caches(&spec).unwrap();
        let vote_committee = state.get_beacon_committee(vote_slot, 0).unwrap();
        let [a, b, c, ..] = vote_committee.committee else {
            panic!("test needs three committee members");
        };
        let make = |voters: HashSet<usize>| {
            let (attestation, proof) = make_pq_attestation(
                &state,
                vote_slot,
                &voters,
                harness.pq_keys.as_ref().unwrap(),
                &spec,
            );
            let attestation = attestation.unwrap();
            let mut statements = pq::attestation_statements(&state, &attestation, &spec).unwrap();
            assert_eq!(statements.len(), 1);
            let attesting_indices = pq::committee_attesters(&state, &attestation)
                .unwrap()
                .remove(0);
            Arc::new(CompactIndexedAttestationPq {
                attestation,
                proof,
                statement: statements.remove(0),
                attesting_indices,
            })
        };
        let left = make(HashSet::from([*a, *b]));
        let right = make(HashSet::from([*b, *c]));
        let view = ProposalView::new(&state, &spec, None)
            .unwrap()
            .with_reward_cache()
            .unwrap();
        let initial = view
            .select(std::slice::from_ref(&left), None, false, true)
            .unwrap();
        let proof = reuse(&initial).unwrap();
        let saved = PreparedAttestations::finish(initial, proof).unwrap();
        let extension = view
            .select(&[left, right], Some(&saved), false, true)
            .unwrap();
        assert_eq!(extension.children.len(), 2);
        assert_eq!(extension.attestations.len(), 1);
        assert_eq!(extension.attestations[0].aggregation_bits.num_set_bits(), 3);
        assert!(extension.gained > 0);
        assert_eq!(extension.statements[0].pubkeys.len(), 3);
        let proof = merge(&ReferenceBackend, &extension).unwrap();
        assert!(
            ReferenceBackend
                .verify(&extension.statements, &proof)
                .unwrap()
        );
        let prepared = PreparedAttestations::finish(extension, proof).unwrap();
        assert!(
            view.bundle_credits(&prepared.attestations, &prepared.statements)
                .is_some()
        );
    }
}
