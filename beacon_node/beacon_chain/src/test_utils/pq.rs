//! Local PQ block production for the harness. All signatures use the real XMSS backend.

use super::*;
use pq_prover::{ProverBackend, ReferenceBackend};
use state_processing::pq::{self, LEAF_OFFSET_BEACON_PROPOSER, MIN_ATTESTATION_INCLUSION_DELAY_PQ};
use types::consts::gloas::BUILDER_INDEX_SELF_BUILD;

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
        let keys = self.pq_keys.clone().expect("PQ harness keys");
        let spec = self.spec.clone();
        let validators = validators.iter().copied().collect();
        tokio::task::spawn_blocking(move || make_pq_block(state, slot, &validators, &keys, &spec))
            .await
            .expect("PQ harness block production should run")
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
            parent_block_hash: *state.latest_block_hash().expect("execution parent"),
            parent_block_root: parent_root,
            block_hash: execution_block_hash,
            prev_randao,
            builder_index: BUILDER_INDEX_SELF_BUILD,
            slot,
            execution_requests_root: ExecutionRequestsPq::<E>::default().tree_hash_root(),
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
