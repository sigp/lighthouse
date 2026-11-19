#![cfg(all(feature = "spec-minimal", not(debug_assertions)))]

use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use execution_layer::{
    NewPayloadRequest, NewPayloadRequestGloas, PayloadAttributes, PayloadParameters,
};
use fork_choice::ForkchoiceUpdateParameters;
use ssz_types::ProgressiveVariableList;
use state_processing::{
    ConsensusContext, VerifySignatures,
    common::get_attestation_participation_flag_indices,
    per_block_processing::{
        BlockSignatureStrategy, VerifyBlockRoot,
        errors::{AttestationInvalid, BlockProcessingError, HeaderInvalid, IntoWithIndex},
        per_block_processing, verify_attestation_for_block_inclusion,
    },
    pq::{LEAF_OFFSET_BEACON_PROPOSER, slot_leaf_index},
    state_advance::complete_state_advance,
};
use types::{consts::altair::TIMELY_HEAD_FLAG_INDEX, *};

type E = MinimalEthSpec;

#[tokio::test]
async fn pq_reference_chain_finalizes_and_rejects_bad_authentication() {
    let spec = ForkName::Pq.make_genesis_spec(E::default_spec());
    let validator_count = E::slots_per_epoch() as usize;
    let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
        .spec(spec.into())
        .deterministic_keypairs(validator_count)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let validators = (0..validator_count).collect::<Vec<_>>();
    let mut state = harness.get_current_state();
    assert_mock_engine_pq_requests(&harness, &state).await;
    let end = E::slots_per_epoch() * 5;
    for slot in (1..=end).map(Slot::new) {
        let (root, next_state) = harness
            .add_attested_block_at_slot(slot, state, &validators)
            .await
            .unwrap();
        assert_eq!(harness.head_block_root(), Hash256::from(root));
        state = next_state;
    }
    assert_eq!(state.finalized_checkpoint().epoch, Epoch::new(3));
    // Independently replayed using consensus-specs a4d16c5be5e8bf8c5a3fb323ee1cb0293efecb1c.
    assert_eq!(
        state.canonical_root().unwrap(),
        "0x104aa66ad03898b2f3dd934ae2bc36bb1a327d3645eb2a17024a952d2a1af13c"
            .parse::<Hash256>()
            .unwrap(),
    );
    assert_eq!(
        harness.get_current_state().finalized_checkpoint(),
        state.finalized_checkpoint(),
    );

    let slot = Slot::new(end + 1);
    let ((signed, _), _) = harness
        .make_pq_block(state.clone(), slot, &validators)
        .await;
    complete_state_advance(&mut state, None, slot, None, &harness.spec).unwrap();
    state.build_caches(&harness.spec).unwrap();
    let SignedBeaconBlock::Pq(block) = &*signed else {
        panic!("expected a PQ block");
    };
    let leaf = slot_leaf_index(slot, LEAF_OFFSET_BEACON_PROPOSER).unwrap();
    let apply = |signed: &SignedBeaconBlock<E>| {
        per_block_processing(
            &mut state.clone(),
            signed,
            BlockSignatureStrategy::VerifyIndividual,
            VerifyBlockRoot::True,
            &mut ConsensusContext::new(slot),
            &harness.spec,
        )
    };

    assert_eq!(apply(&signed), Ok(()));
    let wrong_leaf =
        harness.sign_pq_block(BeaconBlock::Pq(block.message.clone()), &state, leaf + 1);
    assert_eq!(
        apply(&wrong_leaf),
        Err(BlockProcessingError::HeaderInvalid {
            reason: HeaderInvalid::ProposalSignatureInvalid
        }),
    );

    let mut bad_proof = block.message.clone();
    bad_proof.body.proof[10] ^= 1;
    let bad_proof = harness.sign_pq_block(BeaconBlock::Pq(bad_proof), &state, leaf);
    assert_eq!(
        apply(&bad_proof),
        Err(BlockProcessingError::InvalidAttestationProof),
    );

    let mut bad_vrf = block.message.clone();
    bad_vrf.body.randao_reveal[0] = Hash256::repeat_byte(0xde);
    let bad_vrf = harness.sign_pq_block(BeaconBlock::Pq(bad_vrf), &state, leaf);
    assert_eq!(
        apply(&bad_vrf),
        Err(BlockProcessingError::RandaoSignatureInvalid),
    );

    let attestation = block.message.body.attestations[0].clone();
    let mut early = attestation.clone();
    early.data.slot += 1;
    let mut context = ConsensusContext::new(slot);
    let result = verify_attestation_for_block_inclusion(
        &state,
        AttestationRef::Pq(&early),
        &mut context,
        VerifySignatures::False,
        &harness.spec,
    );
    let reason: BlockProcessingError = result
        .err()
        .expect("early attestation rejected")
        .into_with_index(0);
    assert!(matches!(
        reason,
        BlockProcessingError::AttestationInvalid {
            reason: AttestationInvalid::IncludedTooEarly { delay: 2, .. },
            ..
        }
    ));

    let flags = |delay| {
        get_attestation_participation_flag_indices(
            &state,
            &attestation.data,
            Some(state.latest_block_header().slot),
            delay,
            &harness.spec,
        )
        .unwrap()
    };
    assert!(flags(2).contains(&TIMELY_HEAD_FLAG_INDEX));
    assert!(!flags(3).contains(&TIMELY_HEAD_FLAG_INDEX));
}

async fn assert_mock_engine_pq_requests(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    state: &BeaconState<E>,
) {
    let mock = &harness.mock_execution_layer.as_ref().unwrap().server;
    let parent_hash = *state.latest_block_hash().unwrap();
    let parent_root = harness.head_block_root();
    let deposit = DepositRequest {
        pubkey: encode_deposit_pubkey(state.get_validator(0).unwrap().pubkey).unwrap(),
        withdrawal_credentials: Hash256::repeat_byte(0x02),
        amount: harness.spec.effective_balance_increment,
        signature: bls::SignatureBytes::empty(),
        index: 0,
    };
    {
        let mut generator = mock.execution_block_generator();
        generator.set_generate_blobs(false);
        generator.set_next_execution_requests(ExecutionRequests::Pq(ExecutionRequestsPq {
            deposits: ProgressiveVariableList::new(vec![deposit.clone()]).unwrap(),
            ..Default::default()
        }));
    }
    let timestamp = state.genesis_time() + harness.spec.get_slot_duration().as_secs();
    let attributes = PayloadAttributes::new(
        timestamp,
        *state.get_randao_mix(state.current_epoch()).unwrap(),
        Address::ZERO,
        Some(vec![]),
        Some(parent_root),
        Some(1),
        Some(30_000_000),
        None,
    );
    let layer = harness.chain.execution_layer.as_ref().unwrap();
    let proposal = layer
        .get_payload_gloas(PayloadParameters {
            parent_hash,
            parent_gas_limit: None,
            proposer_gas_limit: None,
            payload_attributes: &attributes,
            forkchoice_update_params: &ForkchoiceUpdateParameters {
                head_root: parent_root,
                head_hash: Some(parent_hash),
                justified_hash: Some(parent_hash),
                finalized_hash: Some(parent_hash),
            },
            current_fork: ForkName::Pq,
        })
        .await
        .expect("PQ uses the Gloas Engine API methods");
    assert_eq!(&*proposal.execution_requests.deposits, &[deposit]);
    assert_eq!(
        mock.take_previous_request().unwrap()["method"],
        "engine_getPayloadV6"
    );
    let result = layer
        .notify_new_payload(NewPayloadRequest::Gloas(NewPayloadRequestGloas {
            execution_payload: &proposal.payload,
            versioned_hashes: Vec::new(),
            parent_beacon_block_root: parent_root,
            execution_requests: &proposal.execution_requests,
        }))
        .await
        .unwrap();
    assert_eq!(result, execution_layer::PayloadStatus::Valid);
    assert_eq!(
        mock.take_previous_request().unwrap()["method"],
        "engine_newPayloadV5"
    );
}
