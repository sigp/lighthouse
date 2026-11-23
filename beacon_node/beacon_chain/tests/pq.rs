#![cfg(all(feature = "spec-minimal", not(debug_assertions)))]

use beacon_chain::AvailabilityProcessingStatus;
use beacon_chain::payload_envelope_verification::EnvelopeError;
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
        BlockSignatureStrategy, VerifyBlockRoot, compute_timestamp_at_slot,
        errors::{AttestationInvalid, BlockProcessingError, HeaderInvalid, IntoWithIndex},
        per_block_processing, verify_attestation_for_block_inclusion,
    },
    pq::{LEAF_OFFSET_BEACON_PROPOSER, LEAF_OFFSET_PAYLOAD_ENVELOPE, slot_leaf_index},
    state_advance::complete_state_advance,
};
use std::sync::Arc;
use types::{consts::altair::TIMELY_HEAD_FLAG_INDEX, *};

type E = MinimalEthSpec;

#[tokio::test]
async fn pq_rpc_envelope_rejects_wrong_leaf_and_imports_concurrently() {
    let spec = Arc::new(ForkName::Pq.make_genesis_spec(E::default_spec()));
    let harness = BeaconChainHarness::<EphemeralHarnessType<E>>::builder(E::default())
        .spec(spec.clone())
        .deterministic_keypairs(E::slots_per_epoch() as usize)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .mock_execution_layer_all_payloads_valid()
        .build();
    let slot = Slot::new(1);
    let (contents, state) = harness
        .make_pq_block(harness.get_current_state(), slot, &[])
        .await;
    let root = contents.0.canonical_root();
    let bid = contents
        .0
        .message()
        .body()
        .signed_execution_payload_bid()
        .unwrap();
    let message = ExecutionPayloadEnvelopePq {
        payload: ExecutionPayloadGloas {
            parent_hash: bid.message().parent_block_hash(),
            block_hash: bid.message().block_hash(),
            prev_randao: bid.message().prev_randao(),
            gas_limit: bid.message().gas_limit(),
            timestamp: compute_timestamp_at_slot(&state, slot, &spec).unwrap(),
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
        beacon_block_root: root,
        parent_beacon_block_root: contents.0.parent_root(),
    };
    let domain = spec.get_domain(
        state.current_epoch(),
        Domain::BeaconBuilder,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let leaf = slot_leaf_index(slot, LEAF_OFFSET_PAYLOAD_ENVELOPE).unwrap();
    let proposer_index = state.latest_block_header().proposer_index as usize;
    let sign = |leaf| {
        Arc::new(SignedExecutionPayloadEnvelopePq {
            signature: harness.sign_pq_test_message(
                proposer_index,
                leaf,
                message.signing_root(domain),
            ),
            message: message.clone(),
        })
    };
    harness.process_block(slot, root, contents).await.unwrap();
    let chain = &harness.chain;
    assert!(matches!(
        chain.verify_pq_envelope_for_rpc(sign(leaf + 1)).await,
        Err(EnvelopeError::BadSignature)
    ));
    let mut mismatched_requests = message.clone();
    mismatched_requests
        .execution_requests
        .voluntary_exits
        .push(VoluntaryExitRequest {
            pubkey: XmssPublicKey::from([42; 32]),
        })
        .unwrap();
    let mismatched_requests = Arc::new(SignedExecutionPayloadEnvelopePq {
        signature: harness.sign_pq_test_message(
            proposer_index,
            leaf,
            mismatched_requests.signing_root(domain),
        ),
        message: mismatched_requests,
    });
    assert!(matches!(
        chain.verify_pq_envelope_for_rpc(mismatched_requests).await,
        Err(EnvelopeError::EnvelopeProcessingError(
            state_processing::envelope_processing::EnvelopeProcessingError::ExecutionRequestsRootMismatch { .. }
        ))
    ));
    let signed = sign(leaf);
    let (first, second) = tokio::join!(
        chain.verify_pq_envelope_for_rpc(signed.clone()),
        chain.verify_pq_envelope_for_rpc(signed.clone()),
    );
    let (first, second) = tokio::join!(
        chain.process_verified_pq_envelope(first.unwrap()),
        chain.process_verified_pq_envelope(second.unwrap()),
    );
    for result in [first, second] {
        assert!(
            matches!(result.unwrap(), AvailabilityProcessingStatus::Imported(_, imported) if imported == root)
        );
    }
    assert!(matches!(
        chain.verify_pq_envelope_for_rpc(signed.clone()).await,
        Err(EnvelopeError::EnvelopeAlreadySeen { .. })
    ));
    assert_eq!(
        chain.get_rpc_payload_envelope(&root).unwrap().unwrap(),
        SignedExecutionPayloadEnvelope::Pq(Arc::unwrap_or_clone(signed)),
    );
}

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
    assert!(matches!(
        harness.chain.check_genesis_execution_payload_is_correct().await.unwrap(),
        beacon_chain::bellatrix_readiness::GenesisExecutionPayloadStatus::Correct(hash)
            if hash == *state.latest_block_hash().unwrap()
    ));
    assert_mock_engine_pq_requests(&harness, &state).await;
    let end = E::slots_per_epoch() * 5;
    for slot in (1..=end).map(Slot::new) {
        let (root, next_state) = harness
            .add_attested_block_at_slot(slot, state, &validators)
            .await
            .unwrap();
        assert_eq!(harness.head_block_root(), Hash256::from(root));
        state = next_state;
        if slot == Slot::new(1) {
            check_pq_gossip(&harness, &state, slot);
        }
    }
    assert_eq!(state.finalized_checkpoint().epoch, Epoch::new(3));
    // Independently replayed using consensus-specs 2f43bc0f989f47af81df390a90bc1f78e2436323.
    assert_eq!(
        state.canonical_root().unwrap(),
        "0x8026e5211fd1a7d99a50637b59330992c2d29d1f2ab6ec7aebd40ad241bb16fd"
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

fn check_pq_gossip(
    harness: &BeaconChainHarness<EphemeralHarnessType<E>>,
    state: &BeaconState<E>,
    slot: Slot,
) {
    use beacon_chain::attestation_verification::Error;
    use pq_prover::{ProverBackend, ReferenceBackend};
    use state_processing::pq::{self, LEAF_OFFSET_AGGREGATE_AND_PROOF};
    use tree_hash::TreeHash;

    let chain = &harness.chain;
    let committee = state.get_beacon_committee(slot, 0).unwrap();
    let index = *committee.committee.first().unwrap();
    let Attestation::Pq(mut attestation) = chain.produce_unaggregated_attestation(slot, 0).unwrap()
    else {
        panic!("expected PQ attestation");
    };
    attestation.aggregation_bits.set(0, true).unwrap();
    let statement =
        pq::attestation_statement(state, &attestation.data, &[index as u64], &harness.spec)
            .unwrap();
    let message = Hash256::from(statement.message);
    let mut single = SingleAttestationPq {
        committee_index: 0,
        attester_index: index as u64,
        data: attestation.data.clone(),
        signature: harness.sign_pq_test_message(index, statement.leaf_index + 1, message),
    };
    assert!(matches!(
        chain.verify_unaggregated_attestation_for_gossip(
            &SingleAttestation::Pq(single.clone()),
            None,
        ),
        Err(Error::InvalidSignature)
    ));
    single.signature = harness.sign_pq_test_message(index, statement.leaf_index, message);
    let single_message = SingleAttestation::Pq(single.clone());
    let verified = chain
        .verify_unaggregated_attestation_for_gossip(&single_message, None)
        .unwrap();
    let subnet = verified.subnet_id();
    assert!(u64::from(subnet) < harness.spec.attestation_subnet_count_pq);
    assert!(matches!(
        chain.verify_unaggregated_attestation_for_gossip(&single_message, None),
        Err(Error::PriorAttestationKnown { .. })
    ));

    let proof = ReferenceBackend
        .prove(&[statement], &[vec![single.signature]])
        .unwrap();
    let aggregate = AggregateAndProofPq {
        aggregator_index: index as u64,
        aggregate: attestation,
        proof: proof.into_bytes().try_into().unwrap(),
    };
    let proposer_domain = harness.spec.get_domain(
        state.current_epoch(),
        Domain::AggregateAndProof,
        &state.fork(),
        state.genesis_validators_root(),
    );
    let leaf = pq::slot_leaf_index(slot, LEAF_OFFSET_AGGREGATE_AND_PROOF).unwrap();
    let sign = |message: AggregateAndProofPq<E>, validator: usize, leaf: u64| {
        let root = message.tree_hash_root().signing_root(proposer_domain);
        SignedAggregateAndProof::Pq(SignedAggregateAndProofPq {
            message,
            signature: harness.sign_pq_test_message(validator, leaf, root),
        })
    };
    let mut bad_committee = aggregate.clone();
    bad_committee.aggregate.committee_bits.set(1, true).unwrap();
    assert!(matches!(
        chain.verify_aggregated_attestation_for_gossip(&sign(bad_committee, index, leaf)),
        Err(Error::NotExactlyOneCommitteeBitSet(2))
    ));
    let outsider = (0..state.validators().len())
        .find(|candidate| !committee.committee.contains(candidate))
        .unwrap();
    let mut bad_aggregator = aggregate.clone();
    bad_aggregator.aggregator_index = outsider as u64;
    assert!(matches!(
        chain.verify_aggregated_attestation_for_gossip(&sign(bad_aggregator, outsider, leaf)),
        Err(Error::AggregatorNotInCommittee { .. })
    ));
    assert!(matches!(
        chain.verify_aggregated_attestation_for_gossip(&sign(aggregate.clone(), index, leaf + 1)),
        Err(Error::InvalidSignature)
    ));
    let mut bad_proof = aggregate.clone();
    bad_proof.proof[0] ^= 1;
    assert!(matches!(
        chain.verify_aggregated_attestation_for_gossip(&sign(bad_proof, index, leaf)),
        Err(Error::InvalidSignature)
    ));
    let aggregate = sign(aggregate, index, leaf);
    let verified = chain
        .verify_aggregated_attestation_for_gossip(&aggregate)
        .unwrap();
    chain.add_to_block_inclusion_pool(verified).unwrap();
    assert_eq!(chain.op_pool.pq_attestation_candidates(slot).len(), 1);
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
            execution_requests: types::ExecutionRequestsRef::Pq(
                &(&proposal.execution_requests).into(),
            ),
        }))
        .await
        .unwrap();
    assert_eq!(result, execution_layer::PayloadStatus::Valid);
    assert_eq!(
        mock.take_previous_request().unwrap()["method"],
        "engine_newPayloadV5"
    );
}
