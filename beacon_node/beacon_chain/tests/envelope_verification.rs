use beacon_chain::NotifyExecutionLayer;
use beacon_chain::execution_proof_verification::GossipVerifiedExecutionProof;
use beacon_chain::payload_envelope_verification::{EnvelopeError, EnvelopeSource};
use beacon_chain::test_utils::{
    BeaconChainHarness, fork_name_from_env, generate_data_column_sidecars_from_block, test_spec,
};
use bls::PublicKeyBytes;
use eth2::types::EventKind;
use std::sync::Arc;
use types::execution::{ExecutionProof, ProofData, PublicInput, SignedExecutionProof};
use types::{
    Address, BlockImportSource, Epoch, ExecPayload, ForkName, Hash256, MinimalEthSpec, Slot,
    WithdrawalRequest,
};

type E = MinimalEthSpec;

#[tokio::test]
async fn pre_gloas_block_import_records_payload_gas_limit() {
    if fork_name_from_env() != Some(ForkName::Fulu) {
        return;
    }

    let mut spec = test_spec::<E>();
    spec.gloas_fork_epoch = Some(Epoch::new(1));
    let harness = BeaconChainHarness::builder(E::default())
        .spec(Arc::new(spec))
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.extend_to_slot(Slot::new(1)).await;

    let head = harness.chain.head_beacon_block();
    let payload = head
        .message()
        .execution_payload()
        .expect("Fulu block should contain an execution payload");
    assert_eq!(
        harness
            .chain
            .observed_execution_payloads
            .get_gas_limit(payload.block_hash()),
        Some(payload.gas_limit())
    );
}

#[tokio::test]
async fn pre_gloas_block_import_skips_cache_without_scheduled_gloas() {
    if fork_name_from_env() != Some(ForkName::Fulu) {
        return;
    }

    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.extend_to_slot(Slot::new(1)).await;

    let head = harness.chain.head_beacon_block();
    let payload = head
        .message()
        .execution_payload()
        .expect("Fulu block should contain an execution payload");
    assert_eq!(
        harness
            .chain
            .observed_execution_payloads
            .get_gas_limit(payload.block_hash()),
        None
    );
}

#[tokio::test]
async fn startup_seeds_gloas_genesis_parent_payload() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    let head = harness.chain.canonical_head.cached_head();
    let genesis_bid = head
        .snapshot
        .beacon_state
        .latest_execution_payload_bid()
        .expect("Gloas genesis should contain an execution payload bid");
    assert_eq!(
        harness
            .chain
            .observed_execution_payloads
            .get_gas_limit(genesis_bid.parent_block_hash),
        Some(genesis_bid.gas_limit)
    );
}

#[tokio::test]
async fn lookup_imports_gloas_payload_after_restart() {
    if !fork_name_from_env().is_some_and(|fork| fork.gloas_enabled()) {
        return;
    }

    let spec = Arc::new(test_spec::<E>());
    let harness = BeaconChainHarness::builder(E::default())
        .spec(spec.clone())
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();
    harness.execution_block_generator().set_min_blob_count(1);

    harness.extend_to_slot(Slot::new(1)).await;

    let state = harness.get_current_state();
    let target_slot = Slot::new(2);
    harness.advance_slot();
    let (block_contents, envelope, _) = harness.make_block_with_envelope(state, target_slot).await;
    let block_root = block_contents.0.canonical_root();
    let custody_columns =
        generate_data_column_sidecars_from_block(&block_contents.0, &harness.chain.spec);
    assert!(
        !custody_columns.is_empty(),
        "test block should contain blobs"
    );

    harness
        .process_block(target_slot, block_root, block_contents)
        .await
        .expect("block should be processed");
    harness
        .chain
        .persist_fork_choice()
        .expect("fork choice should persist");

    let store = harness.chain.store.clone();
    let slot_clock = harness.chain.slot_clock.clone();
    drop(harness);
    let resume = || {
        BeaconChainHarness::builder(E::default())
            .spec(spec.clone())
            .deterministic_keypairs(64)
            .resumed_ephemeral_store(store.clone())
            .mock_execution_layer()
            .mock_execution_layer_all_payloads_valid()
            .testing_slot_clock(slot_clock.clone())
            .build()
    };
    let envelope = Arc::new(envelope.expect("Gloas block should produce an envelope"));

    let proof_resumed = resume();
    assert!(
        proof_resumed
            .chain
            .pending_payload_cache
            .get_bid(&block_root)
            .is_none(),
        "the pending bid cache should start empty after restart"
    );
    let proof_status = proof_resumed
        .chain
        .check_execution_proof_availability_and_import(GossipVerifiedExecutionProof {
            proof: Arc::new(SignedExecutionProof {
                message: ExecutionProof {
                    proof_data: ProofData::new(vec![1]).expect("proof data"),
                    proof_type: 0,
                    public_input: PublicInput {
                        new_payload_request_root: Hash256::random(),
                    },
                    beacon_block_root: block_root,
                },
                validator_index: 0,
                signature: bls::Signature::infinity().expect("infinity signature"),
            }),
            block_slot: target_slot,
        })
        .await
        .expect("execution proof should be accepted after restart");
    assert!(matches!(
        proof_status,
        beacon_chain::AvailabilityProcessingStatus::MissingComponents(..)
    ));
    assert!(
        proof_resumed
            .chain
            .pending_payload_cache
            .get_bid(&block_root)
            .is_some(),
        "execution-proof processing should restore the persisted bid"
    );
    drop(proof_resumed);

    let column_resumed = resume();

    assert!(
        column_resumed
            .chain
            .pending_payload_cache
            .get_bid(&block_root)
            .is_none(),
        "the pending bid cache should start empty after restart"
    );

    let column_status = column_resumed
        .chain
        .process_rpc_custody_columns(custody_columns.clone())
        .await
        .expect("custody columns should be accepted after restart");
    assert!(matches!(
        column_status,
        beacon_chain::AvailabilityProcessingStatus::MissingComponents(..)
    ));
    assert!(
        column_resumed
            .chain
            .pending_payload_cache
            .get_bid(&block_root)
            .is_some(),
        "custody-column processing should restore the persisted bid"
    );
    drop(column_resumed);

    let envelope_resumed = resume();
    assert!(
        envelope_resumed
            .chain
            .pending_payload_cache
            .get_bid(&block_root)
            .is_none(),
        "the pending bid cache should start empty after restart"
    );
    let verified_envelope = envelope_resumed
        .chain
        .verify_envelope_for_gossip(envelope, EnvelopeSource::Rpc)
        .await
        .expect("envelope should verify");
    let envelope_status = envelope_resumed
        .chain
        .process_execution_payload_envelope(
            block_root,
            verified_envelope,
            NotifyExecutionLayer::Yes,
            BlockImportSource::Lookup,
            || Ok(()),
        )
        .await
        .expect("envelope should be accepted after restart");
    assert!(matches!(
        envelope_status,
        beacon_chain::AvailabilityProcessingStatus::MissingComponents(..)
    ));
    assert!(
        envelope_resumed
            .chain
            .pending_payload_cache
            .get_bid(&block_root)
            .is_some(),
        "envelope processing should restore the persisted bid"
    );
    let import_status = envelope_resumed
        .chain
        .process_rpc_custody_columns(custody_columns)
        .await
        .expect("custody columns should complete the payload import");
    assert!(matches!(
        import_status,
        beacon_chain::AvailabilityProcessingStatus::Imported(..)
    ));
}

/// An envelope whose `execution_requests` don't hash to the bid's committed
/// `execution_requests_root` must be rejected by the full gossip verification path.
#[tokio::test]
async fn gossip_rejects_execution_requests_root_mismatch() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.extend_to_slot(Slot::new(1)).await;

    let state = harness.get_current_state();
    let target_slot = Slot::new(2);
    harness.advance_slot();
    let (block_contents, opt_envelope, _new_state) =
        harness.make_block_with_envelope(state, target_slot).await;

    let block_root = block_contents.0.canonical_root();
    harness
        .process_block(target_slot, block_root, block_contents)
        .await
        .expect("block should be processed");

    let mut signed_envelope = opt_envelope.expect("Gloas block should produce an envelope");
    let block_hash = signed_envelope.message.payload.block_hash;
    signed_envelope
        .message
        .execution_requests
        .withdrawals
        .push(WithdrawalRequest {
            source_address: Address::repeat_byte(0),
            validator_pubkey: PublicKeyBytes::empty(),
            amount: 0,
        });

    let result = harness
        .chain
        .verify_envelope_for_gossip(Arc::new(signed_envelope), EnvelopeSource::Gossip)
        .await;
    assert!(matches!(
        result,
        Err(EnvelopeError::ExecutionRequestsRootMismatch { .. })
    ));
    assert_eq!(
        harness
            .chain
            .observed_execution_payloads
            .get_gas_limit(block_hash),
        None
    );
}

#[tokio::test]
async fn gossip_verified_envelope_records_payload_gas_limit() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.extend_to_slot(Slot::new(1)).await;

    let state = harness.get_current_state();
    let target_slot = Slot::new(2);
    harness.advance_slot();
    let (block_contents, opt_envelope, _new_state) =
        harness.make_block_with_envelope(state, target_slot).await;

    let block_root = block_contents.0.canonical_root();
    harness
        .process_block(target_slot, block_root, block_contents)
        .await
        .expect("block should be processed");

    let signed_envelope = opt_envelope.expect("Gloas block should produce an envelope");
    let block_hash = signed_envelope.message.payload.block_hash;
    let gas_limit = signed_envelope.message.payload.gas_limit;
    assert_eq!(
        harness
            .chain
            .observed_execution_payloads
            .get_gas_limit(block_hash),
        None
    );

    harness
        .chain
        .verify_envelope_for_gossip(Arc::new(signed_envelope), EnvelopeSource::Gossip)
        .await
        .expect("envelope should pass gossip verification");

    assert_eq!(
        harness
            .chain
            .observed_execution_payloads
            .get_gas_limit(block_hash),
        Some(gas_limit)
    );
}

#[tokio::test]
async fn gossip_ignores_subsequent_envelope_from_same_builder() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.extend_to_slot(Slot::new(1)).await;

    let state = harness.get_current_state();
    let target_slot = Slot::new(2);
    harness.advance_slot();
    let (block_contents, opt_envelope, _new_state) =
        harness.make_block_with_envelope(state, target_slot).await;

    let block_root = block_contents.0.canonical_root();
    harness
        .process_block(target_slot, block_root, block_contents)
        .await
        .expect("block should be processed");

    let signed_envelope = opt_envelope.expect("Gloas block should produce an envelope");
    let envelope = Arc::new(signed_envelope);

    harness
        .chain
        .verify_envelope_for_gossip(envelope.clone(), EnvelopeSource::Gossip)
        .await
        .expect("first envelope should pass gossip verification");
    let second_result = harness
        .chain
        .verify_envelope_for_gossip(envelope, EnvelopeSource::Gossip)
        .await;

    assert!(matches!(
        second_result,
        Err(EnvelopeError::EnvelopeAlreadySeen { .. })
    ));
}

#[tokio::test]
async fn gossip_ignores_subsequent_envelope_with_modified_slot() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.extend_to_slot(Slot::new(1)).await;

    let state = harness.get_current_state();
    let target_slot = Slot::new(2);
    harness.advance_slot();
    let (block_contents, opt_envelope, _new_state) =
        harness.make_block_with_envelope(state, target_slot).await;

    let block_root = block_contents.0.canonical_root();
    harness
        .process_block(target_slot, block_root, block_contents)
        .await
        .expect("block should be processed");

    let signed_envelope = opt_envelope.expect("Gloas block should produce an envelope");
    let envelope = Arc::new(signed_envelope);

    harness
        .chain
        .verify_envelope_for_gossip(envelope.clone(), EnvelopeSource::Gossip)
        .await
        .expect("first envelope should pass gossip verification");

    let mut replayed_envelope = (*envelope).clone();
    replayed_envelope.message.payload.slot_number += 1;

    let second_result = harness
        .chain
        .verify_envelope_for_gossip(Arc::new(replayed_envelope), EnvelopeSource::Gossip)
        .await;

    assert!(matches!(
        second_result,
        Err(EnvelopeError::EnvelopeAlreadySeen { .. })
    ));
}

#[tokio::test]
async fn http_envelope_bypasses_deduplication_but_marks_seen() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.extend_to_slot(Slot::new(1)).await;

    let state = harness.get_current_state();
    let target_slot = Slot::new(2);
    harness.advance_slot();
    let (block_contents, opt_envelope, _new_state) =
        harness.make_block_with_envelope(state, target_slot).await;

    let block_root = block_contents.0.canonical_root();
    harness
        .process_block(target_slot, block_root, block_contents)
        .await
        .expect("block should be processed");

    let signed_envelope = opt_envelope.expect("Gloas block should produce an envelope");
    let envelope = Arc::new(signed_envelope);

    harness
        .chain
        .verify_envelope_for_gossip(envelope.clone(), EnvelopeSource::Http)
        .await
        .expect("first HTTP publish should verify");

    // Re-publishing the same envelope is not rejected as a duplicate
    harness
        .chain
        .verify_envelope_for_gossip(envelope.clone(), EnvelopeSource::Http)
        .await
        .expect("re-published envelope should verify");

    // If the envelope is later published on gossip, then the call should return an error
    let gossip_result = harness
        .chain
        .verify_envelope_for_gossip(envelope, EnvelopeSource::Gossip)
        .await;

    assert!(matches!(
        gossip_result,
        Err(EnvelopeError::EnvelopeAlreadySeen { .. })
    ));
}

#[tokio::test]
async fn rpc_envelope_bypasses_deduplication_but_marks_seen() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.extend_to_slot(Slot::new(1)).await;

    let state = harness.get_current_state();
    let target_slot = Slot::new(2);
    harness.advance_slot();
    let (block_contents, opt_envelope, _new_state) =
        harness.make_block_with_envelope(state, target_slot).await;

    let block_root = block_contents.0.canonical_root();
    harness
        .process_block(target_slot, block_root, block_contents)
        .await
        .expect("block should be processed");

    let signed_envelope = opt_envelope.expect("Gloas block should produce an envelope");
    let envelope = Arc::new(signed_envelope);

    harness
        .chain
        .verify_envelope_for_gossip(envelope.clone(), EnvelopeSource::Rpc)
        .await
        .expect("first RPC envelope should verify");

    // Re-fetching the same envelope over RPC is not rejected as a duplicate
    harness
        .chain
        .verify_envelope_for_gossip(envelope.clone(), EnvelopeSource::Rpc)
        .await
        .expect("re-fetched envelope should verify");

    // If the envelope is later published on gossip, then the call should return an error
    let gossip_result = harness
        .chain
        .verify_envelope_for_gossip(envelope, EnvelopeSource::Gossip)
        .await;

    assert!(matches!(
        gossip_result,
        Err(EnvelopeError::EnvelopeAlreadySeen { .. })
    ));
}

#[tokio::test]
async fn gossip_seen_envelope_can_be_reverified_via_non_gossip() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    harness.extend_to_slot(Slot::new(1)).await;

    let state = harness.get_current_state();
    let target_slot = Slot::new(2);
    harness.advance_slot();
    let (block_contents, opt_envelope, _new_state) =
        harness.make_block_with_envelope(state, target_slot).await;

    let block_root = block_contents.0.canonical_root();
    harness
        .process_block(target_slot, block_root, block_contents)
        .await
        .expect("block should be processed");

    let signed_envelope = opt_envelope.expect("Gloas block should produce an envelope");
    let envelope = Arc::new(signed_envelope);
    let event_handler = harness.chain.event_handler.as_ref().unwrap();
    let mut gossip_receiver = event_handler.subscribe_execution_payload_gossip();

    harness
        .chain
        .verify_envelope_for_gossip(envelope.clone(), EnvelopeSource::Gossip)
        .await
        .expect("gossip envelope should verify and be marked as seen");

    // Check emitted SSE event
    let gossip_event = gossip_receiver
        .try_recv()
        .expect("first envelope observation should emit execution_payload_gossip");
    if let EventKind::ExecutionPayloadGossip(sse) = gossip_event {
        assert_eq!(sse.slot, target_slot);
        assert_eq!(sse.block_root, block_root);
    } else {
        panic!("expected ExecutionPayloadGossip event, got {gossip_event:?}");
    }

    harness
        .chain
        .verify_envelope_for_gossip(envelope.clone(), EnvelopeSource::Rpc)
        .await
        .expect("RPC lookup should re-verify an envelope already seen on gossip");

    assert!(
        gossip_receiver.try_recv().is_err(),
        "an envelope re-verified over RPC must not re-emit execution_payload_gossip"
    );

    harness
        .chain
        .verify_envelope_for_gossip(envelope, EnvelopeSource::Http)
        .await
        .expect("HTTP publish should re-verify an envelope already seen on gossip");

    assert!(
        gossip_receiver.try_recv().is_err(),
        "an envelope re-verified over HTTP must not re-emit execution_payload_gossip"
    );
}
