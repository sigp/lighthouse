use beacon_chain::payload_envelope_verification::EnvelopeError;
use beacon_chain::payload_envelope_verification::EnvelopeSource;
use beacon_chain::test_utils::{BeaconChainHarness, fork_name_from_env};
use bls::PublicKeyBytes;
use eth2::types::EventKind;
use std::sync::Arc;
use types::{Address, ExecPayload, ForkName, MinimalEthSpec, Slot, WithdrawalRequest};

type E = MinimalEthSpec;

#[tokio::test]
async fn pre_gloas_block_import_records_payload_gas_limit() {
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
        Some(payload.gas_limit())
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
