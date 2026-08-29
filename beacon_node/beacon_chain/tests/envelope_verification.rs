use beacon_chain::payload_envelope_verification::EnvelopeError;
use beacon_chain::payload_envelope_verification::EnvelopeSource;
use beacon_chain::test_utils::{BeaconChainHarness, fork_name_from_env};
use bls::PublicKeyBytes;
use eth2::types::EventKind;
use proto_array::ExecutionStatus;
use std::sync::Arc;
use types::{Address, Hash256, MinimalEthSpec, Slot, WithdrawalRequest};

type E = MinimalEthSpec;

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

/// Helper: build a Gloas harness with a mock execution layer.
fn gloas_harness() -> BeaconChainHarness<beacon_chain::test_utils::EphemeralHarnessType<E>> {
    BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build()
}

/// Helper: produce the block and envelope for `slot`, import both, and return the block root.
async fn import_block_and_envelope(
    harness: &BeaconChainHarness<beacon_chain::test_utils::EphemeralHarnessType<E>>,
    slot: Slot,
) -> Hash256 {
    let state = harness.get_current_state();
    harness.advance_slot();
    let (block_contents, opt_envelope, _) = harness.make_block_with_envelope(state, slot).await;
    let block_root = block_contents.0.canonical_root();

    let block = block_contents.0.clone();
    harness
        .process_block(slot, block_root, block_contents)
        .await
        .expect("block should be processed");

    // Without its custody columns the envelope never reaches fork choice.
    harness.process_gossip_columns(&block, None).await;

    let signed_envelope = opt_envelope.expect("Gloas block should produce an envelope");
    let gossip_verified = harness
        .chain
        .verify_envelope_for_gossip(Arc::new(signed_envelope), EnvelopeSource::Gossip)
        .await
        .expect("envelope gossip verification should succeed");

    let status = harness
        .chain
        .process_execution_payload_envelope(
            block_root,
            gossip_verified,
            beacon_chain::NotifyExecutionLayer::Yes,
            types::BlockImportSource::Gossip,
            #[allow(clippy::result_large_err)]
            || Ok(()),
        )
        .await
        .expect("envelope import should succeed even when the execution layer is syncing");

    assert!(
        matches!(
            status,
            beacon_chain::AvailabilityProcessingStatus::Imported(..)
        ),
        "envelope for slot {slot} should import, got {status:?}",
    );

    // The next block builds on the payload status of the head. If the head does not catch up
    // here, every block extends the `EMPTY` variant of its parent.
    harness.chain.recompute_head_at_current_slot().await;

    block_root
}

/// Helper: the execution status that fork choice holds for the payload of a block.
fn execution_status(
    harness: &BeaconChainHarness<beacon_chain::test_utils::EphemeralHarnessType<E>>,
    block_root: Hash256,
) -> ExecutionStatus {
    harness
        .chain
        .canonical_head
        .fork_choice_read_lock()
        .get_block(&block_root)
        .expect("block should be in fork choice")
        .execution_status
}

/// An execution layer that answers `SYNCING` must not stop the import of an envelope. The
/// node holds the payload as `Optimistic`. It does not refuse the payload with
/// `OptimisticSyncNotSupported`.
#[tokio::test]
async fn syncing_execution_layer_imports_payload_optimistically() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let harness = gloas_harness();
    harness.extend_to_slot(Slot::new(1)).await;

    harness
        .mock_execution_layer
        .as_ref()
        .expect("mock execution layer")
        .server
        .all_payloads_syncing(true);

    let block_root = import_block_and_envelope(&harness, Slot::new(2)).await;

    assert!(
        execution_status(&harness, block_root).is_strictly_optimistic(),
        "a payload the execution layer could not validate must be held as optimistic",
    );
}

/// A later valid payload promotes every optimistic payload below it. The node does not fetch
/// an old payload again.
#[tokio::test]
async fn a_later_valid_payload_promotes_its_optimistic_ancestors() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let harness = gloas_harness();
    harness.extend_to_slot(Slot::new(1)).await;

    let mock = harness
        .mock_execution_layer
        .as_ref()
        .expect("mock execution layer");

    // The node imports two slots while the execution layer answers `SYNCING`.
    mock.server.all_payloads_syncing(true);
    let first_root = import_block_and_envelope(&harness, Slot::new(2)).await;
    let second_root = import_block_and_envelope(&harness, Slot::new(3)).await;

    assert!(execution_status(&harness, first_root).is_strictly_optimistic());
    assert!(execution_status(&harness, second_root).is_strictly_optimistic());

    // The execution layer catches up and validates the next payload.
    mock.server.all_payloads_valid();
    let third_root = import_block_and_envelope(&harness, Slot::new(4)).await;

    assert!(
        execution_status(&harness, third_root).is_valid_and_post_bellatrix(),
        "the payload the execution layer validated must be valid",
    );
    assert!(
        execution_status(&harness, second_root).is_valid_and_post_bellatrix(),
        "its parent's payload is vouched for by the valid descendant",
    );
    assert!(
        execution_status(&harness, first_root).is_valid_and_post_bellatrix(),
        "promotion must walk the whole ancestry, not just one step",
    );
}
