use beacon_chain::payload_envelope_verification::EnvelopeError;
use beacon_chain::payload_envelope_verification::gossip_verified_envelope::AllowDuplicates;
use beacon_chain::test_utils::{BeaconChainHarness, fork_name_from_env};
use bls::PublicKeyBytes;
use std::sync::Arc;
use types::{Address, MinimalEthSpec, Slot, WithdrawalRequest};

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
        .verify_envelope_for_gossip(Arc::new(signed_envelope), AllowDuplicates::No)
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
        .verify_envelope_for_gossip(envelope.clone(), AllowDuplicates::No)
        .await
        .expect("first envelope should pass gossip verification");
    let second_result = harness
        .chain
        .verify_envelope_for_gossip(envelope, AllowDuplicates::No)
        .await;

    assert!(matches!(
        second_result,
        Err(EnvelopeError::EnvelopeAlreadySeen { .. })
    ));
}

/// The publish path opts out of deduplication, so that a re-submitted envelope is always
/// broadcast. It still marks the envelope as seen, so gossip keeps deduplicating against it.
#[tokio::test]
async fn already_seen_envelope_is_verified_when_duplicates_are_allowed() {
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
        .verify_envelope_for_gossip(envelope.clone(), AllowDuplicates::Yes)
        .await
        .expect("first envelope should pass gossip verification");
    harness
        .chain
        .verify_envelope_for_gossip(envelope.clone(), AllowDuplicates::Yes)
        .await
        .expect("already seen envelope should pass gossip verification");

    let gossip_result = harness
        .chain
        .verify_envelope_for_gossip(envelope, AllowDuplicates::No)
        .await;

    assert!(matches!(
        gossip_result,
        Err(EnvelopeError::EnvelopeAlreadySeen { .. })
    ));
}
