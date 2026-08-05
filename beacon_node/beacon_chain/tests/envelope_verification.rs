use beacon_chain::payload_envelope_verification::EnvelopeError;
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
        .verify_envelope_for_gossip(Arc::new(signed_envelope))
        .await;
    assert!(matches!(
        result,
        Err(EnvelopeError::ExecutionRequestsRootMismatch { .. })
    ));
}
