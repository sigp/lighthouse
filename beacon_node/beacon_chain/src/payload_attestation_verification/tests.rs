use bls::Signature;
use state_processing::AllCaches;
use types::{
    Domain, EthSpec, Hash256, MinimalEthSpec, PayloadAttestationData, PayloadAttestationMessage,
    SignedRoot, Slot,
};

use crate::{
    payload_attestation_verification::{
        Error as PayloadAttestationError,
        gossip_verified_payload_attestation::{
            GossipVerificationContext, VerifiedPayloadAttestationMessage,
        },
    },
    test_utils::{BeaconChainHarness, EphemeralHarnessType, fork_name_from_env},
};

type E = MinimalEthSpec;
type T = EphemeralHarnessType<E>;

const NUM_VALIDATORS: usize = 64;

struct TestContext {
    harness: BeaconChainHarness<T>,
    genesis_block_root: Hash256,
}

impl TestContext {
    fn new() -> Self {
        let harness = BeaconChainHarness::builder(E::default())
            .default_spec()
            .deterministic_keypairs(NUM_VALIDATORS)
            .fresh_ephemeral_store()
            .build();

        // Advance past genesis so `now_with_past_tolerance` doesn't underflow.
        harness
            .chain
            .slot_clock
            .set_current_time(harness.spec.get_slot_duration());
        let genesis_block_root = harness.chain.genesis_block_root;

        Self {
            harness,
            genesis_block_root,
        }
    }

    fn gossip_ctx(&self) -> GossipVerificationContext<'_, T> {
        self.harness.chain.payload_attestation_gossip_context()
    }

    fn ptc_members(&self, slot: Slot) -> Vec<usize> {
        let head = self.harness.chain.canonical_head.cached_head();
        let state = &head.snapshot.beacon_state;
        let ptc = state
            .get_ptc(slot, &self.harness.spec)
            .expect("should get PTC");
        ptc.0.to_vec()
    }

    fn sign_payload_attestation(
        &self,
        data: PayloadAttestationData,
        validator_index: u64,
    ) -> PayloadAttestationMessage {
        let head = self.harness.chain.canonical_head.cached_head();
        let state = &head.snapshot.beacon_state;
        let domain = self.harness.spec.get_domain(
            data.slot.epoch(E::slots_per_epoch()),
            Domain::PTCAttester,
            &state.fork(),
            state.genesis_validators_root(),
        );
        let message = data.signing_root(domain);
        let signature = self.harness.validator_keypairs[validator_index as usize]
            .sk
            .sign(message);
        PayloadAttestationMessage {
            validator_index,
            data,
            signature,
        }
    }
}

fn make_payload_attestation(
    slot: Slot,
    validator_index: u64,
    beacon_block_root: Hash256,
) -> PayloadAttestationMessage {
    PayloadAttestationMessage {
        validator_index,
        data: PayloadAttestationData {
            beacon_block_root,
            slot,
            payload_present: true,
            blob_data_available: true,
        },
        signature: Signature::empty(),
    }
}

#[test]
fn future_slot() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();

    let future_slot = Slot::new(5);
    let msg = make_payload_attestation(future_slot, 0, ctx.genesis_block_root);
    let result = VerifiedPayloadAttestationMessage::new(msg, &gossip);
    assert!(matches!(
        result,
        Err(PayloadAttestationError::FutureSlot { .. })
    ));
}

#[test]
fn past_slot() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    ctx.harness.chain.slot_clock.set_slot(5);
    let gossip = ctx.gossip_ctx();

    let msg = make_payload_attestation(Slot::new(0), 0, ctx.genesis_block_root);
    let result = VerifiedPayloadAttestationMessage::new(msg, &gossip);
    assert!(matches!(
        result,
        Err(PayloadAttestationError::PastSlot { .. })
    ));
}

#[test]
fn unknown_head_block() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();

    let unknown_root = Hash256::repeat_byte(0xff);
    let msg = make_payload_attestation(Slot::new(1), 0, unknown_root);
    let result = VerifiedPayloadAttestationMessage::new(msg, &gossip);
    assert!(
        matches!(
            result,
            Err(PayloadAttestationError::UnknownHeadBlock { .. })
        ),
        "expected UnknownHeadBlock, got: {:?}",
        result
    );
}

#[test]
fn not_in_ptc() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(1);

    let ptc_members = ctx.ptc_members(slot);
    let non_ptc_validator = (0..NUM_VALIDATORS as u64)
        .find(|&i| !ptc_members.contains(&(i as usize)))
        .expect("should find non-PTC validator");

    let msg = make_payload_attestation(slot, non_ptc_validator, ctx.genesis_block_root);
    let result = VerifiedPayloadAttestationMessage::new(msg, &gossip);
    assert!(matches!(
        result,
        Err(PayloadAttestationError::NotInPTC { .. })
    ));
}

#[test]
fn invalid_signature() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(1);

    let ptc_members = ctx.ptc_members(slot);
    let validator_index = ptc_members[0] as u64;

    let msg = make_payload_attestation(slot, validator_index, ctx.genesis_block_root);
    let result = VerifiedPayloadAttestationMessage::new(msg, &gossip);
    assert!(matches!(
        result,
        Err(PayloadAttestationError::InvalidSignature)
    ));
}

#[test]
fn valid_payload_attestation() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(1);

    let ptc_members = ctx.ptc_members(slot);
    let validator_index = ptc_members[0] as u64;

    let data = PayloadAttestationData {
        beacon_block_root: ctx.genesis_block_root,
        slot,
        payload_present: true,
        blob_data_available: true,
    };
    let msg = ctx.sign_payload_attestation(data, validator_index);
    let result = VerifiedPayloadAttestationMessage::new(msg, &gossip);
    assert!(
        result.is_ok(),
        "expected Ok, got: {:?}",
        result.unwrap_err()
    );
}

#[test]
fn duplicate_after_valid() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(1);

    let ptc_members = ctx.ptc_members(slot);
    let validator_index = ptc_members[0] as u64;

    let data = PayloadAttestationData {
        beacon_block_root: ctx.genesis_block_root,
        slot,
        payload_present: true,
        blob_data_available: true,
    };

    let msg1 = ctx.sign_payload_attestation(data.clone(), validator_index);
    let result1 = VerifiedPayloadAttestationMessage::new(msg1, &gossip);
    assert!(
        result1.is_ok(),
        "first message should pass: {:?}",
        result1.unwrap_err()
    );

    let msg2 = ctx.sign_payload_attestation(data, validator_index);
    let result2 = VerifiedPayloadAttestationMessage::new(msg2, &gossip);
    assert!(matches!(
        result2,
        Err(PayloadAttestationError::PriorPayloadAttestationMessageKnown { .. })
    ));
}

/// Exercises payload attestation gossip verification when the message epoch is ahead of the
/// canonical head due to many missed slots.
#[tokio::test]
async fn stale_head_payload_attestation() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let slots_per_epoch = E::slots_per_epoch();
    // Head at epoch 1, message at epoch 5: 4 epochs of missed slots.
    let head_slot = Slot::new(slots_per_epoch);
    let missed_epochs = 4;
    let target_slot = Slot::new(slots_per_epoch * (1 + missed_epochs));
    let target_epoch = target_slot.epoch(slots_per_epoch);

    // GIVEN a chain with blocks through epoch 1 (so the store has states).
    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();
    harness.extend_to_slot(head_slot).await;

    let head = harness.chain.canonical_head.cached_head();
    let head_epoch = head.snapshot.beacon_state.current_epoch();
    assert!(
        target_epoch > head_epoch + harness.spec.min_seed_lookahead,
        "precondition: message epoch must exceed head + min_seed_lookahead"
    );

    // GIVEN a slot clock advanced to epoch 5 without producing blocks
    // (simulating missed slots during a liveness failure).
    harness.chain.slot_clock.set_slot(target_slot.as_u64());

    // Advance a reference state to compute the PTC at the target slot.
    let mut reference_state = head.snapshot.beacon_state.clone();
    state_processing::state_advance::partial_state_advance(
        &mut reference_state,
        Some(head.snapshot.beacon_state_root()),
        target_slot,
        &harness.spec,
    )
    .expect("should advance reference state");
    reference_state
        .build_all_caches(&harness.spec)
        .expect("should build caches");

    let ptc = reference_state
        .get_ptc(target_slot, &harness.spec)
        .expect("should get PTC from reference state");
    let validator_index = *ptc.0.first().expect("PTC should have at least one member") as u64;

    // WHEN a properly-signed payload attestation from a PTC member is verified. The signature
    // domain should come from the spec fork schedule and genesis validators root, not a loaded
    // state in the verifier.
    let domain = harness.spec.get_domain(
        target_epoch,
        Domain::PTCAttester,
        &reference_state.fork(),
        reference_state.genesis_validators_root(),
    );
    let data = PayloadAttestationData {
        beacon_block_root: head.head_block_root(),
        slot: target_slot,
        payload_present: true,
        blob_data_available: true,
    };
    let message = data.signing_root(domain);
    let signature = harness.validator_keypairs[validator_index as usize]
        .sk
        .sign(message);
    let msg = PayloadAttestationMessage {
        validator_index,
        data,
        signature,
    };

    // THEN verification succeeds despite the head being 4 epochs stale.
    let result = harness
        .chain
        .verify_payload_attestation_message_for_gossip(msg);
    assert!(
        result.is_ok(),
        "expected Ok (head epoch {}, message epoch {}), got: {:?}",
        head_epoch,
        target_epoch,
        result.unwrap_err()
    );
}
