use std::sync::Arc;
use std::time::Duration;

use bls::Signature;
use slot_clock::{SlotClock, TestingSlotClock};
use types::{
    Domain, Epoch, EthSpec, ForkName, Hash256, MinimalEthSpec, PayloadAttestationData,
    PayloadAttestationMessage, SignedRoot, Slot,
};

use crate::{
    payload_attestation_verification::{
        Error as PayloadAttestationError,
        gossip_verified_payload_attestation::{
            GossipVerificationContext, VerifiedPayloadAttestationMessage,
        },
    },
    test_utils::{BeaconChainHarness, EphemeralHarnessType, fork_name_from_env, test_spec},
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
        let spec = Arc::new(test_spec::<E>());
        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            spec.get_slot_duration(),
        );
        let harness = BeaconChainHarness::builder(E::default())
            .spec(spec)
            .deterministic_keypairs(NUM_VALIDATORS)
            .fresh_ephemeral_store()
            .testing_slot_clock(slot_clock)
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
fn block_not_at_slot() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();

    // The genesis block is at slot 0, but the message claims slot 1. A PTC member assigned to an
    // empty slot must not attest, so this must be ignored (per consensus-specs #5281).
    let msg = make_payload_attestation(Slot::new(1), 0, ctx.genesis_block_root);
    let result = VerifiedPayloadAttestationMessage::new(msg, &gossip);
    assert!(
        matches!(result, Err(PayloadAttestationError::BlockNotAtSlot { .. })),
        "expected BlockNotAtSlot, got: {:?}",
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
    let slot = Slot::new(0);

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
    let slot = Slot::new(0);

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
    let slot = Slot::new(0);

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
    let slot = Slot::new(0);

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

#[tokio::test]
async fn ptc_cache_is_primed_at_gloas_fork_boundary() {
    // Only run this test once, when FORK_NAME=gloas exactly.
    let mut spec = test_spec::<E>();
    if spec.fork_name_at_epoch(Epoch::new(0)) != ForkName::Gloas {
        return;
    }

    let gloas_fork_epoch = Epoch::new(2);
    spec.gloas_fork_epoch = Some(gloas_fork_epoch);
    assert_eq!(
        spec.fork_name_at_epoch(gloas_fork_epoch - 1),
        ForkName::Fulu
    );
    assert_eq!(spec.fork_name_at_epoch(gloas_fork_epoch), ForkName::Gloas);

    let slots_per_epoch = E::slots_per_epoch();
    let fork_boundary_slot = gloas_fork_epoch.start_slot(slots_per_epoch);
    let test_slots = (fork_boundary_slot.as_u64()
        ..fork_boundary_slot.as_u64() + slots_per_epoch * 2)
        .map(Slot::new);

    let harness = BeaconChainHarness::builder(E::default())
        .spec(Arc::new(spec))
        .deterministic_keypairs(NUM_VALIDATORS)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    for slot in test_slots {
        harness.extend_to_slot(slot).await;
        assert!(
            harness
                .chain
                .shuffling_cache
                .read()
                .check_gloas_ptcs_invariant(&harness.spec),
            "shuffling cache should satisfy the Gloas PTC invariant"
        );

        let head = harness.chain.canonical_head.cached_head();
        let state = &head.snapshot.beacon_state;
        let ptc = state.get_ptc(slot, &harness.spec).expect("should get PTC");
        let validator_index = *ptc.0.first().expect("PTC should have a member") as u64;
        let data = PayloadAttestationData {
            beacon_block_root: head.head_block_root(),
            slot,
            payload_present: true,
            blob_data_available: true,
        };
        let domain = harness.spec.get_domain(
            data.slot.epoch(slots_per_epoch),
            Domain::PTCAttester,
            &state.fork(),
            state.genesis_validators_root(),
        );
        let signature = harness.validator_keypairs[validator_index as usize]
            .sk
            .sign(data.signing_root(domain));
        let msg = PayloadAttestationMessage {
            validator_index,
            data,
            signature,
        };

        let result = harness
            .chain
            .verify_payload_attestation_message_for_gossip(msg);
        assert!(
            result.is_ok(),
            "expected PTC payload attestation to verify at slot {}, got: {:?}",
            slot,
            result.unwrap_err()
        );
    }
}

/// Check that a payload attestation whose assigned slot is empty is ignored.
#[tokio::test]
async fn stale_head_empty_slot_payload_attestation_ignored() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let slots_per_epoch = E::slots_per_epoch();
    // Head at epoch 1, message at epoch 5: 4 epochs of missed slots.
    let head_slot = Slot::new(slots_per_epoch);
    let missed_epochs = 4;
    let target_slot = Slot::new(slots_per_epoch * (1 + missed_epochs));

    // Given a chain with blocks through epoch 1, then a slot clock advanced 4 epochs without
    // producing blocks (simulating missed slots).
    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(64)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();
    harness.extend_to_slot(head_slot).await;
    harness.chain.slot_clock.set_slot(target_slot.as_u64());

    let head = harness.chain.canonical_head.cached_head();

    // When a payload attestation for empty target slot references a stale block root
    // it is ignored because target_slot != block.slot
    let data = PayloadAttestationData {
        beacon_block_root: head.head_block_root(),
        slot: target_slot,
        payload_present: true,
        blob_data_available: true,
    };
    let msg = PayloadAttestationMessage {
        validator_index: 0,
        data,
        signature: Signature::empty(),
    };

    let result = harness
        .chain
        .verify_payload_attestation_message_for_gossip(msg);
    assert!(
        matches!(result, Err(PayloadAttestationError::BlockNotAtSlot { .. })),
        "expected BlockNotAtSlot, got: {result:?}"
    );
}

/// Exercises payload attestation gossip verification for a non-canonical block whose PTC differs
/// from the canonical chain's PTC for the same slot.
#[tokio::test]
async fn side_chain_payload_attestation_uses_side_chain_ptc() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let slots_per_epoch = E::slots_per_epoch();
    let fork_slot = Slot::new(slots_per_epoch);
    let target_slot = Slot::new(slots_per_epoch * 4);
    let target_epoch = target_slot.epoch(slots_per_epoch);

    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .deterministic_keypairs(NUM_VALIDATORS)
        .fresh_ephemeral_store()
        .mock_execution_layer()
        .build();

    // Build a common prefix through epoch 1.
    harness.extend_to_slot(fork_slot).await;
    let fork_state = harness.chain.head_snapshot().beacon_state.clone();

    // Build two branches for several epochs. The side chain skips its first slot, giving it
    // different RANDAO mixes and therefore a different PTC by the target slot. The canonical chain
    // is processed second and receives sub-finality attestations, so it remains the head without
    // finalizing past the side-chain fork point.
    let side_slots: Vec<_> = ((fork_slot + 2).as_u64()..=target_slot.as_u64())
        .map(Slot::new)
        .collect();
    let canonical_slots: Vec<_> = ((fork_slot + 1).as_u64()..=target_slot.as_u64())
        .map(Slot::new)
        .collect();
    let canonical_validators = (0..NUM_VALIDATORS / 2).collect::<Vec<_>>();

    let results = harness
        .add_blocks_on_multiple_chains(vec![
            (fork_state.clone(), side_slots, vec![]),
            (fork_state, canonical_slots, canonical_validators),
        ])
        .await;

    let side_head_root: Hash256 = results[0].2.into();
    let side_head_state = &results[0].3;
    let canonical_head_root: Hash256 = results[1].2.into();
    let canonical_head_state = &results[1].3;

    assert_ne!(side_head_root, canonical_head_root);
    assert_eq!(
        harness.chain.head_snapshot().beacon_block_root,
        canonical_head_root
    );

    let side_ptc = side_head_state
        .get_ptc(target_slot, &harness.spec)
        .expect("should get side-chain PTC");
    let canonical_ptc = canonical_head_state
        .get_ptc(target_slot, &harness.spec)
        .expect("should get canonical PTC");
    assert_ne!(
        side_ptc, canonical_ptc,
        "precondition: side-chain PTC should differ from canonical PTC"
    );

    let validator_index = side_ptc
        .0
        .iter()
        .copied()
        .find(|validator_index| !canonical_ptc.0.contains(validator_index))
        .expect("should find a validator in the side-chain PTC only")
        as u64;

    let domain = harness.spec.get_domain(
        target_epoch,
        Domain::PTCAttester,
        &side_head_state.fork(),
        side_head_state.genesis_validators_root(),
    );
    let data = PayloadAttestationData {
        beacon_block_root: side_head_root,
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

    let verified = harness
        .chain
        .verify_payload_attestation_message_for_gossip(msg)
        .expect("side-chain payload attestation should verify");
    assert_eq!(verified.ptc(), &side_ptc);
}
