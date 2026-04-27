use std::sync::Arc;
use std::time::Duration;

use bls::{Keypair, Signature};
use fork_choice::ForkChoice;
use genesis::{generate_deterministic_keypairs, interop_genesis_state};
use parking_lot::RwLock;
use proto_array::PayloadStatus;
use slot_clock::{SlotClock, TestingSlotClock};
use state_processing::AllCaches;
use state_processing::genesis::genesis_block;
use store::{HotColdDB, StoreConfig};
use types::{
    ChainSpec, Checkpoint, Domain, Epoch, EthSpec, Hash256, MinimalEthSpec, PayloadAttestationData,
    PayloadAttestationMessage, SignedBeaconBlock, SignedRoot, Slot,
};

use crate::{
    beacon_fork_choice_store::BeaconForkChoiceStore,
    beacon_snapshot::BeaconSnapshot,
    canonical_head::CanonicalHead,
    observed_attesters::ObservedPayloadAttesters,
    payload_attestation_verification::{
        Error as PayloadAttestationError,
        gossip_verified_payload_attestation::{
            GossipVerificationContext, VerifiedPayloadAttestationMessage,
        },
    },
    test_utils::{BeaconChainHarness, EphemeralHarnessType, fork_name_from_env, test_spec},
    validator_pubkey_cache::ValidatorPubkeyCache,
};

type E = MinimalEthSpec;
type T = EphemeralHarnessType<E>;

const NUM_VALIDATORS: usize = 64;

struct TestContext {
    canonical_head: CanonicalHead<T>,
    observed_payload_attesters: RwLock<ObservedPayloadAttesters<E>>,
    validator_pubkey_cache: RwLock<ValidatorPubkeyCache<T>>,
    slot_clock: TestingSlotClock,
    keypairs: Vec<Keypair>,
    spec: ChainSpec,
    genesis_block_root: Hash256,
    store: Arc<store::HotColdDB<E, store::MemoryStore<E>, store::MemoryStore<E>>>,
}

impl TestContext {
    fn new() -> Self {
        let spec = test_spec::<E>();
        let store = Arc::new(
            HotColdDB::open_ephemeral(StoreConfig::default(), Arc::new(spec.clone()))
                .expect("should open ephemeral store"),
        );

        let keypairs = generate_deterministic_keypairs(NUM_VALIDATORS);

        let mut state =
            interop_genesis_state::<E>(&keypairs, 0, Hash256::repeat_byte(0x42), None, &spec)
                .expect("should build genesis state");

        *state.finalized_checkpoint_mut() = Checkpoint {
            epoch: Epoch::new(1),
            root: Hash256::ZERO,
        };

        let mut block = genesis_block(&state, &spec).expect("should build genesis block");
        *block.state_root_mut() = state
            .update_tree_hash_cache()
            .expect("should hash genesis state");
        let signed_block = SignedBeaconBlock::from_block(block, Signature::empty());
        let block_root = signed_block.canonical_root();

        let snapshot = BeaconSnapshot::new(
            Arc::new(signed_block.clone()),
            None,
            block_root,
            state.clone(),
        );

        let fc_store = BeaconForkChoiceStore::get_forkchoice_store(store.clone(), snapshot.clone())
            .expect("should create fork choice store");
        let fork_choice =
            ForkChoice::from_anchor(fc_store, block_root, &signed_block, &state, None, &spec)
                .expect("should create fork choice");

        let canonical_head =
            CanonicalHead::new(fork_choice, Arc::new(snapshot), PayloadStatus::Pending);

        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            spec.get_slot_duration(),
        );
        // Advance past genesis so `now_with_past_tolerance` doesn't underflow.
        slot_clock.set_current_time(spec.get_slot_duration());

        let validator_pubkey_cache =
            ValidatorPubkeyCache::new(&state, store.clone()).expect("should create pubkey cache");

        Self {
            canonical_head,
            observed_payload_attesters: RwLock::new(ObservedPayloadAttesters::default()),
            validator_pubkey_cache: RwLock::new(validator_pubkey_cache),
            slot_clock,
            keypairs,
            spec,
            genesis_block_root: block_root,
            store,
        }
    }

    fn gossip_ctx(&self) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            slot_clock: &self.slot_clock,
            spec: &self.spec,
            observed_payload_attesters: &self.observed_payload_attesters,
            canonical_head: &self.canonical_head,
            validator_pubkey_cache: &self.validator_pubkey_cache,
            store: &self.store,
        }
    }

    fn ptc_members(&self, slot: Slot) -> Vec<usize> {
        let head = self.canonical_head.cached_head();
        let state = &head.snapshot.beacon_state;
        let ptc = state.get_ptc(slot, &self.spec).expect("should get PTC");
        ptc.0.to_vec()
    }

    fn sign_payload_attestation(
        &self,
        data: PayloadAttestationData,
        validator_index: u64,
    ) -> PayloadAttestationMessage {
        let head = self.canonical_head.cached_head();
        let state = &head.snapshot.beacon_state;
        let domain = self.spec.get_domain(
            data.slot.epoch(E::slots_per_epoch()),
            Domain::PTCAttester,
            &state.fork(),
            state.genesis_validators_root(),
        );
        let message = data.signing_root(domain);
        let signature = self.keypairs[validator_index as usize].sk.sign(message);
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
    ctx.slot_clock.set_slot(5);
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

/// Exercises the `partial_state_advance` fallback in gossip verification when
/// the head state is too stale to compute PTC membership (e.g., during a
/// network liveness failure with many missed slots).
#[tokio::test]
async fn stale_head_with_partial_advance() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }

    let slots_per_epoch = E::slots_per_epoch();
    // Head at epoch 1, message at epoch 5 — 4 epochs of missed slots.
    // This exceeds min_seed_lookahead (1), triggering the fallback path:
    // get_advanced_hot_state loads the stored state, then partial_state_advance
    // advances it through epoch boundaries to populate ptc_window.
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
        "precondition: message epoch must exceed head + min_seed_lookahead to trigger fallback"
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

    // WHEN a properly-signed payload attestation from a PTC member is verified.
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
