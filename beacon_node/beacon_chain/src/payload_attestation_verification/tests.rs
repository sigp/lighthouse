use std::sync::Arc;
use std::time::Duration;

use bls::{Keypair, Signature};
use fork_choice::ForkChoice;
use genesis::{generate_deterministic_keypairs, interop_genesis_state};
use parking_lot::RwLock;
use proto_array::PayloadStatus;
use slot_clock::{SlotClock, TestingSlotClock};
use store::{HotColdDB, StoreConfig};
use types::{
    BeaconBlock, ChainSpec, Checkpoint, Domain, Epoch, EthSpec, Hash256, MinimalEthSpec,
    PayloadAttestationData, PayloadAttestationMessage, SignedBeaconBlock, SignedRoot, Slot,
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
    test_utils::{EphemeralHarnessType, fork_name_from_env, test_spec},
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

        let mut genesis_block = BeaconBlock::empty(&spec);
        *genesis_block.state_root_mut() = state
            .update_tree_hash_cache()
            .expect("should hash genesis state");
        let signed_block = SignedBeaconBlock::from_block(genesis_block, Signature::empty());
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
