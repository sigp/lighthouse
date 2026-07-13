use std::sync::Arc;
use std::time::Duration;

use bls::Signature;
use fork_choice::ForkChoice;
use genesis::{generate_deterministic_keypairs, interop_genesis_state};
use parking_lot::{Mutex, RwLock};
use proto_array::PayloadStatus;
use slot_clock::{SlotClock, TestingSlotClock};
use store::{HotColdDB, MemoryStore, StoreConfig};
use types::{
    Address, BeaconBlock, ChainSpec, Checkpoint, Epoch, EthSpec, Hash256, MinimalEthSpec,
    ProposerPreferences, SignedBeaconBlock, SignedProposerPreferences, Slot,
};

use crate::{
    beacon_fork_choice_store::BeaconForkChoiceStore,
    beacon_proposer_cache::BeaconProposerCache,
    beacon_snapshot::BeaconSnapshot,
    canonical_head::CanonicalHead,
    chain_config::FastConfirmationMode,
    proposer_preferences_verification::{
        ProposerPreferencesError,
        gossip_verified_proposer_preferences::{
            GossipVerificationContext, GossipVerifiedProposerPreferences,
        },
        proposer_preference_cache::GossipVerifiedProposerPreferenceCache,
    },
    test_utils::{EphemeralHarnessType, fork_name_from_env, test_spec},
    validator_pubkey_cache::ValidatorPubkeyCache,
};

type E = MinimalEthSpec;
type T = EphemeralHarnessType<E>;

const NUM_VALIDATORS: usize = 64;

struct TestContext {
    canonical_head: CanonicalHead<T>,
    preferences_cache: GossipVerifiedProposerPreferenceCache,
    slot_clock: TestingSlotClock,
    spec: ChainSpec,
    store: Arc<HotColdDB<E, MemoryStore, MemoryStore>>,
    head_block_root: Hash256,
    beacon_proposer_cache: Mutex<BeaconProposerCache>,
    validator_pubkey_cache: RwLock<ValidatorPubkeyCache<T>>,
    genesis_validators_root: Hash256,
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

        let genesis_state_root = state
            .update_tree_hash_cache()
            .expect("should hash genesis state");

        let block_root = state.get_latest_block_root(genesis_state_root);

        // Build a signed block with the correct state root for the snapshot.
        let mut genesis_block = BeaconBlock::empty(&spec);
        *genesis_block.state_root_mut() = genesis_state_root;
        let signed_block = SignedBeaconBlock::from_block(genesis_block, Signature::empty());

        let _ = store
            .init_anchor_info(Hash256::ZERO, Slot::new(0), Slot::new(0), false)
            .expect("should init anchor info");
        store
            .put_state(&genesis_state_root, &state)
            .expect("should persist genesis state");

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

        let canonical_head = CanonicalHead::new(
            fork_choice,
            Arc::new(snapshot),
            PayloadStatus::Pending,
            FastConfirmationMode::Disabled,
            &store,
            &spec,
        )
        .unwrap();

        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(0),
            spec.get_slot_duration(),
        );

        let genesis_validators_root = state.genesis_validators_root();
        let validator_pubkey_cache = RwLock::new(
            ValidatorPubkeyCache::new(&state, store.clone())
                .expect("should build validator pubkey cache"),
        );

        Self {
            canonical_head,
            preferences_cache: GossipVerifiedProposerPreferenceCache::default(),
            slot_clock,
            spec,
            store,
            head_block_root: block_root,
            beacon_proposer_cache: Mutex::new(BeaconProposerCache::default()),
            validator_pubkey_cache,
            genesis_validators_root,
        }
    }

    fn gossip_ctx(&self) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            canonical_head: &self.canonical_head,
            gossip_verified_proposer_preferences_cache: &self.preferences_cache,
            slot_clock: &self.slot_clock,
            spec: &self.spec,
            store: &self.store,
            beacon_proposer_cache: &self.beacon_proposer_cache,
            validator_pubkey_cache: &self.validator_pubkey_cache,
            genesis_validators_root: self.genesis_validators_root,
        }
    }

    fn proposer_at_slot(&self, slot: Slot) -> u64 {
        let head = self.canonical_head.cached_head();
        let state = &head.snapshot.beacon_state;
        let lookahead = state
            .proposer_lookahead()
            .expect("Gloas state has lookahead");
        let slot_in_epoch = slot.as_usize() % E::slots_per_epoch() as usize;
        let epoch = slot.epoch(E::slots_per_epoch());
        let current_epoch = state.slot().epoch(E::slots_per_epoch());
        let index = if epoch == current_epoch.saturating_add(self.spec.min_seed_lookahead) {
            E::slots_per_epoch() as usize + slot_in_epoch
        } else {
            slot_in_epoch
        };
        *lookahead.get(index).expect("index in range")
    }
}

fn make_signed_preferences(
    proposal_slot: Slot,
    validator_index: u64,
    dependent_root: Hash256,
) -> Arc<SignedProposerPreferences> {
    Arc::new(SignedProposerPreferences {
        message: ProposerPreferences {
            dependent_root,
            proposal_slot,
            validator_index,
            fee_recipient: Address::ZERO,
            target_gas_limit: 30_000_000,
        },
        signature: Signature::empty(),
    })
}

#[test]
fn already_seen_validator() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(1);

    let verified = GossipVerifiedProposerPreferences {
        signed_preferences: make_signed_preferences(slot, 42, Hash256::ZERO),
    };
    ctx.preferences_cache.insert_seen_validator(&verified);

    let prefs = make_signed_preferences(slot, 42, Hash256::ZERO);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(matches!(
        result,
        Err(ProposerPreferencesError::AlreadySeen {
            validator_index: 42,
            ..
        })
    ));
}

#[test]
fn invalid_epoch_too_far_ahead() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();

    let far_slot = Slot::new(3 * E::slots_per_epoch());
    let prefs = make_signed_preferences(far_slot, 0, Hash256::ZERO);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(matches!(
        result,
        Err(ProposerPreferencesError::InvalidProposalEpoch { .. })
    ));
}

#[test]
fn proposal_slot_already_passed() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();

    let prefs = make_signed_preferences(Slot::new(0), 0, Hash256::ZERO);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(matches!(
        result,
        Err(ProposerPreferencesError::ProposalSlotAlreadyPassed { .. })
    ));
}

#[test]
fn wrong_proposer_for_slot() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(1);

    let actual_proposer = ctx.proposer_at_slot(slot);
    let wrong_validator = if actual_proposer == 0 { 1 } else { 0 };

    let prefs = make_signed_preferences(slot, wrong_validator, ctx.head_block_root);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(matches!(
        result,
        Err(ProposerPreferencesError::InvalidProposalSlot { .. })
    ));
}

#[test]
fn correct_proposer_bad_signature() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(1);

    let actual_proposer = ctx.proposer_at_slot(slot);
    let prefs = make_signed_preferences(slot, actual_proposer, ctx.head_block_root);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(matches!(
        result,
        Err(ProposerPreferencesError::BadSignature)
    ));
    assert!(
        !ctx.preferences_cache
            .get_seen_validator(&slot, ctx.head_block_root, actual_proposer)
    );
    assert!(
        ctx.preferences_cache
            .get_preferences(&slot, ctx.head_block_root)
            .is_none()
    );
}

#[test]
fn validator_index_out_of_bounds() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(1);

    let prefs = make_signed_preferences(slot, u64::MAX, ctx.head_block_root);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(matches!(
        result,
        Err(ProposerPreferencesError::InvalidProposalSlot { .. })
    ));
}

/// Same (slot, validator_index) but different dependent_root should NOT be deduplicated.
#[test]
fn same_validator_different_dependent_root_not_deduplicated() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let slot = Slot::new(1);

    let verified_a = GossipVerifiedProposerPreferences {
        signed_preferences: Arc::new(SignedProposerPreferences {
            message: ProposerPreferences {
                proposal_slot: slot,
                validator_index: 42,
                dependent_root: Hash256::repeat_byte(0xaa),
                fee_recipient: Address::ZERO,
                target_gas_limit: 30_000_000,
            },
            signature: Signature::empty(),
        }),
    };
    ctx.preferences_cache.insert_seen_validator(&verified_a);

    // Different dependent_root — should not be seen.
    assert!(
        !ctx.preferences_cache
            .get_seen_validator(&slot, Hash256::repeat_byte(0xbb), 42,)
    );
    // Same dependent_root — should be seen.
    assert!(
        ctx.preferences_cache
            .get_seen_validator(&slot, Hash256::repeat_byte(0xaa), 42,)
    );
}

#[test]
fn dependent_root_unknown() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(1);

    let unknown_root = Hash256::repeat_byte(0xff);
    let prefs = make_signed_preferences(slot, 0, unknown_root);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(matches!(
        result,
        Err(ProposerPreferencesError::DependentRootUnknown { .. })
    ));
}

#[test]
fn invalid_epoch_too_old() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    // Advance the clock so that epoch 0 slots are too old.
    ctx.slot_clock.set_slot(3 * E::slots_per_epoch());
    let gossip = ctx.gossip_ctx();

    let old_slot = Slot::new(1);
    let prefs = make_signed_preferences(old_slot, 0, Hash256::ZERO);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(matches!(
        result,
        Err(ProposerPreferencesError::InvalidProposalEpoch { .. })
    ));
}

// TODO(gloas) add successful proposer preferences check once we have proposer preferences signing logic

#[test]
fn preferences_for_next_epoch_slot() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();

    // Head is at slot 0 (epoch 0). Pick a slot in epoch 1.
    let next_epoch_slot = Slot::new(E::slots_per_epoch() + 1);
    let actual_proposer = ctx.proposer_at_slot(next_epoch_slot);

    let prefs = make_signed_preferences(next_epoch_slot, actual_proposer, ctx.head_block_root);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    // Should pass consistency checks but fail on signature (empty sig).
    assert!(
        matches!(result, Err(ProposerPreferencesError::BadSignature)),
        "expected BadSignature for next-epoch slot, got: {:?}",
        result
    );
}
