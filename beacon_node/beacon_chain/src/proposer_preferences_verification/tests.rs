use std::sync::Arc;
use std::time::Duration;

use bls::Signature;
use fork_choice::ForkChoice;
use genesis::{generate_deterministic_keypairs, interop_genesis_state};
use parking_lot::{Mutex, RwLock};
use proto_array::PayloadStatus;
use slot_clock::{SlotClock, TestingSlotClock};
use state_processing::AllCaches;
use store::{HotColdDB, MemoryStore, StoreConfig};
use types::{
    Address, BeaconBlock, ChainSpec, EthSpec, Hash256, MinimalEthSpec, ProposerPreferences,
    SignedBeaconBlock, SignedProposerPreferences, Slot,
};

use crate::{
    beacon_fork_choice_store::BeaconForkChoiceStore,
    beacon_proposer_cache::{BeaconProposerCache, ensure_state_can_determine_proposers_for_epoch},
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
        state
            .build_all_caches(&spec)
            .expect("should build state caches");
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
        let mut state = head.snapshot.beacon_state.clone();
        let state_root = head.snapshot.beacon_block.message().state_root();
        let epoch = slot.epoch(E::slots_per_epoch());
        state
            .build_all_caches(&self.spec)
            .expect("should build state caches");
        ensure_state_can_determine_proposers_for_epoch(&mut state, state_root, epoch, &self.spec)
            .expect("should advance state to determine proposers");
        let proposers = state
            .get_beacon_proposer_indices(epoch, &self.spec)
            .expect("should compute proposer indices");
        let slot_in_epoch = slot.as_usize() % E::slots_per_epoch() as usize;
        *proposers.get(slot_in_epoch).expect("slot within epoch") as u64
    }

    /// Insert a block into fork choice by cloning the parent's proto node with a new
    /// root and slot. The block has no state in the store, so verification can only
    /// proceed as far as the fork-choice-based checks.
    fn add_block(&self, parent_root: Hash256, root: Hash256, slot: Slot) {
        let mut fork_choice = self.canonical_head.fork_choice_write_lock();
        let mut block = fork_choice
            .get_block(&parent_root)
            .expect("parent block should be in fork choice");
        block.root = root;
        block.parent_root = Some(parent_root);
        block.slot = slot;
        fork_choice
            .proto_array_mut()
            .process_block::<E>(block, slot, &self.spec, Duration::ZERO)
            .expect("should insert block into fork choice");
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
    // Advance to epoch 1 so the genesis head is a valid dependent root for epoch-2
    // proposals (it is strictly before the start of lookahead epoch 1).
    ctx.slot_clock.set_slot(E::slots_per_epoch());
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(2 * E::slots_per_epoch());

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
    // Clock and proposal both in epoch 2: the childless genesis head is only a
    // valid dependent root via the head exemption.
    ctx.slot_clock.set_slot(2 * E::slots_per_epoch());
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(2 * E::slots_per_epoch() + 1);

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
    ctx.slot_clock.set_slot(E::slots_per_epoch());
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(2 * E::slots_per_epoch());

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
    // Clock in epoch 1, proposal in epoch 2 (the next epoch).
    ctx.slot_clock.set_slot(E::slots_per_epoch());
    let gossip = ctx.gossip_ctx();

    let next_epoch_slot = Slot::new(2 * E::slots_per_epoch() + 1);
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

/// For proposal epochs at or before the lookahead there is no block strictly before the
/// boundary; the genesis block is exempt so genesis-gloas networks can gossip preferences
/// during the first epochs.
#[test]
fn genesis_dependent_root_valid_for_early_epochs() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(1);

    let actual_proposer = ctx.proposer_at_slot(slot);
    let prefs = make_signed_preferences(slot, actual_proposer, ctx.head_block_root);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(
        matches!(result, Err(ProposerPreferencesError::BadSignature)),
        "expected BadSignature for genesis dependent root, got: {:?}",
        result
    );
}

/// The genesis exemption only admits the block at slot 0: any other block is still too
/// recent for early proposal epochs.
#[test]
fn non_genesis_dependent_root_too_recent_for_early_epochs() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();

    let recent_root = Hash256::repeat_byte(0xab);
    ctx.add_block(ctx.head_block_root, recent_root, Slot::new(1));

    let prefs = make_signed_preferences(Slot::new(2), 0, recent_root);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(matches!(
        result,
        Err(ProposerPreferencesError::DependentRootToRecent { .. })
    ));
}

#[test]
fn dependent_root_too_recent() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    ctx.slot_clock.set_slot(E::slots_per_epoch());
    let gossip = ctx.gossip_ctx();

    // A block after the start of lookahead epoch 1 cannot be a dependent root for
    // epoch-2 proposals.
    let recent_root = Hash256::repeat_byte(0xaa);
    ctx.add_block(
        ctx.head_block_root,
        recent_root,
        Slot::new(E::slots_per_epoch() + 4),
    );

    let proposal_slot = Slot::new(2 * E::slots_per_epoch() + 1);
    let prefs = make_signed_preferences(proposal_slot, 0, recent_root);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(matches!(
        result,
        Err(ProposerPreferencesError::DependentRootToRecent { .. })
    ));
}

/// A known, old-enough block that has no children and is not the head is not a
/// plausible dependent root on any branch.
#[test]
fn dependent_root_childless_non_head() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    ctx.slot_clock.set_slot(E::slots_per_epoch());
    let gossip = ctx.gossip_ctx();

    let branch_root = Hash256::repeat_byte(0xbb);
    ctx.add_block(ctx.head_block_root, branch_root, Slot::new(4));

    let proposal_slot = Slot::new(2 * E::slots_per_epoch() + 1);
    let prefs = make_signed_preferences(proposal_slot, 0, branch_root);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(matches!(
        result,
        Err(ProposerPreferencesError::InvalidDependentRoot { .. })
    ));
}

/// A child that is itself before the lookahead boundary does not qualify: the block is
/// not the latest one before the boundary on that branch.
#[test]
fn dependent_root_child_before_boundary() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    ctx.slot_clock.set_slot(E::slots_per_epoch());
    let gossip = ctx.gossip_ctx();

    let parent_root = Hash256::repeat_byte(0xcc);
    let child_root = Hash256::repeat_byte(0xdd);
    ctx.add_block(ctx.head_block_root, parent_root, Slot::new(2));
    ctx.add_block(parent_root, child_root, Slot::new(4));

    let proposal_slot = Slot::new(2 * E::slots_per_epoch() + 1);
    let prefs = make_signed_preferences(proposal_slot, 0, parent_root);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(matches!(
        result,
        Err(ProposerPreferencesError::InvalidDependentRoot { .. })
    ));
}

/// A non-head block with a child crossing the lookahead boundary passes dependent-root
/// validation. Verification still fails later (the fabricated block has no state in the
/// store), but not with a dependent-root error.
#[test]
fn dependent_root_valid_via_boundary_crossing_child() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    ctx.slot_clock.set_slot(E::slots_per_epoch());
    let gossip = ctx.gossip_ctx();

    let parent_root = Hash256::repeat_byte(0xee);
    let child_root = Hash256::repeat_byte(0xef);
    ctx.add_block(ctx.head_block_root, parent_root, Slot::new(4));
    ctx.add_block(parent_root, child_root, Slot::new(E::slots_per_epoch() + 4));

    let proposal_slot = Slot::new(2 * E::slots_per_epoch() + 1);
    let prefs = make_signed_preferences(proposal_slot, 0, parent_root);
    let result = GossipVerifiedProposerPreferences::new(prefs, &gossip);
    assert!(
        !matches!(
            &result,
            Err(ProposerPreferencesError::DependentRootToRecent { .. }
                | ProposerPreferencesError::InvalidDependentRoot { .. })
        ),
        "expected dependent root to be accepted, got: {:?}",
        result
    );
}
