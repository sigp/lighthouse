use std::sync::Arc;

use std::time::Duration;

use bls::{Keypair, PublicKeyBytes, Signature};
use ethereum_hashing::hash;
use fork_choice::ForkChoice;
use genesis::{generate_deterministic_keypairs, interop_genesis_state};
use kzg::KzgCommitment;
use slot_clock::{SlotClock, TestingSlotClock};
use ssz::Encode;
use ssz_types::VariableList;
use state_processing::genesis::genesis_block;
use store::{HotColdDB, StoreConfig};
use types::{
    Address, ChainSpec, Checkpoint, Domain, Epoch, EthSpec, ExecutionBlockHash,
    ExecutionPayloadBid, Hash256, MinimalEthSpec, ProposerPreferences, SignedBeaconBlock,
    SignedExecutionPayloadBid, SignedProposerPreferences, SignedRoot, Slot,
};

use proto_array::{Block as ProtoBlock, ExecutionStatus, PayloadStatus};
use types::AttestationShufflingId;

use crate::{
    beacon_fork_choice_store::BeaconForkChoiceStore,
    beacon_snapshot::BeaconSnapshot,
    canonical_head::CanonicalHead,
    payload_bid_verification::{
        PayloadBidError,
        gossip_verified_bid::{GossipVerificationContext, GossipVerifiedPayloadBid},
        payload_bid_cache::GossipVerifiedPayloadBidCache,
    },
    proposer_preferences_verification::{
        gossip_verified_proposer_preferences::GossipVerifiedProposerPreferences,
        proposer_preference_cache::GossipVerifiedProposerPreferenceCache,
    },
    test_utils::{EphemeralHarnessType, fork_name_from_env, test_spec},
};

type E = MinimalEthSpec;
type T = EphemeralHarnessType<E>;

/// Number of regular validators (must be >= min_genesis_active_validator_count for MinimalEthSpec).
const NUM_VALIDATORS: usize = 64;
/// Number of builders to register.
const NUM_BUILDERS: usize = 4;
/// Balance given to each builder (min_deposit_amount + extra to cover bids in tests).
const BUILDER_BALANCE: u64 = 2_000_000_000;

struct TestContext {
    canonical_head: CanonicalHead<T>,
    bid_cache: GossipVerifiedPayloadBidCache<T>,
    preferences_cache: GossipVerifiedProposerPreferenceCache,
    slot_clock: TestingSlotClock,
    keypairs: Vec<Keypair>,
    spec: ChainSpec,
    genesis_block_root: Hash256,
    inactive_builder_index: u64,
}

fn builder_withdrawal_credentials(pubkey: &bls::PublicKey, spec: &ChainSpec) -> Hash256 {
    let fake_execution_address = &hash(&pubkey.as_ssz_bytes())[0..20];
    let mut credentials = [0u8; 32];
    credentials[0] = spec.builder_withdrawal_prefix_byte;
    credentials[12..].copy_from_slice(fake_execution_address);
    Hash256::from_slice(&credentials)
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

        // Register builders in the builder registry.
        for keypair in keypairs.iter().take(NUM_BUILDERS) {
            let creds = builder_withdrawal_credentials(&keypair.pk, &spec);
            state
                .add_builder_to_registry(
                    PublicKeyBytes::from(keypair.pk.clone()),
                    creds,
                    BUILDER_BALANCE,
                    Slot::new(0),
                    &spec,
                )
                .expect("should register builder");
        }

        // Bump finalized checkpoint epoch so builders are considered active
        // (is_active_builder requires deposit_epoch < finalized_checkpoint.epoch).
        *state.finalized_checkpoint_mut() = Checkpoint {
            epoch: Epoch::new(1),
            root: Hash256::ZERO,
        };

        // Set a non-zero gas_limit on latest_execution_payload_bid so the gas limit
        // compatibility check doesn't reject all bids at genesis.
        if let Ok(bid) = state.latest_execution_payload_bid_mut() {
            bid.gas_limit = 30_000_000;
        }
        // Update body_root to reflect the modified bid (genesis block embeds it).
        let genesis_body_root = genesis_block(&state, &spec)
            .expect("should build genesis block")
            .body_root();
        state.latest_block_header_mut().body_root = genesis_body_root;

        let inactive_keypair = &keypairs[NUM_BUILDERS];
        let inactive_creds = builder_withdrawal_credentials(&inactive_keypair.pk, &spec);
        let inactive_builder_index = state
            .add_builder_to_registry(
                PublicKeyBytes::from(inactive_keypair.pk.clone()),
                inactive_creds,
                BUILDER_BALANCE,
                Slot::new(E::slots_per_epoch()),
                &spec,
            )
            .expect("should register inactive builder");

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

        Self {
            canonical_head,
            bid_cache: GossipVerifiedPayloadBidCache::default(),
            preferences_cache: GossipVerifiedProposerPreferenceCache::default(),
            slot_clock,
            keypairs,
            spec,
            genesis_block_root: block_root,
            inactive_builder_index,
        }
    }

    fn sign_bid(&self, bid: ExecutionPayloadBid<E>) -> Arc<SignedExecutionPayloadBid<E>> {
        let head = self.canonical_head.cached_head();
        let state = &head.snapshot.beacon_state;
        let domain = self.spec.get_domain(
            bid.slot.epoch(E::slots_per_epoch()),
            Domain::BeaconBuilder,
            &state.fork(),
            state.genesis_validators_root(),
        );
        let message = bid.signing_root(domain);
        let signature = self.keypairs[bid.builder_index as usize].sk.sign(message);
        Arc::new(SignedExecutionPayloadBid {
            message: bid,
            signature,
        })
    }

    fn gossip_ctx(&self) -> GossipVerificationContext<'_, T> {
        GossipVerificationContext {
            canonical_head: &self.canonical_head,
            gossip_verified_payload_bid_cache: &self.bid_cache,
            gossip_verified_proposer_preferences_cache: &self.preferences_cache,
            slot_clock: &self.slot_clock,
            spec: &self.spec,
        }
    }

    fn insert_non_canonical_block(&self) -> Hash256 {
        let shuffling_id = AttestationShufflingId {
            shuffling_epoch: Epoch::new(0),
            shuffling_decision_block: self.genesis_block_root,
        };
        let fork_block_root = Hash256::repeat_byte(0xab);
        let mut fc = self.canonical_head.fork_choice_write_lock();
        fc.proto_array_mut()
            .process_block::<E>(
                ProtoBlock {
                    slot: Slot::new(1),
                    root: fork_block_root,
                    parent_root: Some(self.genesis_block_root),
                    target_root: fork_block_root,
                    current_epoch_shuffling_id: shuffling_id.clone(),
                    next_epoch_shuffling_id: shuffling_id,
                    state_root: Hash256::ZERO,
                    justified_checkpoint: Checkpoint {
                        epoch: Epoch::new(0),
                        root: self.genesis_block_root,
                    },
                    finalized_checkpoint: Checkpoint {
                        epoch: Epoch::new(0),
                        root: self.genesis_block_root,
                    },
                    execution_status: ExecutionStatus::irrelevant(),
                    unrealized_justified_checkpoint: None,
                    unrealized_finalized_checkpoint: None,
                    execution_payload_parent_hash: Some(ExecutionBlockHash::zero()),
                    execution_payload_block_hash: Some(ExecutionBlockHash::repeat_byte(0xab)),
                    proposer_index: Some(0),
                },
                Slot::new(1),
                &self.spec,
                Duration::from_secs(0),
            )
            .expect("should insert fork block");
        fork_block_root
    }
}

fn make_signed_bid(
    slot: Slot,
    builder_index: u64,
    fee_recipient: Address,
    gas_limit: u64,
    value: u64,
    parent_block_root: Hash256,
) -> Arc<SignedExecutionPayloadBid<E>> {
    Arc::new(SignedExecutionPayloadBid {
        message: ExecutionPayloadBid {
            slot,
            builder_index,
            fee_recipient,
            gas_limit,
            value,
            parent_block_root,
            ..ExecutionPayloadBid::default()
        },
        signature: Signature::empty(),
    })
}

fn make_signed_preferences(
    proposal_slot: Slot,
    validator_index: u64,
    fee_recipient: Address,
    target_gas_limit: u64,
) -> Arc<SignedProposerPreferences> {
    Arc::new(SignedProposerPreferences {
        message: ProposerPreferences {
            dependent_root: Hash256::ZERO,
            proposal_slot,
            validator_index,
            fee_recipient,
            target_gas_limit,
        },
        signature: Signature::empty(),
    })
}

fn seed_preferences(ctx: &TestContext, slot: Slot, fee_recipient: Address, gas_limit: u64) {
    let prefs = GossipVerifiedProposerPreferences {
        signed_preferences: make_signed_preferences(slot, 0, fee_recipient, gas_limit),
    };
    ctx.preferences_cache.insert_preferences(prefs);
}

#[test]
fn no_proposer_preferences_for_slot() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let bid = make_signed_bid(
        Slot::new(0),
        0,
        Address::ZERO,
        30_000_000,
        100,
        Hash256::ZERO,
    );

    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(matches!(
        result,
        Err(PayloadBidError::NoProposerPreferences { .. })
    ));
}

#[test]
fn builder_already_seen_for_slot() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    let bid = make_signed_bid(slot, 42, Address::ZERO, 30_000_000, 100, Hash256::ZERO);
    let verified = GossipVerifiedPayloadBid {
        signed_bid: bid.clone(),
    };
    ctx.bid_cache.insert_seen_builder(&verified);

    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(matches!(
        result,
        Err(PayloadBidError::BuilderAlreadySeen {
            builder_index: 42,
            ..
        })
    ));
}

#[test]
fn bid_value_below_cached() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    let high_bid = GossipVerifiedPayloadBid {
        signed_bid: make_signed_bid(slot, 99, Address::ZERO, 30_000_000, 500, Hash256::ZERO),
    };
    ctx.bid_cache.insert_highest_bid(high_bid);

    let low_bid = make_signed_bid(slot, 1, Address::ZERO, 30_000_000, 100, Hash256::ZERO);
    let result = GossipVerifiedPayloadBid::new(low_bid, &gossip);
    assert!(matches!(
        result,
        Err(PayloadBidError::BidValueBelowCached { .. })
    ));
}

#[test]
fn invalid_bid_slot() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(5);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    let bid = make_signed_bid(
        slot,
        0,
        Address::ZERO,
        30_000_000,
        100,
        ctx.genesis_block_root,
    );
    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(matches!(
        result,
        Err(PayloadBidError::InvalidBidSlot { .. })
    ));
}

#[test]
fn fee_recipient_mismatch() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::repeat_byte(0xaa), 30_000_000);

    let bid = make_signed_bid(
        slot,
        0,
        Address::ZERO,
        30_000_000,
        100,
        ctx.genesis_block_root,
    );
    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(matches!(result, Err(PayloadBidError::InvalidFeeRecipient)));
}

#[test]
fn gas_limit_mismatch() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    let bid = make_signed_bid(
        slot,
        0,
        Address::ZERO,
        50_000_000,
        100,
        ctx.genesis_block_root,
    );
    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(matches!(result, Err(PayloadBidError::InvalidGasLimit)));
}

#[test]
fn execution_payment_nonzero() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    let bid = Arc::new(SignedExecutionPayloadBid {
        message: ExecutionPayloadBid {
            slot,
            gas_limit: 30_000_000,
            execution_payment: 42,
            parent_block_root: ctx.genesis_block_root,
            ..ExecutionPayloadBid::default()
        },
        signature: Signature::empty(),
    });
    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(matches!(
        result,
        Err(PayloadBidError::ExecutionPaymentNonZero { .. })
    ));
}

#[test]
fn unknown_builder_index() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    // Use a builder_index that doesn't exist in the registry.
    let bid = make_signed_bid(
        slot,
        9999,
        Address::ZERO,
        30_000_000,
        100,
        ctx.genesis_block_root,
    );
    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(matches!(
        result,
        Err(PayloadBidError::InvalidBuilder {
            builder_index: 9999
        })
    ));
}

#[test]
fn inactive_builder() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    let bid = make_signed_bid(
        slot,
        ctx.inactive_builder_index,
        Address::ZERO,
        30_000_000,
        100,
        ctx.genesis_block_root,
    );
    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(matches!(
        result,
        Err(PayloadBidError::InvalidBuilder { .. })
    ));
}

#[test]
fn builder_cant_cover_bid() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    // Builder index 0 exists but bid value far exceeds their balance.
    let bid = make_signed_bid(
        slot,
        0,
        Address::ZERO,
        30_000_000,
        u64::MAX,
        ctx.genesis_block_root,
    );
    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(matches!(
        result,
        Err(PayloadBidError::BuilderCantCoverBid { .. })
    ));
}

#[test]
fn parent_block_root_unknown() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    // Parent block root not in fork choice.
    let unknown_root = Hash256::repeat_byte(0xff);
    let bid = make_signed_bid(slot, 0, Address::ZERO, 30_000_000, 0, unknown_root);
    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(result.is_err(), "expected error, got Ok");
    let err = result.unwrap_err();
    assert!(
        matches!(err, PayloadBidError::ParentBlockRootUnknown { .. }),
        "expected ParentBlockRootUnknown, got: {err:?}"
    );
}

#[test]
fn parent_block_root_not_canonical() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    let fork_root = ctx.insert_non_canonical_block();
    let bid = make_signed_bid(slot, 0, Address::ZERO, 30_000_000, 0, fork_root);
    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(result.is_err(), "expected error, got Ok");
    let err = result.unwrap_err();
    assert!(
        matches!(err, PayloadBidError::ParentBlockRootNotCanonical { .. }),
        "expected ParentBlockRootNotCanonical, got: {err:?}"
    );
}

#[test]
fn invalid_blob_kzg_commitments() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    let max_blobs = ctx
        .spec
        .max_blobs_per_block(slot.epoch(E::slots_per_epoch())) as usize;
    let commitments: Vec<KzgCommitment> = (0..=max_blobs)
        .map(|_| KzgCommitment::empty_for_testing())
        .collect();

    let bid = Arc::new(SignedExecutionPayloadBid {
        message: ExecutionPayloadBid {
            slot,
            builder_index: 0,
            fee_recipient: Address::ZERO,
            gas_limit: 30_000_000,
            value: 0,
            parent_block_root: ctx.genesis_block_root,
            blob_kzg_commitments: VariableList::new(commitments).unwrap(),
            ..ExecutionPayloadBid::default()
        },
        signature: Signature::empty(),
    });
    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(matches!(
        result,
        Err(PayloadBidError::InvalidBlobKzgCommitments { .. })
    ));
}

#[test]
fn bad_signature() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    // All checks pass but signature is empty/invalid.
    let bid = make_signed_bid(
        slot,
        0,
        Address::ZERO,
        30_000_000,
        0,
        ctx.genesis_block_root,
    );
    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(matches!(result, Err(PayloadBidError::BadSignature)));
    assert!(!ctx.bid_cache.seen_builder_index(&slot, 0));
    assert!(
        ctx.bid_cache
            .get_highest_bid(slot, ExecutionBlockHash::zero(), ctx.genesis_block_root)
            .is_none()
    );
}

#[test]
fn valid_bid() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    let bid = ctx.sign_bid(ExecutionPayloadBid {
        slot,
        builder_index: 0,
        fee_recipient: Address::ZERO,
        gas_limit: 30_000_000,
        value: 0,
        parent_block_root: ctx.genesis_block_root,
        ..ExecutionPayloadBid::default()
    });
    let result = GossipVerifiedPayloadBid::new(bid, &gossip);
    assert!(
        result.is_ok(),
        "expected Ok, got: {:?}",
        result.unwrap_err()
    );
}

#[test]
fn two_builders_coexist_in_cache() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    let bid_0 = ctx.sign_bid(ExecutionPayloadBid {
        slot,
        builder_index: 0,
        fee_recipient: Address::ZERO,
        gas_limit: 30_000_000,
        value: 0,
        parent_block_root: ctx.genesis_block_root,
        ..ExecutionPayloadBid::default()
    });
    let result_0 = GossipVerifiedPayloadBid::new(bid_0, &gossip);
    assert!(
        result_0.is_ok(),
        "builder 0 should pass: {:?}",
        result_0.unwrap_err()
    );

    // Builder 1 must bid strictly higher than builder 0's cached value.
    let bid_1 = ctx.sign_bid(ExecutionPayloadBid {
        slot,
        builder_index: 1,
        fee_recipient: Address::ZERO,
        gas_limit: 30_000_000,
        value: 1,
        parent_block_root: ctx.genesis_block_root,
        ..ExecutionPayloadBid::default()
    });
    let result_1 = GossipVerifiedPayloadBid::new(bid_1, &gossip);
    assert!(
        result_1.is_ok(),
        "builder 1 should pass: {:?}",
        result_1.unwrap_err()
    );

    // Both builders should be seen.
    assert!(ctx.bid_cache.seen_builder_index(&slot, 0));
    assert!(ctx.bid_cache.seen_builder_index(&slot, 1));

    let highest = ctx
        .bid_cache
        .get_highest_bid(slot, ExecutionBlockHash::zero(), ctx.genesis_block_root)
        .expect("should have highest bid");
    assert_eq!(highest.message.value, 1);
    assert_eq!(highest.message.builder_index, 1);
}

#[test]
fn bid_equal_to_cached_value_rejected() {
    if !fork_name_from_env().is_some_and(|f| f.gloas_enabled()) {
        return;
    }
    let ctx = TestContext::new();
    let gossip = ctx.gossip_ctx();
    let slot = Slot::new(0);
    seed_preferences(&ctx, slot, Address::ZERO, 30_000_000);

    // Seed a cached bid with value 100.
    let high_bid = GossipVerifiedPayloadBid {
        signed_bid: make_signed_bid(
            slot,
            99,
            Address::ZERO,
            30_000_000,
            100,
            ctx.genesis_block_root,
        ),
    };
    ctx.bid_cache.insert_highest_bid(high_bid);

    // Submit a bid with exactly the same value — should be rejected.
    let equal_bid = make_signed_bid(
        slot,
        1,
        Address::ZERO,
        30_000_000,
        100,
        ctx.genesis_block_root,
    );
    let result = GossipVerifiedPayloadBid::new(equal_bid, &gossip);
    assert!(matches!(
        result,
        Err(PayloadBidError::BidValueBelowCached {
            cached_value: 100,
            incoming_value: 100,
        })
    ));
}
