#![cfg(not(debug_assertions))]

use beacon_chain::attestation_verification::Error as AttnError;
use beacon_chain::builder::BeaconChainBuilder;
use beacon_chain::schema_change::migrate_schema;
use beacon_chain::test_utils::{
    test_spec, AttestationStrategy, BeaconChainHarness, BlockStrategy, DiskHarnessType,
};
use beacon_chain::{
    historical_blocks::HistoricalBlockError, migrate::MigratorConfig, BeaconChain,
    BeaconChainError, BeaconChainTypes, BeaconSnapshot, BlockError, ChainConfig,
    NotifyExecutionLayer, ServerSentEventHandler, WhenSlotSkipped,
};
use lazy_static::lazy_static;
use logging::test_logger;
use maplit::hashset;
use rand::Rng;
use slot_clock::{SlotClock, TestingSlotClock};
use state_processing::{state_advance::complete_state_advance, BlockReplayer};
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::Arc;
use std::time::Duration;
use store::metadata::{SchemaVersion, CURRENT_SCHEMA_VERSION};
use store::{
    iter::{BlockRootsIterator, StateRootsIterator},
    HotColdDB, LevelDB, StoreConfig,
};
use tempfile::{tempdir, TempDir};
use tokio::time::sleep;
use tree_hash::TreeHash;
use types::test_utils::{SeedableRng, XorShiftRng};
use types::*;

// Should ideally be divisible by 3.
pub const LOW_VALIDATOR_COUNT: usize = 24;
pub const HIGH_VALIDATOR_COUNT: usize = 64;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(HIGH_VALIDATOR_COUNT);
}

type E = MinimalEthSpec;
type TestHarness = BeaconChainHarness<DiskHarnessType<E>>;

fn get_store(db_path: &TempDir) -> Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>> {
    get_store_with_spec(db_path, test_spec::<E>())
}

fn get_store_with_spec(
    db_path: &TempDir,
    spec: ChainSpec,
) -> Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>> {
    let hot_path = db_path.path().join("hot_db");
    let cold_path = db_path.path().join("cold_db");
    let config = StoreConfig::default();
    let log = test_logger();

    HotColdDB::open(&hot_path, &cold_path, |_, _, _| Ok(()), config, spec, log)
        .expect("disk store should initialize")
}

fn get_harness(
    store: Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>>,
    validator_count: usize,
) -> TestHarness {
    // Most tests expect to retain historic states, so we use this as the default.
    let chain_config = ChainConfig {
        reconstruct_historic_states: true,
        ..ChainConfig::default()
    };
    get_harness_generic(store, validator_count, chain_config)
}

fn get_harness_generic(
    store: Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>>,
    validator_count: usize,
    chain_config: ChainConfig,
) -> TestHarness {
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .logger(store.logger().clone())
        .fresh_disk_store(store)
        .mock_execution_layer()
        .chain_config(chain_config)
        .build();
    harness.advance_slot();
    harness
}

#[tokio::test]
async fn full_participation_no_skips() {
    let num_blocks_produced = E::slots_per_epoch() * 5;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    check_finalization(&harness, num_blocks_produced);
    check_split_slot(&harness, store);
    check_chain_dump(&harness, num_blocks_produced + 1);
    check_iterators(&harness);
}

#[tokio::test]
async fn randomised_skips() {
    let num_slots = E::slots_per_epoch() * 5;
    let mut num_blocks_produced = 0;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);
    let rng = &mut XorShiftRng::from_seed([42; 16]);

    let mut head_slot = 0;

    for slot in 1..=num_slots {
        if rng.gen_bool(0.8) {
            harness
                .extend_chain(
                    1,
                    BlockStrategy::ForkCanonicalChainAt {
                        previous_slot: Slot::new(head_slot),
                        first_slot: Slot::new(slot),
                    },
                    AttestationStrategy::AllValidators,
                )
                .await;
            harness.advance_slot();
            num_blocks_produced += 1;
            head_slot = slot;
        } else {
            harness.advance_slot();
        }
    }

    let state = &harness.chain.head_snapshot().beacon_state;

    assert_eq!(
        state.slot(),
        num_slots,
        "head should be at the current slot"
    );

    check_split_slot(&harness, store.clone());
    check_chain_dump(&harness, num_blocks_produced + 1);
    check_iterators(&harness);
}

#[tokio::test]
async fn long_skip() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // Number of blocks to create in the first run, intentionally not falling on an epoch
    // boundary in order to check that the DB hot -> cold migration is capable of reaching
    // back across the skip distance, and correctly migrating those extra non-finalized states.
    let initial_blocks = E::slots_per_epoch() * 5 + E::slots_per_epoch() / 2;
    let skip_slots = E::slots_per_historical_root() as u64 * 8;
    // Create the minimum ~2.5 epochs of extra blocks required to re-finalize the chain.
    // Having this set lower ensures that we start justifying and finalizing quickly after a skip.
    let final_blocks = 2 * E::slots_per_epoch() + E::slots_per_epoch() / 2;

    harness
        .extend_chain(
            initial_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    check_finalization(&harness, initial_blocks);

    // 2. Skip slots
    for _ in 0..skip_slots {
        harness.advance_slot();
    }

    // 3. Produce more blocks, establish a new finalized epoch
    harness
        .extend_chain(
            final_blocks as usize,
            BlockStrategy::ForkCanonicalChainAt {
                previous_slot: Slot::new(initial_blocks),
                first_slot: Slot::new(initial_blocks + skip_slots as u64 + 1),
            },
            AttestationStrategy::AllValidators,
        )
        .await;

    check_finalization(&harness, initial_blocks + skip_slots + final_blocks);
    check_split_slot(&harness, store);
    check_chain_dump(&harness, initial_blocks + final_blocks + 1);
    check_iterators(&harness);
}

/// Go forward to the point where the genesis randao value is no longer part of the vector.
///
/// This implicitly checks that:
/// 1. The chunked vector scheme doesn't attempt to store an incorrect genesis value
/// 2. We correctly load the genesis value for all required slots
/// NOTE: this test takes about a minute to run
#[tokio::test]
async fn randao_genesis_storage() {
    let validator_count = 8;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), validator_count);

    let num_slots = E::slots_per_epoch() * (E::epochs_per_historical_vector() - 1) as u64;

    // Check we have a non-trivial genesis value
    let genesis_value = *harness
        .chain
        .head_snapshot()
        .beacon_state
        .get_randao_mix(Epoch::new(0))
        .expect("randao mix ok");
    assert!(!genesis_value.is_zero());

    harness
        .extend_chain(
            num_slots as usize - 1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Check that genesis value is still present
    assert!(harness
        .chain
        .head_snapshot()
        .beacon_state
        .randao_mixes()
        .iter()
        .find(|x| **x == genesis_value)
        .is_some());

    // Then upon adding one more block, it isn't
    harness.advance_slot();
    harness
        .extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    assert!(harness
        .chain
        .head_snapshot()
        .beacon_state
        .randao_mixes()
        .iter()
        .find(|x| **x == genesis_value)
        .is_none());

    check_finalization(&harness, num_slots);
    check_split_slot(&harness, store);
    check_chain_dump(&harness, num_slots + 1);
    check_iterators(&harness);
}

// Check that closing and reopening a freezer DB restores the split slot to its correct value.
#[tokio::test]
async fn split_slot_restore() {
    let db_path = tempdir().unwrap();

    let split_slot = {
        let store = get_store(&db_path);
        let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

        let num_blocks = 4 * E::slots_per_epoch();

        harness
            .extend_chain(
                num_blocks as usize,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::AllValidators,
            )
            .await;

        store.get_split_slot()
    };
    assert_ne!(split_slot, Slot::new(0));

    // Re-open the store
    let store = get_store(&db_path);

    assert_eq!(store.get_split_slot(), split_slot);
}

// Check attestation processing and `load_epoch_boundary_state` in the presence of a split DB.
// This is a bit of a monster test in that it tests lots of different things, but until they're
// tested elsewhere, this is as good a place as any.
#[tokio::test]
async fn epoch_boundary_state_attestation_processing() {
    let num_blocks_produced = E::slots_per_epoch() * 5;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    let late_validators = vec![0, 1];
    let timely_validators = (2..LOW_VALIDATOR_COUNT).collect::<Vec<_>>();

    let mut late_attestations = vec![];

    for _ in 0..num_blocks_produced {
        harness
            .extend_chain(
                1,
                BlockStrategy::OnCanonicalHead,
                AttestationStrategy::SomeValidators(timely_validators.clone()),
            )
            .await;

        let head = harness.chain.head_snapshot();
        late_attestations.extend(harness.get_unaggregated_attestations(
            &AttestationStrategy::SomeValidators(late_validators.clone()),
            &head.beacon_state,
            head.beacon_state_root(),
            head.beacon_block_root,
            head.beacon_block.slot(),
        ));

        harness.advance_slot();
    }

    check_finalization(&harness, num_blocks_produced);
    check_split_slot(&harness, store.clone());
    check_chain_dump(&harness, num_blocks_produced + 1);
    check_iterators(&harness);

    let mut checked_pre_fin = false;

    for (attestation, subnet_id) in late_attestations.into_iter().flatten() {
        // load_epoch_boundary_state is idempotent!
        let block_root = attestation.data.beacon_block_root;
        let block = store
            .get_blinded_block(&block_root)
            .unwrap()
            .expect("block exists");
        let epoch_boundary_state = store
            .load_epoch_boundary_state(&block.state_root())
            .expect("no error")
            .expect("epoch boundary state exists");
        let ebs_of_ebs = store
            .load_epoch_boundary_state(&epoch_boundary_state.canonical_root())
            .expect("no error")
            .expect("ebs of ebs exists");
        assert_eq!(epoch_boundary_state, ebs_of_ebs);

        // If the attestation is pre-finalization it should be rejected.
        let finalized_epoch = harness.finalized_checkpoint().epoch;

        let res = harness
            .chain
            .verify_unaggregated_attestation_for_gossip(&attestation, Some(subnet_id));

        let current_slot = harness.chain.slot().expect("should get slot");
        let expected_attestation_slot = attestation.data.slot;
        // Extra -1 to handle gossip clock disparity.
        let expected_earliest_permissible_slot = current_slot - E::slots_per_epoch() - 1;

        if expected_attestation_slot <= finalized_epoch.start_slot(E::slots_per_epoch())
            || expected_attestation_slot < expected_earliest_permissible_slot
        {
            checked_pre_fin = true;
            assert!(matches!(
                res.err().unwrap(),
                AttnError::PastSlot {
                    attestation_slot,
                    earliest_permissible_slot,
                }
                if attestation_slot == expected_attestation_slot && earliest_permissible_slot == expected_earliest_permissible_slot
            ));
        } else {
            res.expect("should have verified attetation");
        }
    }
    assert!(checked_pre_fin);
}

// Test that the `end_slot` for forwards block and state root iterators works correctly.
#[tokio::test]
async fn forwards_iter_block_and_state_roots_until() {
    let num_blocks_produced = E::slots_per_epoch() * 17;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    let all_validators = &harness.get_all_validators();
    let (mut head_state, mut head_state_root) = harness.get_current_state_and_root();
    let head_block_root = harness.head_block_root();
    let mut block_roots = vec![head_block_root];
    let mut state_roots = vec![head_state_root];

    for slot in (1..=num_blocks_produced).map(Slot::from) {
        let (block_root, mut state) = harness
            .add_attested_block_at_slot(slot, head_state, head_state_root, all_validators)
            .await
            .unwrap();
        head_state_root = state.update_tree_hash_cache().unwrap();
        head_state = state;
        block_roots.push(block_root.into());
        state_roots.push(head_state_root);
    }

    check_finalization(&harness, num_blocks_produced);
    check_split_slot(&harness, store.clone());

    // The last restore point slot is the point at which the hybrid forwards iterator behaviour
    // changes.
    let last_restore_point_slot = store.get_latest_restore_point_slot().unwrap();
    assert!(last_restore_point_slot > 0);

    let chain = &harness.chain;
    let head_state = harness.get_current_state();
    let head_slot = head_state.slot();
    assert_eq!(head_slot, num_blocks_produced);

    let test_range = |start_slot: Slot, end_slot: Slot| {
        let mut block_root_iter = chain
            .forwards_iter_block_roots_until(start_slot, end_slot)
            .unwrap();
        let mut state_root_iter = chain
            .forwards_iter_state_roots_until(start_slot, end_slot)
            .unwrap();

        for slot in (start_slot.as_u64()..=end_slot.as_u64()).map(Slot::new) {
            let block_root = block_roots[slot.as_usize()];
            assert_eq!(block_root_iter.next().unwrap().unwrap(), (block_root, slot));

            let state_root = state_roots[slot.as_usize()];
            assert_eq!(state_root_iter.next().unwrap().unwrap(), (state_root, slot));
        }
    };

    let split_slot = store.get_split_slot();
    assert!(split_slot > last_restore_point_slot);

    test_range(Slot::new(0), last_restore_point_slot);
    test_range(last_restore_point_slot, last_restore_point_slot);
    test_range(last_restore_point_slot - 1, last_restore_point_slot);
    test_range(Slot::new(0), last_restore_point_slot - 1);
    test_range(Slot::new(0), split_slot);
    test_range(last_restore_point_slot - 1, split_slot);
    test_range(Slot::new(0), head_state.slot());
}

#[tokio::test]
async fn block_replay_with_inaccurate_state_roots() {
    let num_blocks_produced = E::slots_per_epoch() * 3 + 31;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);
    let chain = &harness.chain;

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    // Slot must not be 0 mod 32 or else no blocks will be replayed.
    let (mut head_state, head_state_root) = harness.get_current_state_and_root();
    let head_block_root = harness.head_block_root();
    assert_ne!(head_state.slot() % 32, 0);

    let (_, mut fast_head_state) = store
        .get_inconsistent_state_for_attestation_verification_only(
            &head_block_root,
            head_state.slot(),
            head_state_root,
        )
        .unwrap()
        .unwrap();
    assert_eq!(head_state.validators(), fast_head_state.validators());

    head_state.build_all_committee_caches(&chain.spec).unwrap();
    fast_head_state
        .build_all_committee_caches(&chain.spec)
        .unwrap();

    assert_eq!(
        head_state
            .get_cached_active_validator_indices(RelativeEpoch::Current)
            .unwrap(),
        fast_head_state
            .get_cached_active_validator_indices(RelativeEpoch::Current)
            .unwrap()
    );
}

#[tokio::test]
async fn block_replayer_hooks() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);
    let chain = &harness.chain;

    let block_slots = vec![1, 3, 5, 10, 11, 12, 13, 14, 31, 32, 33]
        .into_iter()
        .map(Slot::new)
        .collect::<Vec<_>>();
    let max_slot = *block_slots.last().unwrap();
    let all_slots = (0..=max_slot.as_u64()).map(Slot::new).collect::<Vec<_>>();

    let (state, state_root) = harness.get_current_state_and_root();
    let all_validators = harness.get_all_validators();
    let (_, _, end_block_root, mut end_state) = harness
        .add_attested_blocks_at_slots(state.clone(), state_root, &block_slots, &all_validators)
        .await;

    let blocks = store
        .load_blocks_to_replay(Slot::new(0), max_slot, end_block_root.into())
        .unwrap();

    let mut pre_slots = vec![];
    let mut post_slots = vec![];
    let mut pre_block_slots = vec![];
    let mut post_block_slots = vec![];

    let mut replay_state = BlockReplayer::<MinimalEthSpec>::new(state, &chain.spec)
        .pre_slot_hook(Box::new(|state| {
            pre_slots.push(state.slot());
            Ok(())
        }))
        .post_slot_hook(Box::new(|state, epoch_summary, is_skip_slot| {
            if is_skip_slot {
                assert!(!block_slots.contains(&state.slot()));
            } else {
                assert!(block_slots.contains(&state.slot()));
            }
            if state.slot() % E::slots_per_epoch() == 0 {
                assert!(epoch_summary.is_some());
            }
            post_slots.push(state.slot());
            Ok(())
        }))
        .pre_block_hook(Box::new(|state, block| {
            assert_eq!(state.slot(), block.slot());
            pre_block_slots.push(block.slot());
            Ok(())
        }))
        .post_block_hook(Box::new(|state, block| {
            assert_eq!(state.slot(), block.slot());
            post_block_slots.push(block.slot());
            Ok(())
        }))
        .apply_blocks(blocks, None)
        .unwrap()
        .into_state();

    // All but last slot seen by pre-slot hook
    assert_eq!(&pre_slots, all_slots.split_last().unwrap().1);
    // All but 0th slot seen by post-slot hook
    assert_eq!(&post_slots, all_slots.split_first().unwrap().1);
    // All blocks seen by both hooks
    assert_eq!(pre_block_slots, block_slots);
    assert_eq!(post_block_slots, block_slots);

    // States match.
    end_state.drop_all_caches().unwrap();
    replay_state.drop_all_caches().unwrap();
    assert_eq!(end_state, replay_state);
}

#[tokio::test]
async fn delete_blocks_and_states() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    let unforked_blocks: u64 = 4 * E::slots_per_epoch();

    // Finalize an initial portion of the chain.
    let initial_slots: Vec<Slot> = (1..=unforked_blocks).map(Into::into).collect();
    let (state, state_root) = harness.get_current_state_and_root();
    let all_validators = harness.get_all_validators();
    harness
        .add_attested_blocks_at_slots(state, state_root, &initial_slots, &all_validators)
        .await;

    // Create a fork post-finalization.
    let two_thirds = (LOW_VALIDATOR_COUNT / 3) * 2;
    let honest_validators: Vec<usize> = (0..two_thirds).collect();
    let faulty_validators: Vec<usize> = (two_thirds..LOW_VALIDATOR_COUNT).collect();

    let fork_blocks = 2 * E::slots_per_epoch();

    let slot_u64: u64 = harness.get_current_slot().as_u64() + 1;

    let fork1_slots: Vec<Slot> = (slot_u64..(slot_u64 + fork_blocks))
        .map(Into::into)
        .collect();
    let fork2_slots: Vec<Slot> = (slot_u64 + 1..(slot_u64 + 1 + fork_blocks))
        .map(Into::into)
        .collect();

    let fork1_state = harness.get_current_state();
    let fork2_state = fork1_state.clone();
    let results = harness
        .add_blocks_on_multiple_chains(vec![
            (fork1_state, fork1_slots, honest_validators),
            (fork2_state, fork2_slots, faulty_validators),
        ])
        .await;

    let honest_head = results[0].2;
    let faulty_head = results[1].2;

    assert_ne!(honest_head, faulty_head, "forks should be distinct");
    assert_eq!(harness.head_slot(), unforked_blocks + fork_blocks);

    assert_eq!(
        harness.head_block_root(),
        honest_head.into(),
        "the honest chain should be the canonical chain",
    );

    let faulty_head_block = store
        .get_blinded_block(&faulty_head.into())
        .expect("no errors")
        .expect("faulty head block exists");

    let faulty_head_state = store
        .get_state(
            &faulty_head_block.state_root(),
            Some(faulty_head_block.slot()),
        )
        .expect("no db error")
        .expect("faulty head state exists");

    // Delete faulty fork
    // Attempting to load those states should find them unavailable
    for (state_root, slot) in
        StateRootsIterator::new(&store, &faulty_head_state).map(Result::unwrap)
    {
        if slot <= unforked_blocks {
            break;
        }
        store.delete_state(&state_root, slot).unwrap();
        assert_eq!(store.get_state(&state_root, Some(slot)).unwrap(), None);
    }

    // Double-deleting should also be OK (deleting non-existent things is fine)
    for (state_root, slot) in
        StateRootsIterator::new(&store, &faulty_head_state).map(Result::unwrap)
    {
        if slot <= unforked_blocks {
            break;
        }
        store.delete_state(&state_root, slot).unwrap();
    }

    // Deleting the blocks from the fork should remove them completely
    for (block_root, slot) in
        BlockRootsIterator::new(&store, &faulty_head_state).map(Result::unwrap)
    {
        if slot <= unforked_blocks + 1 {
            break;
        }
        store.delete_block(&block_root).unwrap();
        assert_eq!(store.get_blinded_block(&block_root).unwrap(), None);
    }

    // Deleting frozen states should do nothing
    let split_slot = store.get_split_slot();
    let finalized_states = harness
        .chain
        .forwards_iter_state_roots(Slot::new(0))
        .expect("should get iter")
        .map(Result::unwrap);

    for (state_root, slot) in finalized_states {
        if slot < split_slot {
            store.delete_state(&state_root, slot).unwrap();
        }
    }

    // After all that, the chain dump should still be OK
    check_chain_dump(&harness, unforked_blocks + fork_blocks + 1);
}

// Check that we never produce invalid blocks when there is deep forking that changes the shuffling.
// See https://github.com/sigp/lighthouse/issues/845
async fn multi_epoch_fork_valid_blocks_test(
    initial_blocks: usize,
    num_fork1_blocks_: usize,
    num_fork2_blocks_: usize,
    num_fork1_validators: usize,
) -> (TempDir, TestHarness, Hash256, Hash256) {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let validators_keypairs =
        types::test_utils::generate_deterministic_keypairs(LOW_VALIDATOR_COUNT);
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(validators_keypairs)
        .fresh_disk_store(store)
        .mock_execution_layer()
        .build();

    let num_fork1_blocks: u64 = num_fork1_blocks_.try_into().unwrap();
    let num_fork2_blocks: u64 = num_fork2_blocks_.try_into().unwrap();

    // Create the initial portion of the chain
    if initial_blocks > 0 {
        let initial_slots: Vec<Slot> = (1..=initial_blocks).map(Into::into).collect();
        let (state, state_root) = harness.get_current_state_and_root();
        let all_validators = harness.get_all_validators();
        harness
            .add_attested_blocks_at_slots(state, state_root, &initial_slots, &all_validators)
            .await;
    }

    assert!(num_fork1_validators <= LOW_VALIDATOR_COUNT);
    let fork1_validators: Vec<usize> = (0..num_fork1_validators).collect();
    let fork2_validators: Vec<usize> = (num_fork1_validators..LOW_VALIDATOR_COUNT).collect();

    let fork1_state = harness.get_current_state();
    let fork2_state = fork1_state.clone();

    let slot_u64: u64 = harness.get_current_slot().as_u64() + 1;
    let fork1_slots: Vec<Slot> = (slot_u64..(slot_u64 + num_fork1_blocks))
        .map(Into::into)
        .collect();
    let fork2_slots: Vec<Slot> = (slot_u64 + 1..(slot_u64 + 1 + num_fork2_blocks))
        .map(Into::into)
        .collect();

    let results = harness
        .add_blocks_on_multiple_chains(vec![
            (fork1_state, fork1_slots, fork1_validators),
            (fork2_state, fork2_slots, fork2_validators),
        ])
        .await;

    let head1 = results[0].2;
    let head2 = results[1].2;

    (db_path, harness, head1.into(), head2.into())
}

// This is the minimal test of block production with different shufflings.
#[tokio::test]
async fn block_production_different_shuffling_early() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    multi_epoch_fork_valid_blocks_test(
        slots_per_epoch - 2,
        slots_per_epoch + 3,
        slots_per_epoch + 3,
        LOW_VALIDATOR_COUNT / 2,
    )
    .await;
}

#[tokio::test]
async fn block_production_different_shuffling_long() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    multi_epoch_fork_valid_blocks_test(
        2 * slots_per_epoch - 2,
        3 * slots_per_epoch,
        3 * slots_per_epoch,
        LOW_VALIDATOR_COUNT / 2,
    )
    .await;
}

// Check that the op pool safely includes multiple attestations per block when necessary.
// This checks the correctness of the shuffling compatibility memoization.
#[tokio::test]
async fn multiple_attestations_per_block() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store, HIGH_VALIDATOR_COUNT);

    harness
        .extend_chain(
            E::slots_per_epoch() as usize * 3,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let head = harness.chain.head_snapshot();
    let committees_per_slot = head
        .beacon_state
        .get_committee_count_at_slot(head.beacon_state.slot())
        .unwrap();
    assert!(committees_per_slot > 1);

    for snapshot in harness.chain.chain_dump().unwrap() {
        let slot = snapshot.beacon_block.slot();
        assert_eq!(
            snapshot
                .beacon_block
                .as_ref()
                .message()
                .body()
                .attestations()
                .len() as u64,
            if slot <= 1 { 0 } else { committees_per_slot }
        );
    }
}

#[tokio::test]
async fn shuffling_compatible_linear_chain() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    let head_block_root = harness
        .extend_chain(
            4 * E::slots_per_epoch() as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    check_shuffling_compatible(
        &harness,
        &get_state_for_block(&harness, head_block_root),
        head_block_root,
    );
}

#[tokio::test]
async fn shuffling_compatible_missing_pivot_block() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // Skip the block at the end of the first epoch.
    harness
        .extend_chain(
            E::slots_per_epoch() as usize - 2,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;
    harness.advance_slot();
    harness.advance_slot();
    let head_block_root = harness
        .extend_chain(
            2 * E::slots_per_epoch() as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    check_shuffling_compatible(
        &harness,
        &get_state_for_block(&harness, head_block_root),
        head_block_root,
    );
}

#[tokio::test]
async fn shuffling_compatible_simple_fork() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    let (db_path, harness, head1, head2) = multi_epoch_fork_valid_blocks_test(
        2 * slots_per_epoch,
        3 * slots_per_epoch,
        3 * slots_per_epoch,
        LOW_VALIDATOR_COUNT / 2,
    )
    .await;

    let head1_state = get_state_for_block(&harness, head1);
    let head2_state = get_state_for_block(&harness, head2);

    check_shuffling_compatible(&harness, &head1_state, head1);
    check_shuffling_compatible(&harness, &head1_state, head2);
    check_shuffling_compatible(&harness, &head2_state, head1);
    check_shuffling_compatible(&harness, &head2_state, head2);

    drop(db_path);
}

#[tokio::test]
async fn shuffling_compatible_short_fork() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    let (db_path, harness, head1, head2) = multi_epoch_fork_valid_blocks_test(
        2 * slots_per_epoch - 2,
        slots_per_epoch + 2,
        slots_per_epoch + 2,
        LOW_VALIDATOR_COUNT / 2,
    )
    .await;

    let head1_state = get_state_for_block(&harness, head1);
    let head2_state = get_state_for_block(&harness, head2);

    check_shuffling_compatible(&harness, &head1_state, head1);
    check_shuffling_compatible(&harness, &head1_state, head2);
    check_shuffling_compatible(&harness, &head2_state, head1);
    check_shuffling_compatible(&harness, &head2_state, head2);

    drop(db_path);
}

fn get_state_for_block(harness: &TestHarness, block_root: Hash256) -> BeaconState<E> {
    let head_block = harness
        .chain
        .store
        .get_blinded_block(&block_root)
        .unwrap()
        .unwrap();
    harness
        .chain
        .get_state(&head_block.state_root(), Some(head_block.slot()))
        .unwrap()
        .unwrap()
}

/// Check the invariants that apply to `shuffling_is_compatible`.
fn check_shuffling_compatible(
    harness: &TestHarness,
    head_state: &BeaconState<E>,
    head_block_root: Hash256,
) {
    for maybe_tuple in harness
        .chain
        .rev_iter_block_roots_from(head_block_root)
        .unwrap()
    {
        let (block_root, slot) = maybe_tuple.unwrap();

        // Would an attestation to `block_root` at the current epoch be compatible with the head
        // state's shuffling?
        let current_epoch_shuffling_is_compatible = harness.chain.shuffling_is_compatible(
            &block_root,
            head_state.current_epoch(),
            &head_state,
        );

        // Check for consistency with the more expensive shuffling lookup.
        harness
            .chain
            .with_committee_cache(
                block_root,
                head_state.current_epoch(),
                |committee_cache, _| {
                    let state_cache = head_state.committee_cache(RelativeEpoch::Current).unwrap();
                    if current_epoch_shuffling_is_compatible {
                        assert_eq!(committee_cache, state_cache, "block at slot {slot}");
                    } else {
                        assert_ne!(committee_cache, state_cache, "block at slot {slot}");
                    }
                    Ok(())
                },
            )
            .unwrap_or_else(|e| {
                // If the lookup fails then the shuffling must be invalid in some way, e.g. the
                // block with `block_root` is from a later epoch than `previous_epoch`.
                assert!(
                    !current_epoch_shuffling_is_compatible,
                    "block at slot {slot} has compatible shuffling at epoch {} \
                     but should be incompatible due to error: {e:?}",
                    head_state.current_epoch()
                );
            });

        // Similarly for the previous epoch
        let previous_epoch_shuffling_is_compatible = harness.chain.shuffling_is_compatible(
            &block_root,
            head_state.previous_epoch(),
            &head_state,
        );
        harness
            .chain
            .with_committee_cache(
                block_root,
                head_state.previous_epoch(),
                |committee_cache, _| {
                    let state_cache = head_state.committee_cache(RelativeEpoch::Previous).unwrap();
                    if previous_epoch_shuffling_is_compatible {
                        assert_eq!(committee_cache, state_cache);
                    } else {
                        assert_ne!(committee_cache, state_cache);
                    }
                    Ok(())
                },
            )
            .unwrap_or_else(|e| {
                // If the lookup fails then the shuffling must be invalid in some way, e.g. the
                // block with `block_root` is from a later epoch than `previous_epoch`.
                assert!(
                    !previous_epoch_shuffling_is_compatible,
                    "block at slot {slot} has compatible shuffling at epoch {} \
                     but should be incompatible due to error: {e:?}",
                    head_state.previous_epoch()
                );
            });

        // Targeting two epochs before the current epoch should always return false
        if head_state.current_epoch() >= 2 {
            assert_eq!(
                harness.chain.shuffling_is_compatible(
                    &block_root,
                    head_state.current_epoch() - 2,
                    &head_state
                ),
                false
            );
        }
    }
}

// Ensure blocks from abandoned forks are pruned from the Hot DB
#[tokio::test]
async fn prunes_abandoned_fork_between_two_finalized_checkpoints() {
    const HONEST_VALIDATOR_COUNT: usize = 32;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 16;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let rig = get_harness(store.clone(), VALIDATOR_COUNT);
    let slots_per_epoch = rig.slots_per_epoch();
    let (mut state, state_root) = rig.get_current_state_and_root();

    let canonical_chain_slots: Vec<Slot> = (1..=rig.epoch_start_slot(1)).map(Slot::new).collect();
    let (canonical_chain_blocks_pre_finalization, _, _, new_state) = rig
        .add_attested_blocks_at_slots(
            state,
            state_root,
            &canonical_chain_slots,
            &honest_validators,
        )
        .await;
    state = new_state;
    let canonical_chain_slot: u64 = rig.get_current_slot().into();

    let stray_slots: Vec<Slot> = (canonical_chain_slot + 1..rig.epoch_start_slot(2))
        .map(Slot::new)
        .collect();
    let (current_state, current_state_root) = rig.get_current_state_and_root();
    let (stray_blocks, stray_states, stray_head, _) = rig
        .add_attested_blocks_at_slots(
            current_state,
            current_state_root,
            &stray_slots,
            &adversarial_validators,
        )
        .await;

    // Precondition: Ensure all stray_blocks blocks are still known
    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    assert_eq!(rig.get_finalized_checkpoints(), hashset! {},);

    assert!(rig.chain.knows_head(&stray_head));

    // Trigger finalization
    let finalization_slots: Vec<Slot> = ((canonical_chain_slot + 1)
        ..=(canonical_chain_slot + slots_per_epoch * 5))
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (canonical_chain_blocks_post_finalization, _, _, _) = rig
        .add_attested_blocks_at_slots(state, state_root, &finalization_slots, &honest_validators)
        .await;

    // Postcondition: New blocks got finalized
    assert_eq!(
        rig.get_finalized_checkpoints(),
        hashset! {
            canonical_chain_blocks_pre_finalization[&rig.epoch_start_slot(1).into()],
            canonical_chain_blocks_post_finalization[&rig.epoch_start_slot(2).into()],
        },
    );

    // Postcondition: Ensure all stray_blocks blocks have been pruned
    for &block_hash in stray_blocks.values() {
        assert!(
            !rig.block_exists(block_hash),
            "abandoned block {} should have been pruned",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            !rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
        assert!(
            !rig.cold_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
    }

    assert!(!rig.chain.knows_head(&stray_head));
}

#[tokio::test]
async fn pruning_does_not_touch_abandoned_block_shared_with_canonical_chain() {
    const HONEST_VALIDATOR_COUNT: usize = 32;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 16;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let rig = get_harness(store.clone(), VALIDATOR_COUNT);
    let slots_per_epoch = rig.slots_per_epoch();
    let (state, state_root) = rig.get_current_state_and_root();

    // Fill up 0th epoch
    let canonical_chain_slots_zeroth_epoch: Vec<Slot> =
        (1..rig.epoch_start_slot(1)).map(Slot::new).collect();
    let (_, _, _, mut state) = rig
        .add_attested_blocks_at_slots(
            state,
            state_root,
            &canonical_chain_slots_zeroth_epoch,
            &honest_validators,
        )
        .await;

    // Fill up 1st epoch
    let canonical_chain_slots_first_epoch: Vec<Slot> = (rig.epoch_start_slot(1)
        ..=rig.epoch_start_slot(1) + 1)
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (canonical_chain_blocks_first_epoch, _, shared_head, mut state) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &canonical_chain_slots_first_epoch,
            &honest_validators,
        )
        .await;
    let canonical_chain_slot: u64 = rig.get_current_slot().into();

    let stray_chain_slots_first_epoch: Vec<Slot> = (rig.epoch_start_slot(1) + 2
        ..=rig.epoch_start_slot(1) + 2)
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (stray_blocks, stray_states, stray_head, _) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &stray_chain_slots_first_epoch,
            &adversarial_validators,
        )
        .await;

    // Preconditions
    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    let chain_dump = rig.chain.chain_dump().unwrap();
    assert_eq!(
        get_finalized_epoch_boundary_blocks(&chain_dump),
        vec![Hash256::zero().into()].into_iter().collect(),
    );

    assert!(get_blocks(&chain_dump).contains(&shared_head));

    // Trigger finalization
    let finalization_slots: Vec<Slot> = ((canonical_chain_slot + 1)
        ..=(canonical_chain_slot + slots_per_epoch * 5))
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (canonical_chain_blocks, _, _, _) = rig
        .add_attested_blocks_at_slots(state, state_root, &finalization_slots, &honest_validators)
        .await;

    // Postconditions
    assert_eq!(
        rig.get_finalized_checkpoints(),
        hashset! {
            canonical_chain_blocks_first_epoch[&rig.epoch_start_slot(1).into()],
            canonical_chain_blocks[&rig.epoch_start_slot(2).into()],
        },
    );

    for &block_hash in stray_blocks.values() {
        assert!(
            !rig.block_exists(block_hash),
            "stray block {} should have been pruned",
            block_hash,
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            !rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
        assert!(
            !rig.cold_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
    }

    assert!(!rig.chain.knows_head(&stray_head));
    let chain_dump = rig.chain.chain_dump().unwrap();
    assert!(get_blocks(&chain_dump).contains(&shared_head));
}

#[tokio::test]
async fn pruning_does_not_touch_blocks_prior_to_finalization() {
    const HONEST_VALIDATOR_COUNT: usize = 32;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 16;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let rig = get_harness(store.clone(), VALIDATOR_COUNT);
    let slots_per_epoch = rig.slots_per_epoch();
    let (mut state, state_root) = rig.get_current_state_and_root();

    // Fill up 0th epoch with canonical chain blocks
    let zeroth_epoch_slots: Vec<Slot> = (1..=rig.epoch_start_slot(1)).map(Slot::new).collect();
    let (canonical_chain_blocks, _, _, new_state) = rig
        .add_attested_blocks_at_slots(state, state_root, &zeroth_epoch_slots, &honest_validators)
        .await;
    state = new_state;
    let canonical_chain_slot: u64 = rig.get_current_slot().into();

    // Fill up 1st epoch.  Contains a fork.
    let first_epoch_slots: Vec<Slot> = ((rig.epoch_start_slot(1) + 1)..(rig.epoch_start_slot(2)))
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (stray_blocks, stray_states, stray_head, _) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &first_epoch_slots,
            &adversarial_validators,
        )
        .await;

    // Preconditions
    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    assert_eq!(rig.get_finalized_checkpoints(), hashset! {});

    // Trigger finalization
    let slots: Vec<Slot> = ((canonical_chain_slot + 1)
        ..=(canonical_chain_slot + slots_per_epoch * 4))
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (_, _, _, _) = rig
        .add_attested_blocks_at_slots(state, state_root, &slots, &honest_validators)
        .await;

    // Postconditions
    assert_eq!(
        rig.get_finalized_checkpoints(),
        hashset! {canonical_chain_blocks[&rig.epoch_start_slot(1).into()]},
    );

    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    assert!(rig.chain.knows_head(&stray_head));
}

#[tokio::test]
async fn prunes_fork_growing_past_youngest_finalized_checkpoint() {
    const HONEST_VALIDATOR_COUNT: usize = 32;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 16;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let rig = get_harness(store.clone(), VALIDATOR_COUNT);
    let (state, state_root) = rig.get_current_state_and_root();

    // Fill up 0th epoch with canonical chain blocks
    let zeroth_epoch_slots: Vec<Slot> = (1..=rig.epoch_start_slot(1)).map(Slot::new).collect();
    let (canonical_blocks_zeroth_epoch, _, _, mut state) = rig
        .add_attested_blocks_at_slots(state, state_root, &zeroth_epoch_slots, &honest_validators)
        .await;

    // Fill up 1st epoch.  Contains a fork.
    let slots_first_epoch: Vec<Slot> = (rig.epoch_start_slot(1) + 1..rig.epoch_start_slot(2))
        .map(Into::into)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (stray_blocks_first_epoch, stray_states_first_epoch, _, mut stray_state) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &slots_first_epoch,
            &adversarial_validators,
        )
        .await;
    let (canonical_blocks_first_epoch, _, _, mut canonical_state) = rig
        .add_attested_blocks_at_slots(state, state_root, &slots_first_epoch, &honest_validators)
        .await;

    // Fill up 2nd epoch.  Extends both the canonical chain and the fork.
    let stray_slots_second_epoch: Vec<Slot> = (rig.epoch_start_slot(2)
        ..=rig.epoch_start_slot(2) + 1)
        .map(Into::into)
        .collect();
    let stray_state_root = stray_state.update_tree_hash_cache().unwrap();
    let (stray_blocks_second_epoch, stray_states_second_epoch, stray_head, _) = rig
        .add_attested_blocks_at_slots(
            stray_state,
            stray_state_root,
            &stray_slots_second_epoch,
            &adversarial_validators,
        )
        .await;

    // Precondition: Ensure all stray_blocks blocks are still known
    let stray_blocks: HashMap<Slot, SignedBeaconBlockHash> = stray_blocks_first_epoch
        .into_iter()
        .chain(stray_blocks_second_epoch.into_iter())
        .collect();

    let stray_states: HashMap<Slot, BeaconStateHash> = stray_states_first_epoch
        .into_iter()
        .chain(stray_states_second_epoch.into_iter())
        .collect();

    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    // Precondition: Nothing is finalized yet
    assert_eq!(rig.get_finalized_checkpoints(), hashset! {},);

    assert!(rig.chain.knows_head(&stray_head));

    // Trigger finalization
    let canonical_slots: Vec<Slot> = (rig.epoch_start_slot(2)..=rig.epoch_start_slot(6))
        .map(Into::into)
        .collect();
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    let (canonical_blocks, _, _, _) = rig
        .add_attested_blocks_at_slots(
            canonical_state,
            canonical_state_root,
            &canonical_slots,
            &honest_validators,
        )
        .await;

    // Postconditions
    let canonical_blocks: HashMap<Slot, SignedBeaconBlockHash> = canonical_blocks_zeroth_epoch
        .into_iter()
        .chain(canonical_blocks_first_epoch.into_iter())
        .chain(canonical_blocks.into_iter())
        .collect();

    // Postcondition: New blocks got finalized
    assert_eq!(
        rig.get_finalized_checkpoints(),
        hashset! {
            canonical_blocks[&rig.epoch_start_slot(1).into()],
            canonical_blocks[&rig.epoch_start_slot(2).into()],
        },
    );

    // Postcondition: Ensure all stray_blocks blocks have been pruned
    for &block_hash in stray_blocks.values() {
        assert!(
            !rig.block_exists(block_hash),
            "abandoned block {} should have been pruned",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            !rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
        assert!(
            !rig.cold_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
    }

    assert!(!rig.chain.knows_head(&stray_head));
}

// This is to check if state outside of normal block processing are pruned correctly.
#[tokio::test]
async fn prunes_skipped_slots_states() {
    const HONEST_VALIDATOR_COUNT: usize = 32;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 16;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let rig = get_harness(store.clone(), VALIDATOR_COUNT);
    let (state, state_root) = rig.get_current_state_and_root();

    let canonical_slots_zeroth_epoch: Vec<Slot> =
        (1..=rig.epoch_start_slot(1)).map(Into::into).collect();
    let (canonical_blocks_zeroth_epoch, _, _, mut canonical_state) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &canonical_slots_zeroth_epoch,
            &honest_validators,
        )
        .await;

    let skipped_slot: Slot = (rig.epoch_start_slot(1) + 1).into();

    let stray_slots: Vec<Slot> = ((skipped_slot + 1).into()..rig.epoch_start_slot(2))
        .map(Into::into)
        .collect();
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    let (stray_blocks, stray_states, _, stray_state) = rig
        .add_attested_blocks_at_slots(
            canonical_state.clone(),
            canonical_state_root,
            &stray_slots,
            &adversarial_validators,
        )
        .await;

    // Preconditions
    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    assert_eq!(rig.get_finalized_checkpoints(), hashset! {},);

    // Make sure slots were skipped
    assert!(rig.is_skipped_slot(&stray_state, skipped_slot));
    {
        let state_hash = (*stray_state.get_state_root(skipped_slot).unwrap()).into();
        assert!(
            rig.hot_state_exists(state_hash),
            "skipped slot state {} should be still present",
            state_hash
        );
    }

    // Trigger finalization
    let canonical_slots: Vec<Slot> = ((skipped_slot + 1).into()..rig.epoch_start_slot(7))
        .map(Into::into)
        .collect();
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    let (canonical_blocks_post_finalization, _, _, _) = rig
        .add_attested_blocks_at_slots(
            canonical_state,
            canonical_state_root,
            &canonical_slots,
            &honest_validators,
        )
        .await;

    // Postconditions
    let canonical_blocks: HashMap<Slot, SignedBeaconBlockHash> = canonical_blocks_zeroth_epoch
        .into_iter()
        .chain(canonical_blocks_post_finalization.into_iter())
        .collect();
    assert_eq!(
        rig.get_finalized_checkpoints(),
        hashset! {
            canonical_blocks[&rig.epoch_start_slot(1).into()],
            canonical_blocks[&rig.epoch_start_slot(2).into()],
        },
    );

    for (&slot, &state_hash) in &stray_states {
        assert!(
            !rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
        assert!(
            !rig.cold_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
    }

    assert!(rig.is_skipped_slot(&stray_state, skipped_slot));
    {
        let state_hash: BeaconStateHash =
            (*stray_state.get_state_root(skipped_slot).unwrap()).into();
        assert!(
            !rig.hot_state_exists(state_hash),
            "skipped slot {} state {} should have been pruned",
            skipped_slot,
            state_hash
        );
    }
}

// This is to check if state outside of normal block processing are pruned correctly.
#[tokio::test]
async fn finalizes_non_epoch_start_slot() {
    const HONEST_VALIDATOR_COUNT: usize = 32;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 16;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let rig = get_harness(store.clone(), VALIDATOR_COUNT);
    let (state, state_root) = rig.get_current_state_and_root();

    let canonical_slots_zeroth_epoch: Vec<Slot> =
        (1..rig.epoch_start_slot(1)).map(Into::into).collect();
    let (canonical_blocks_zeroth_epoch, _, _, mut canonical_state) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &canonical_slots_zeroth_epoch,
            &honest_validators,
        )
        .await;

    let skipped_slot: Slot = rig.epoch_start_slot(1).into();

    let stray_slots: Vec<Slot> = ((skipped_slot + 1).into()..rig.epoch_start_slot(2))
        .map(Into::into)
        .collect();
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    let (stray_blocks, stray_states, _, stray_state) = rig
        .add_attested_blocks_at_slots(
            canonical_state.clone(),
            canonical_state_root,
            &stray_slots,
            &adversarial_validators,
        )
        .await;

    // Preconditions
    for &block_hash in stray_blocks.values() {
        assert!(
            rig.block_exists(block_hash),
            "stray block {} should be still present",
            block_hash
        );
    }

    for (&slot, &state_hash) in &stray_states {
        assert!(
            rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should be still present",
            state_hash,
            slot
        );
    }

    assert_eq!(rig.get_finalized_checkpoints(), hashset! {});

    // Make sure slots were skipped
    assert!(rig.is_skipped_slot(&stray_state, skipped_slot));
    {
        let state_hash = (*stray_state.get_state_root(skipped_slot).unwrap()).into();
        assert!(
            rig.hot_state_exists(state_hash),
            "skipped slot state {} should be still present",
            state_hash
        );
    }

    // Trigger finalization
    let canonical_slots: Vec<Slot> = ((skipped_slot + 1).into()..rig.epoch_start_slot(7))
        .map(Into::into)
        .collect();
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    let (canonical_blocks_post_finalization, _, _, _) = rig
        .add_attested_blocks_at_slots(
            canonical_state,
            canonical_state_root,
            &canonical_slots,
            &honest_validators,
        )
        .await;

    // Postconditions
    let canonical_blocks: HashMap<Slot, SignedBeaconBlockHash> = canonical_blocks_zeroth_epoch
        .into_iter()
        .chain(canonical_blocks_post_finalization.into_iter())
        .collect();
    assert_eq!(
        rig.get_finalized_checkpoints(),
        hashset! {
            canonical_blocks[&(rig.epoch_start_slot(1)-1).into()],
            canonical_blocks[&rig.epoch_start_slot(2).into()],
        },
    );

    for (&slot, &state_hash) in &stray_states {
        assert!(
            !rig.hot_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
        assert!(
            !rig.cold_state_exists(state_hash),
            "stray state {} at slot {} should have been pruned",
            state_hash,
            slot
        );
    }

    assert!(rig.is_skipped_slot(&stray_state, skipped_slot));
    {
        let state_hash: BeaconStateHash =
            (*stray_state.get_state_root(skipped_slot).unwrap()).into();
        assert!(
            !rig.hot_state_exists(state_hash),
            "skipped slot {} state {} should have been pruned",
            skipped_slot,
            state_hash
        );
    }
}

fn check_all_blocks_exist<'a>(
    harness: &TestHarness,
    blocks: impl Iterator<Item = &'a SignedBeaconBlockHash>,
) {
    for &block_hash in blocks {
        let block = harness.chain.get_blinded_block(&block_hash.into()).unwrap();
        assert!(
            block.is_some(),
            "expected block {:?} to be in DB",
            block_hash
        );
    }
}

fn check_all_states_exist<'a>(
    harness: &TestHarness,
    states: impl Iterator<Item = &'a BeaconStateHash>,
) {
    for &state_hash in states {
        let state = harness.chain.get_state(&state_hash.into(), None).unwrap();
        assert!(
            state.is_some(),
            "expected state {:?} to be in DB",
            state_hash,
        );
    }
}

// Check that none of the given states exist in the database.
fn check_no_states_exist<'a>(
    harness: &TestHarness,
    states: impl Iterator<Item = &'a BeaconStateHash>,
) {
    for &state_root in states {
        assert!(
            harness
                .chain
                .get_state(&state_root.into(), None)
                .unwrap()
                .is_none(),
            "state {:?} should not be in the DB",
            state_root
        );
    }
}

// Check that none of the given blocks exist in the database.
fn check_no_blocks_exist<'a>(
    harness: &TestHarness,
    blocks: impl Iterator<Item = &'a SignedBeaconBlockHash>,
) {
    for &block_hash in blocks {
        let block = harness.chain.get_blinded_block(&block_hash.into()).unwrap();
        assert!(
            block.is_none(),
            "did not expect block {:?} to be in the DB",
            block_hash
        );
    }
}

#[tokio::test]
async fn prune_single_block_fork() {
    let slots_per_epoch = E::slots_per_epoch();
    pruning_test(3 * slots_per_epoch, 1, slots_per_epoch, 0, 1).await;
}

#[tokio::test]
async fn prune_single_block_long_skip() {
    let slots_per_epoch = E::slots_per_epoch();
    pruning_test(
        2 * slots_per_epoch,
        1,
        2 * slots_per_epoch,
        2 * slots_per_epoch as u64,
        1,
    )
    .await;
}

#[tokio::test]
async fn prune_shared_skip_states_mid_epoch() {
    let slots_per_epoch = E::slots_per_epoch();
    pruning_test(
        slots_per_epoch + slots_per_epoch / 2,
        1,
        slots_per_epoch,
        2,
        slots_per_epoch - 1,
    )
    .await;
}

#[tokio::test]
async fn prune_shared_skip_states_epoch_boundaries() {
    let slots_per_epoch = E::slots_per_epoch();
    pruning_test(slots_per_epoch - 1, 1, slots_per_epoch, 2, slots_per_epoch).await;
    pruning_test(slots_per_epoch - 1, 2, slots_per_epoch, 1, slots_per_epoch).await;
    pruning_test(
        2 * slots_per_epoch + slots_per_epoch / 2,
        slots_per_epoch as u64 / 2,
        slots_per_epoch,
        slots_per_epoch as u64 / 2 + 1,
        slots_per_epoch,
    )
    .await;
    pruning_test(
        2 * slots_per_epoch + slots_per_epoch / 2,
        slots_per_epoch as u64 / 2,
        slots_per_epoch,
        slots_per_epoch as u64 / 2 + 1,
        slots_per_epoch,
    )
    .await;
    pruning_test(
        2 * slots_per_epoch - 1,
        slots_per_epoch as u64,
        1,
        0,
        2 * slots_per_epoch,
    )
    .await;
}

/// Generic harness for pruning tests.
async fn pruning_test(
    // Number of blocks to start the chain with before forking.
    num_initial_blocks: u64,
    // Number of skip slots on the main chain after the initial blocks.
    num_canonical_skips: u64,
    // Number of blocks on the main chain after the skip, but before the finalisation-triggering
    // blocks.
    num_canonical_middle_blocks: u64,
    // Number of skip slots on the fork chain after the initial blocks.
    num_fork_skips: u64,
    // Number of blocks on the fork chain after the skips.
    num_fork_blocks: u64,
) {
    const VALIDATOR_COUNT: usize = 24;
    const VALIDATOR_SUPERMAJORITY: usize = (VALIDATOR_COUNT / 3) * 2;
    const HONEST_VALIDATOR_COUNT: usize = VALIDATOR_SUPERMAJORITY;

    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), VALIDATOR_COUNT);
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let faulty_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();

    let slots = |start: Slot, num_blocks: u64| -> Vec<Slot> {
        (start.as_u64()..start.as_u64() + num_blocks)
            .map(Slot::new)
            .collect()
    };

    let start_slot = Slot::new(1);
    let divergence_slot = start_slot + num_initial_blocks;
    let (state, state_root) = harness.get_current_state_and_root();
    let (_, _, _, divergence_state) = harness
        .add_attested_blocks_at_slots(
            state,
            state_root,
            &slots(start_slot, num_initial_blocks)[..],
            &honest_validators,
        )
        .await;

    let mut chains = harness
        .add_blocks_on_multiple_chains(vec![
            // Canonical chain
            (
                divergence_state.clone(),
                slots(
                    divergence_slot + num_canonical_skips,
                    num_canonical_middle_blocks,
                ),
                honest_validators.clone(),
            ),
            // Fork chain
            (
                divergence_state.clone(),
                slots(divergence_slot + num_fork_skips, num_fork_blocks),
                faulty_validators,
            ),
        ])
        .await;
    let (_, _, _, mut canonical_state) = chains.remove(0);
    let (stray_blocks, stray_states, _, stray_head_state) = chains.remove(0);

    let stray_head_slot = divergence_slot + num_fork_skips + num_fork_blocks - 1;
    let stray_head_state_root = stray_states[&stray_head_slot];
    let stray_states = harness
        .chain
        .rev_iter_state_roots_from(stray_head_state_root.into(), &stray_head_state)
        .map(Result::unwrap)
        .map(|(state_root, _)| state_root.into())
        .collect::<HashSet<_>>();

    check_all_blocks_exist(&harness, stray_blocks.values());
    check_all_states_exist(&harness, stray_states.iter());

    let chain_dump = harness.chain.chain_dump().unwrap();
    assert_eq!(
        get_finalized_epoch_boundary_blocks(&chain_dump),
        vec![Hash256::zero().into()].into_iter().collect(),
    );

    // Trigger finalization
    let num_finalization_blocks = 4 * E::slots_per_epoch();
    let canonical_slot = divergence_slot + num_canonical_skips + num_canonical_middle_blocks;
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    harness
        .add_attested_blocks_at_slots(
            canonical_state,
            canonical_state_root,
            &slots(canonical_slot, num_finalization_blocks),
            &honest_validators,
        )
        .await;

    // Check that finalization has advanced past the divergence slot.
    assert!(
        harness
            .finalized_checkpoint()
            .epoch
            .start_slot(E::slots_per_epoch())
            > divergence_slot
    );
    check_chain_dump(
        &harness,
        (num_initial_blocks + num_canonical_middle_blocks + num_finalization_blocks + 1) as u64,
    );

    let all_canonical_states = harness
        .chain
        .forwards_iter_state_roots(Slot::new(0))
        .unwrap()
        .map(Result::unwrap)
        .map(|(state_root, _)| state_root.into())
        .collect::<HashSet<BeaconStateHash>>();

    check_all_states_exist(&harness, all_canonical_states.iter());
    check_no_states_exist(&harness, stray_states.difference(&all_canonical_states));
    check_no_blocks_exist(&harness, stray_blocks.values());
}

#[tokio::test]
async fn garbage_collect_temp_states_from_failed_block() {
    let db_path = tempdir().unwrap();

    // Wrap these functions to ensure the variables are dropped before we try to open another
    // instance of the store.
    let mut store = {
        let store = get_store(&db_path);
        let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

        let slots_per_epoch = E::slots_per_epoch();

        let genesis_state = harness.get_current_state();
        let block_slot = Slot::new(2 * slots_per_epoch);
        let (signed_block, state) = harness.make_block(genesis_state, block_slot).await;

        let (mut block, _) = signed_block.deconstruct();

        // Mutate the block to make it invalid, and re-sign it.
        *block.state_root_mut() = Hash256::repeat_byte(0xff);
        let proposer_index = block.proposer_index() as usize;
        let block = block.sign(
            &harness.validator_keypairs[proposer_index].sk,
            &state.fork(),
            state.genesis_validators_root(),
            &harness.spec,
        );

        // The block should be rejected, but should store a bunch of temporary states.
        harness.set_current_slot(block_slot);
        harness.process_block_result(block).await.unwrap_err();

        assert_eq!(
            store.iter_temporary_state_roots().count(),
            block_slot.as_usize() - 1
        );
        store
    };

    // Wait until all the references to the store have been dropped, this helps ensure we can
    // re-open the store later.
    loop {
        store = if let Err(store_arc) = Arc::try_unwrap(store) {
            sleep(Duration::from_millis(500)).await;
            store_arc
        } else {
            break;
        }
    }

    // On startup, the store should garbage collect all the temporary states.
    let store = get_store(&db_path);
    assert_eq!(store.iter_temporary_state_roots().count(), 0);
}

#[tokio::test]
async fn weak_subjectivity_sync_easy() {
    let num_initial_slots = E::slots_per_epoch() * 11;
    let checkpoint_slot = Slot::new(E::slots_per_epoch() * 9);
    let slots = (1..num_initial_slots).map(Slot::new).collect();
    weak_subjectivity_sync_test(slots, checkpoint_slot).await
}

#[tokio::test]
async fn weak_subjectivity_sync_unaligned_advanced_checkpoint() {
    let num_initial_slots = E::slots_per_epoch() * 11;
    let checkpoint_slot = Slot::new(E::slots_per_epoch() * 9);
    let slots = (1..num_initial_slots)
        .map(Slot::new)
        .filter(|&slot| {
            // Skip 3 slots leading up to the checkpoint slot.
            slot <= checkpoint_slot - 3 || slot > checkpoint_slot
        })
        .collect();
    weak_subjectivity_sync_test(slots, checkpoint_slot).await
}

#[tokio::test]
async fn weak_subjectivity_sync_unaligned_unadvanced_checkpoint() {
    let num_initial_slots = E::slots_per_epoch() * 11;
    let checkpoint_slot = Slot::new(E::slots_per_epoch() * 9 - 3);
    let slots = (1..num_initial_slots)
        .map(Slot::new)
        .filter(|&slot| {
            // Skip 3 slots after the checkpoint slot.
            slot <= checkpoint_slot || slot > checkpoint_slot + 3
        })
        .collect();
    weak_subjectivity_sync_test(slots, checkpoint_slot).await
}

async fn weak_subjectivity_sync_test(slots: Vec<Slot>, checkpoint_slot: Slot) {
    // Build an initial chain on one harness, representing a synced node with full history.
    let num_final_blocks = E::slots_per_epoch() * 2;

    let temp1 = tempdir().unwrap();
    let full_store = get_store(&temp1);
    let harness = get_harness(full_store.clone(), LOW_VALIDATOR_COUNT);

    let all_validators = (0..LOW_VALIDATOR_COUNT).collect::<Vec<_>>();

    let (genesis_state, genesis_state_root) = harness.get_current_state_and_root();
    harness
        .add_attested_blocks_at_slots(
            genesis_state.clone(),
            genesis_state_root,
            &slots,
            &all_validators,
        )
        .await;

    let wss_block_root = harness
        .chain
        .block_root_at_slot(checkpoint_slot, WhenSlotSkipped::Prev)
        .unwrap()
        .unwrap();
    let wss_state_root = harness
        .chain
        .state_root_at_slot(checkpoint_slot)
        .unwrap()
        .unwrap();

    let wss_block = harness
        .chain
        .store
        .get_full_block(&wss_block_root)
        .unwrap()
        .unwrap();
    let wss_state = full_store
        .get_state(&wss_state_root, Some(checkpoint_slot))
        .unwrap()
        .unwrap();

    // Add more blocks that advance finalization further.
    harness.advance_slot();
    harness
        .extend_chain(
            num_final_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let (shutdown_tx, _shutdown_rx) = futures::channel::mpsc::channel(1);
    let log = test_logger();
    let temp2 = tempdir().unwrap();
    let store = get_store(&temp2);
    let spec = test_spec::<E>();
    let seconds_per_slot = spec.seconds_per_slot;

    // Initialise a new beacon chain from the finalized checkpoint.
    // The slot clock must be set to a time ahead of the checkpoint state.
    let slot_clock = TestingSlotClock::new(
        Slot::new(0),
        Duration::from_secs(harness.chain.genesis_time),
        Duration::from_secs(seconds_per_slot),
    );
    slot_clock.set_slot(harness.get_current_slot().as_u64());

    let beacon_chain = Arc::new(
        BeaconChainBuilder::new(MinimalEthSpec)
            .store(store.clone())
            .custom_spec(test_spec::<E>())
            .task_executor(harness.chain.task_executor.clone())
            .logger(log.clone())
            .weak_subjectivity_state(wss_state, wss_block.clone(), genesis_state)
            .unwrap()
            .store_migrator_config(MigratorConfig::default().blocking())
            .dummy_eth1_backend()
            .expect("should build dummy backend")
            .slot_clock(slot_clock)
            .shutdown_sender(shutdown_tx)
            .chain_config(ChainConfig::default())
            .event_handler(Some(ServerSentEventHandler::new_with_capacity(
                log.clone(),
                1,
            )))
            .build()
            .expect("should build"),
    );

    // Apply blocks forward to reach head.
    let chain_dump = harness.chain.chain_dump().unwrap();
    let new_blocks = chain_dump
        .iter()
        .filter(|snapshot| snapshot.beacon_block.slot() > checkpoint_slot);

    for snapshot in new_blocks {
        let full_block = harness
            .chain
            .get_block(&snapshot.beacon_block_root)
            .await
            .unwrap()
            .unwrap();
        let slot = full_block.slot();
        let state_root = full_block.state_root();

        beacon_chain.slot_clock.set_slot(slot.as_u64());
        beacon_chain
            .process_block(
                full_block.canonical_root(),
                Arc::new(full_block),
                NotifyExecutionLayer::Yes,
                || Ok(()),
            )
            .await
            .unwrap();
        beacon_chain.recompute_head_at_current_slot().await;

        // Check that the new block's state can be loaded correctly.
        let mut state = beacon_chain
            .store
            .get_state(&state_root, Some(slot))
            .unwrap()
            .unwrap();
        assert_eq!(state.update_tree_hash_cache().unwrap(), state_root);
    }

    // Forwards iterator from 0 should fail as we lack blocks.
    assert!(matches!(
        beacon_chain.forwards_iter_block_roots(Slot::new(0)),
        Err(BeaconChainError::HistoricalBlockError(
            HistoricalBlockError::BlockOutOfRange { .. }
        ))
    ));

    // Simulate processing of a `StatusMessage` with an older finalized epoch by calling
    // `block_root_at_slot` with an old slot for which we don't know the block root. It should
    // return `None` rather than erroring.
    assert_eq!(
        beacon_chain
            .block_root_at_slot(Slot::new(1), WhenSlotSkipped::None)
            .unwrap(),
        None
    );

    // Simulate querying the API for a historic state that is unknown. It should also return
    // `None` rather than erroring.
    assert_eq!(beacon_chain.state_root_at_slot(Slot::new(1)).unwrap(), None);

    // Supply blocks backwards to reach genesis. Omit the genesis block to check genesis handling.
    let historical_blocks = chain_dump[..wss_block.slot().as_usize()]
        .iter()
        .filter(|s| s.beacon_block.slot() != 0)
        .map(|s| s.beacon_block.clone())
        .collect::<Vec<_>>();
    beacon_chain
        .import_historical_block_batch(historical_blocks.clone())
        .unwrap();
    assert_eq!(beacon_chain.store.get_oldest_block_slot(), 0);

    // Resupplying the blocks should not fail, they can be safely ignored.
    beacon_chain
        .import_historical_block_batch(historical_blocks)
        .unwrap();

    // The forwards iterator should now match the original chain
    let forwards = beacon_chain
        .forwards_iter_block_roots(Slot::new(0))
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    let expected = harness
        .chain
        .forwards_iter_block_roots(Slot::new(0))
        .unwrap()
        .map(Result::unwrap)
        .collect::<Vec<_>>();
    assert_eq!(forwards, expected);

    // All blocks can be loaded.
    let mut prev_block_root = Hash256::zero();
    for (block_root, slot) in beacon_chain
        .forwards_iter_block_roots(Slot::new(0))
        .unwrap()
        .map(Result::unwrap)
    {
        let block = store.get_blinded_block(&block_root).unwrap().unwrap();
        if block_root != prev_block_root {
            assert_eq!(block.slot(), slot);
        }
        prev_block_root = block_root;
    }

    // All states from the oldest state slot can be loaded.
    let (_, oldest_state_slot) = store.get_historic_state_limits();
    for (state_root, slot) in beacon_chain
        .forwards_iter_state_roots(oldest_state_slot)
        .unwrap()
        .map(Result::unwrap)
    {
        let state = store.get_state(&state_root, Some(slot)).unwrap().unwrap();
        assert_eq!(state.slot(), slot);
        assert_eq!(state.canonical_root(), state_root);
    }

    // Anchor slot is still set to the slot of the checkpoint block.
    assert_eq!(store.get_anchor_slot(), Some(wss_block.slot()));

    // Reconstruct states.
    store.clone().reconstruct_historic_states().unwrap();
    assert_eq!(store.get_anchor_slot(), None);
}

/// Test that blocks and attestations that refer to states around an unaligned split state are
/// processed correctly.
#[tokio::test]
async fn process_blocks_and_attestations_for_unaligned_checkpoint() {
    let temp = tempdir().unwrap();
    let store = get_store(&temp);
    let chain_config = ChainConfig {
        reconstruct_historic_states: false,
        ..ChainConfig::default()
    };
    let harness = get_harness_generic(store.clone(), LOW_VALIDATOR_COUNT, chain_config);

    let all_validators = (0..LOW_VALIDATOR_COUNT).collect::<Vec<_>>();

    let split_slot = Slot::new(E::slots_per_epoch() * 4);
    let pre_skips = 1;
    let post_skips = 1;

    // Build the chain up to the intended split slot, with 3 skips before the split.
    let slots = (1..=split_slot.as_u64() - pre_skips)
        .map(Slot::new)
        .collect::<Vec<_>>();

    let (genesis_state, genesis_state_root) = harness.get_current_state_and_root();
    harness
        .add_attested_blocks_at_slots(
            genesis_state.clone(),
            genesis_state_root,
            &slots,
            &all_validators,
        )
        .await;

    // Before the split slot becomes finalized, create two forking blocks that build on the split
    // block:
    //
    // - one that is invalid because it conflicts with finalization (slot <= finalized_slot)
    // - one that is valid because its slot is not finalized (slot > finalized_slot)
    let (unadvanced_split_state, unadvanced_split_state_root) =
        harness.get_current_state_and_root();

    let (invalid_fork_block, _) = harness
        .make_block(unadvanced_split_state.clone(), split_slot)
        .await;
    let (valid_fork_block, _) = harness
        .make_block(unadvanced_split_state.clone(), split_slot + 1)
        .await;

    // Advance the chain so that the intended split slot is finalized.
    // Do not attest in the epoch boundary slot, to make attestation production later easier (no
    // equivocations).
    let finalizing_slot = split_slot + 2 * E::slots_per_epoch();
    for _ in 0..pre_skips + post_skips {
        harness.advance_slot();
    }
    harness.extend_to_slot(finalizing_slot - 1).await;
    harness
        .add_block_at_slot(finalizing_slot, harness.get_current_state())
        .await
        .unwrap();

    // Check that the split slot is as intended.
    let split = store.get_split_info();
    assert_eq!(split.slot, split_slot);
    assert_eq!(split.block_root, valid_fork_block.parent_root());
    assert_ne!(split.state_root, unadvanced_split_state_root);

    // Applying the invalid block should fail.
    let err = harness
        .chain
        .process_block(
            invalid_fork_block.canonical_root(),
            Arc::new(invalid_fork_block.clone()),
            NotifyExecutionLayer::Yes,
            || Ok(()),
        )
        .await
        .unwrap_err();
    assert!(matches!(err, BlockError::WouldRevertFinalizedSlot { .. }));

    // Applying the valid block should succeed, but it should not become head.
    harness
        .chain
        .process_block(
            valid_fork_block.canonical_root(),
            Arc::new(valid_fork_block.clone()),
            NotifyExecutionLayer::Yes,
            || Ok(()),
        )
        .await
        .unwrap();
    harness.chain.recompute_head_at_current_slot().await;
    assert_ne!(harness.head_block_root(), valid_fork_block.canonical_root());

    // Attestations to the split block in the next 2 epochs should be processed successfully.
    let attestation_start_slot = harness.get_current_slot();
    let attestation_end_slot = attestation_start_slot + 2 * E::slots_per_epoch();
    let (split_state_root, mut advanced_split_state) = harness
        .chain
        .store
        .get_advanced_hot_state(split.block_root, split.slot, split.state_root)
        .unwrap()
        .unwrap();
    complete_state_advance(
        &mut advanced_split_state,
        Some(split_state_root),
        attestation_start_slot,
        &harness.chain.spec,
    )
    .unwrap();
    advanced_split_state
        .build_caches(&harness.chain.spec)
        .unwrap();
    let advanced_split_state_root = advanced_split_state.update_tree_hash_cache().unwrap();
    for slot in (attestation_start_slot.as_u64()..attestation_end_slot.as_u64()).map(Slot::new) {
        let attestations = harness.make_attestations(
            &all_validators,
            &advanced_split_state,
            advanced_split_state_root,
            split.block_root.into(),
            slot,
        );
        harness.advance_slot();
        harness.process_attestations(attestations);
    }
}

#[tokio::test]
async fn finalizes_after_resuming_from_db() {
    let validator_count = 16;
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 8;
    let first_half = num_blocks_produced / 2;

    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);

    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_disk_store(store.clone())
        .mock_execution_layer()
        .build();

    harness.advance_slot();

    harness
        .extend_chain(
            first_half as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    assert!(
        harness
            .chain
            .head_snapshot()
            .beacon_state
            .finalized_checkpoint()
            .epoch
            > 0,
        "the chain should have already finalized"
    );

    let latest_slot = harness.chain.slot().expect("should have a slot");

    harness
        .chain
        .persist_head_and_fork_choice()
        .expect("should persist the head and fork choice");
    harness
        .chain
        .persist_op_pool()
        .expect("should persist the op pool");
    harness
        .chain
        .persist_eth1_cache()
        .expect("should persist the eth1 cache");

    let original_chain = harness.chain;

    let resumed_harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .resumed_disk_store(store)
        .testing_slot_clock(original_chain.slot_clock.clone())
        .mock_execution_layer()
        .build();

    assert_chains_pretty_much_the_same(&original_chain, &resumed_harness.chain);

    // Set the slot clock of the resumed harness to be in the slot following the previous harness.
    //
    // This allows us to produce the block at the next slot.
    resumed_harness
        .chain
        .slot_clock
        .set_slot(latest_slot.as_u64() + 1);

    resumed_harness
        .extend_chain(
            (num_blocks_produced - first_half) as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let state = &resumed_harness.chain.head_snapshot().beacon_state;
    assert_eq!(
        state.slot(),
        num_blocks_produced,
        "head should be at the current slot"
    );
    assert_eq!(
        state.current_epoch(),
        num_blocks_produced / MinimalEthSpec::slots_per_epoch(),
        "head should be at the expected epoch"
    );
    assert_eq!(
        state.current_justified_checkpoint().epoch,
        state.current_epoch() - 1,
        "the head should be justified one behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        state.current_epoch() - 2,
        "the head should be finalized two behind the current epoch"
    );
}

#[tokio::test]
async fn revert_minority_fork_on_resume() {
    let validator_count = 16;
    let slots_per_epoch = MinimalEthSpec::slots_per_epoch();

    let fork_epoch = Epoch::new(4);
    let fork_slot = fork_epoch.start_slot(slots_per_epoch);
    let initial_blocks = slots_per_epoch * fork_epoch.as_u64() - 1;
    let post_fork_blocks = slots_per_epoch * 3;

    let mut spec1 = MinimalEthSpec::default_spec();
    spec1.altair_fork_epoch = None;
    let mut spec2 = MinimalEthSpec::default_spec();
    spec2.altair_fork_epoch = Some(fork_epoch);

    let seconds_per_slot = spec1.seconds_per_slot;

    let all_validators = (0..validator_count).collect::<Vec<usize>>();

    // Chain with no fork epoch configured.
    let db_path1 = tempdir().unwrap();
    let store1 = get_store_with_spec(&db_path1, spec1.clone());
    let harness1 = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec1)
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_disk_store(store1)
        .mock_execution_layer()
        .build();

    // Chain with fork epoch configured.
    let db_path2 = tempdir().unwrap();
    let store2 = get_store_with_spec(&db_path2, spec2.clone());
    let harness2 = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec2.clone())
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_disk_store(store2)
        .mock_execution_layer()
        .build();

    // Apply the same blocks to both chains initially.
    let mut state = harness1.get_current_state();
    let mut block_root = harness1.chain.genesis_block_root;
    for slot in (1..=initial_blocks).map(Slot::new) {
        let state_root = state.update_tree_hash_cache().unwrap();

        let attestations = harness1.make_attestations(
            &all_validators,
            &state,
            state_root,
            block_root.into(),
            slot,
        );
        harness1.set_current_slot(slot);
        harness2.set_current_slot(slot);
        harness1.process_attestations(attestations.clone());
        harness2.process_attestations(attestations);

        let (block, new_state) = harness1.make_block(state, slot).await;

        harness1
            .process_block(slot, block.canonical_root(), block.clone())
            .await
            .unwrap();
        harness2
            .process_block(slot, block.canonical_root(), block.clone())
            .await
            .unwrap();

        state = new_state;
        block_root = block.canonical_root();
    }

    assert_eq!(harness1.head_slot(), fork_slot - 1);
    assert_eq!(harness2.head_slot(), fork_slot - 1);

    // Fork the two chains.
    let mut state1 = state.clone();
    let mut state2 = state.clone();

    let mut majority_blocks = vec![];

    for i in 0..post_fork_blocks {
        let slot = fork_slot + i;

        // Attestations on majority chain.
        let state_root = state.update_tree_hash_cache().unwrap();

        let attestations = harness2.make_attestations(
            &all_validators,
            &state2,
            state_root,
            block_root.into(),
            slot,
        );
        harness2.set_current_slot(slot);
        harness2.process_attestations(attestations);

        // Minority chain block (no attesters).
        let (block1, new_state1) = harness1.make_block(state1, slot).await;
        harness1
            .process_block(slot, block1.canonical_root(), block1)
            .await
            .unwrap();
        state1 = new_state1;

        // Majority chain block (all attesters).
        let (block2, new_state2) = harness2.make_block(state2, slot).await;
        harness2
            .process_block(slot, block2.canonical_root(), block2.clone())
            .await
            .unwrap();

        state2 = new_state2;
        block_root = block2.canonical_root();

        majority_blocks.push(block2);
    }

    let end_slot = fork_slot + post_fork_blocks - 1;
    assert_eq!(harness1.head_slot(), end_slot);
    assert_eq!(harness2.head_slot(), end_slot);

    // Resume from disk with the hard-fork activated: this should revert the post-fork blocks.
    // We have to do some hackery with the `slot_clock` so that the correct slot is set when
    // the beacon chain builder loads the head block.
    drop(harness1);
    let resume_store = get_store_with_spec(&db_path1, spec2.clone());

    let resumed_harness = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec2)
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .resumed_disk_store(resume_store)
        .override_store_mutator(Box::new(move |mut builder| {
            builder = builder
                .resume_from_db()
                .unwrap()
                .testing_slot_clock(Duration::from_secs(seconds_per_slot))
                .unwrap();
            builder
                .get_slot_clock()
                .unwrap()
                .set_slot(end_slot.as_u64());
            builder
        }))
        .mock_execution_layer()
        .build();

    // Head should now be just before the fork.
    resumed_harness.chain.recompute_head_at_current_slot().await;
    assert_eq!(resumed_harness.head_slot(), fork_slot - 1);

    // Head track should know the canonical head and the rogue head.
    assert_eq!(resumed_harness.chain.heads().len(), 2);
    assert!(resumed_harness
        .chain
        .knows_head(&resumed_harness.head_block_root().into()));

    // Apply blocks from the majority chain and trigger finalization.
    let initial_split_slot = resumed_harness.chain.store.get_split_slot();
    for block in &majority_blocks {
        resumed_harness
            .process_block_result(block.clone())
            .await
            .unwrap();

        // The canonical head should be the block from the majority chain.
        resumed_harness.chain.recompute_head_at_current_slot().await;
        assert_eq!(resumed_harness.head_slot(), block.slot());
        assert_eq!(resumed_harness.head_block_root(), block.canonical_root());
    }
    let advanced_split_slot = resumed_harness.chain.store.get_split_slot();

    // Check that the migration ran successfully.
    assert!(advanced_split_slot > initial_split_slot);

    // Check that there is only a single head now matching harness2 (the minority chain is gone).
    let heads = resumed_harness.chain.heads();
    assert_eq!(heads, harness2.chain.heads());
    assert_eq!(heads.len(), 1);
}

// This test checks whether the schema downgrade from the latest version to some minimum supported
// version is correct. This is the easiest schema test to write without historic versions of
// Lighthouse on-hand, but has the disadvantage that the min version needs to be adjusted manually
// as old downgrades are deprecated.
#[tokio::test]
async fn schema_downgrade_to_min_version() {
    let num_blocks_produced = E::slots_per_epoch() * 4;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);
    let spec = &harness.chain.spec.clone();

    harness
        .extend_chain(
            num_blocks_produced as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        )
        .await;

    let min_version = if harness.spec.capella_fork_epoch.is_some() {
        // Can't downgrade beyond V14 once Capella is reached, for simplicity don't test that
        // at all if Capella is enabled.
        SchemaVersion(14)
    } else {
        SchemaVersion(11)
    };

    // Save the slot clock so that the new harness doesn't revert in time.
    let slot_clock = harness.chain.slot_clock.clone();

    // Close the database to ensure everything is written to disk.
    drop(store);
    drop(harness);

    // Re-open the store.
    let store = get_store(&db_path);

    // Downgrade.
    let deposit_contract_deploy_block = 0;
    migrate_schema::<DiskHarnessType<E>>(
        store.clone(),
        deposit_contract_deploy_block,
        CURRENT_SCHEMA_VERSION,
        min_version,
        store.logger().clone(),
        spec,
    )
    .expect("schema downgrade to minimum version should work");

    // Upgrade back.
    migrate_schema::<DiskHarnessType<E>>(
        store.clone(),
        deposit_contract_deploy_block,
        min_version,
        CURRENT_SCHEMA_VERSION,
        store.logger().clone(),
        spec,
    )
    .expect("schema upgrade from minimum version should work");

    // Recreate the harness.
    /*
    let slot_clock = TestingSlotClock::new(
        Slot::new(0),
        Duration::from_secs(harness.chain.genesis_time),
        Duration::from_secs(spec.seconds_per_slot),
    );
    slot_clock.set_slot(harness.get_current_slot().as_u64());
    */

    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..LOW_VALIDATOR_COUNT].to_vec())
        .logger(store.logger().clone())
        .testing_slot_clock(slot_clock)
        .resumed_disk_store(store.clone())
        .mock_execution_layer()
        .build();

    check_finalization(&harness, num_blocks_produced);
    check_split_slot(&harness, store.clone());
    check_chain_dump(&harness, num_blocks_produced + 1);
    check_iterators(&harness);

    // Check that downgrading beyond the minimum version fails (bound is *tight*).
    let min_version_sub_1 = SchemaVersion(min_version.as_u64().checked_sub(1).unwrap());
    migrate_schema::<DiskHarnessType<E>>(
        store.clone(),
        deposit_contract_deploy_block,
        CURRENT_SCHEMA_VERSION,
        min_version_sub_1,
        harness.logger().clone(),
        spec,
    )
    .expect_err("should not downgrade below minimum version");
}

/// Checks that two chains are the same, for the purpose of these tests.
///
/// Several fields that are hard/impossible to check are ignored (e.g., the store).
fn assert_chains_pretty_much_the_same<T: BeaconChainTypes>(a: &BeaconChain<T>, b: &BeaconChain<T>) {
    assert_eq!(a.spec, b.spec, "spec should be equal");
    assert_eq!(a.op_pool, b.op_pool, "op_pool should be equal");
    let a_head = a.head_snapshot();
    let b_head = b.head_snapshot();
    assert_eq!(
        a_head.beacon_block_root, b_head.beacon_block_root,
        "head block roots should be equal"
    );
    assert_eq!(
        a_head.beacon_block, b_head.beacon_block,
        "head blocks should be equal"
    );
    // Clone with committee caches only to prevent other caches from messing with the equality
    // check.
    assert_eq!(
        a_head.beacon_state.clone_with_only_committee_caches(),
        b_head.beacon_state.clone_with_only_committee_caches(),
        "head states should be equal"
    );
    assert_eq!(a.heads(), b.heads(), "heads() should be equal");
    assert_eq!(
        a.genesis_block_root, b.genesis_block_root,
        "genesis_block_root should be equal"
    );

    let slot = a.slot().unwrap();
    let spec = T::EthSpec::default_spec();
    assert!(
        a.canonical_head
            .fork_choice_write_lock()
            .get_head(slot, &spec)
            .unwrap()
            == b.canonical_head
                .fork_choice_write_lock()
                .get_head(slot, &spec)
                .unwrap(),
        "fork_choice heads should be equal"
    );
}

/// Check that the head state's slot matches `expected_slot`.
fn check_slot(harness: &TestHarness, expected_slot: u64) {
    let state = &harness.chain.head_snapshot().beacon_state;

    assert_eq!(
        state.slot(),
        expected_slot,
        "head should be at the current slot"
    );
}

/// Check that the chain has finalized under best-case assumptions, and check the head slot.
fn check_finalization(harness: &TestHarness, expected_slot: u64) {
    let state = &harness.chain.head_snapshot().beacon_state;

    check_slot(harness, expected_slot);

    assert_eq!(
        state.current_justified_checkpoint().epoch,
        state.current_epoch() - 1,
        "the head should be justified one behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint().epoch,
        state.current_epoch() - 2,
        "the head should be finalized two behind the current epoch"
    );
}

/// Check that the HotColdDB's split_slot is equal to the start slot of the last finalized epoch.
fn check_split_slot(harness: &TestHarness, store: Arc<HotColdDB<E, LevelDB<E>, LevelDB<E>>>) {
    let split_slot = store.get_split_slot();
    assert_eq!(
        harness
            .chain
            .head_snapshot()
            .beacon_state
            .finalized_checkpoint()
            .epoch
            .start_slot(E::slots_per_epoch()),
        split_slot
    );
    assert_ne!(split_slot, 0);
}

/// Check that all the states in a chain dump have the correct tree hash.
fn check_chain_dump(harness: &TestHarness, expected_len: u64) {
    let chain_dump = harness.chain.chain_dump().unwrap();
    let split_slot = harness.chain.store.get_split_slot();

    assert_eq!(chain_dump.len() as u64, expected_len);

    for checkpoint in &chain_dump {
        // Check that the tree hash of the stored state is as expected
        assert_eq!(
            checkpoint.beacon_state_root(),
            checkpoint.beacon_state.tree_hash_root(),
            "tree hash of stored state is incorrect"
        );

        // Check that looking up the state root with no slot hint succeeds.
        // This tests the state root -> slot mapping.
        assert_eq!(
            harness
                .chain
                .store
                .get_state(&checkpoint.beacon_state_root(), None)
                .expect("no error")
                .expect("state exists")
                .slot(),
            checkpoint.beacon_state.slot()
        );

        // Check presence of execution payload on disk.
        if harness.chain.spec.bellatrix_fork_epoch.is_some() {
            assert_eq!(
                harness
                    .chain
                    .store
                    .execution_payload_exists(&checkpoint.beacon_block_root)
                    .unwrap(),
                checkpoint.beacon_block.slot() >= split_slot,
                "incorrect payload storage for block at slot {}: {:?}",
                checkpoint.beacon_block.slot(),
                checkpoint.beacon_block_root,
            );
        }
    }

    // Check the forwards block roots iterator against the chain dump
    let chain_dump_block_roots = chain_dump
        .iter()
        .map(|checkpoint| (checkpoint.beacon_block_root, checkpoint.beacon_block.slot()))
        .collect::<Vec<_>>();

    let mut forward_block_roots = harness
        .chain
        .forwards_iter_block_roots(Slot::new(0))
        .expect("should get iter")
        .map(Result::unwrap)
        .collect::<Vec<_>>();

    // Drop the block roots for skipped slots.
    forward_block_roots.dedup_by_key(|(block_root, _)| *block_root);

    for i in 0..std::cmp::max(chain_dump_block_roots.len(), forward_block_roots.len()) {
        assert_eq!(
            chain_dump_block_roots[i],
            forward_block_roots[i],
            "split slot is {}",
            harness.chain.store.get_split_slot()
        );
    }
}

/// Check that every state from the canonical chain is in the database, and that the
/// reverse state and block root iterators reach genesis.
fn check_iterators(harness: &TestHarness) {
    let mut max_slot = None;
    for (state_root, slot) in harness
        .chain
        .forwards_iter_state_roots(Slot::new(0))
        .expect("should get iter")
        .map(Result::unwrap)
    {
        assert!(
            harness
                .chain
                .store
                .get_state(&state_root, Some(slot))
                .unwrap()
                .is_some(),
            "state {:?} from canonical chain should be in DB",
            state_root
        );
        max_slot = Some(slot);
    }
    // Assert that we reached the head.
    assert_eq!(max_slot, Some(harness.head_slot()));
    // Assert that the block root iterator reaches the head.
    assert_eq!(
        harness
            .chain
            .forwards_iter_block_roots(Slot::new(0))
            .expect("should get iter")
            .last()
            .map(Result::unwrap)
            .map(|(_, slot)| slot),
        Some(harness.head_slot())
    );
}

fn get_finalized_epoch_boundary_blocks(
    dump: &[BeaconSnapshot<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>],
) -> HashSet<SignedBeaconBlockHash> {
    dump.iter()
        .cloned()
        .map(|checkpoint| checkpoint.beacon_state.finalized_checkpoint().root.into())
        .collect()
}

fn get_blocks(
    dump: &[BeaconSnapshot<MinimalEthSpec, BlindedPayload<MinimalEthSpec>>],
) -> HashSet<SignedBeaconBlockHash> {
    dump.iter()
        .cloned()
        .map(|checkpoint| checkpoint.beacon_block_root.into())
        .collect()
}
