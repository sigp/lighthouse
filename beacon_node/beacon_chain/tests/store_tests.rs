#![cfg(not(debug_assertions))]

#[macro_use]
extern crate lazy_static;

use beacon_chain::test_utils::{
    AttestationStrategy, BeaconChainHarness, BlockStrategy, DiskHarnessType,
};
use rand::Rng;
use sloggers::{null::NullLoggerBuilder, Build};
use std::sync::Arc;
use store::{DiskStore, Store};
use tempfile::{tempdir, TempDir};
use tree_hash::TreeHash;
use types::test_utils::{SeedableRng, XorShiftRng};
use types::*;

// Should ideally be divisible by 3.
pub const VALIDATOR_COUNT: usize = 24;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
}

type E = MinimalEthSpec;
type TestHarness = BeaconChainHarness<DiskHarnessType<E>>;

fn get_store(db_path: &TempDir) -> Arc<DiskStore<E>> {
    let spec = MinimalEthSpec::default_spec();
    let hot_path = db_path.path().join("hot_db");
    let cold_path = db_path.path().join("cold_db");
    let slots_per_restore_point = MinimalEthSpec::slots_per_historical_root() as u64;
    let log = NullLoggerBuilder.build().expect("logger should build");
    Arc::new(
        DiskStore::open(&hot_path, &cold_path, slots_per_restore_point, spec, log)
            .expect("disk store should initialize"),
    )
}

fn get_harness(store: Arc<DiskStore<E>>, validator_count: usize) -> TestHarness {
    let harness = BeaconChainHarness::new_with_disk_store(
        MinimalEthSpec,
        store,
        KEYPAIRS[0..validator_count].to_vec(),
    );
    harness.advance_slot();
    harness
}

#[test]
fn full_participation_no_skips() {
    let num_blocks_produced = E::slots_per_epoch() * 5;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), VALIDATOR_COUNT);

    harness.extend_chain(
        num_blocks_produced as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    check_finalization(&harness, num_blocks_produced);
    check_split_slot(&harness, store);
    check_chain_dump(&harness, num_blocks_produced + 1);
    check_iterators(&harness);
}

#[test]
fn randomised_skips() {
    let num_slots = E::slots_per_epoch() * 5;
    let mut num_blocks_produced = 0;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), VALIDATOR_COUNT);
    let rng = &mut XorShiftRng::from_seed([42; 16]);

    let mut head_slot = 0;

    for slot in 1..=num_slots {
        if rng.gen_bool(0.8) {
            harness.extend_chain(
                1,
                BlockStrategy::ForkCanonicalChainAt {
                    previous_slot: Slot::new(head_slot),
                    first_slot: Slot::new(slot),
                },
                AttestationStrategy::AllValidators,
            );
            harness.advance_slot();
            num_blocks_produced += 1;
            head_slot = slot;
        } else {
            harness.advance_slot();
        }
    }

    let state = &harness.chain.head().expect("should get head").beacon_state;

    assert_eq!(state.slot, num_slots, "head should be at the current slot");

    check_split_slot(&harness, store);
    check_chain_dump(&harness, num_blocks_produced + 1);
    check_iterators(&harness);
}

#[test]
fn long_skip() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), VALIDATOR_COUNT);

    // Number of blocks to create in the first run, intentionally not falling on an epoch
    // boundary in order to check that the DB hot -> cold migration is capable of reaching
    // back across the skip distance, and correctly migrating those extra non-finalized states.
    let initial_blocks = E::slots_per_epoch() * 5 + E::slots_per_epoch() / 2;
    let skip_slots = E::slots_per_historical_root() as u64 * 8;
    let final_blocks = E::slots_per_epoch() * 4;

    harness.extend_chain(
        initial_blocks as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    check_finalization(&harness, initial_blocks);

    // 2. Skip slots
    for _ in 0..skip_slots {
        harness.advance_slot();
    }

    // 3. Produce more blocks, establish a new finalized epoch
    harness.extend_chain(
        final_blocks as usize,
        BlockStrategy::ForkCanonicalChainAt {
            previous_slot: Slot::new(initial_blocks),
            first_slot: Slot::new(initial_blocks + skip_slots as u64 + 1),
        },
        AttestationStrategy::AllValidators,
    );

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
#[test]
fn randao_genesis_storage() {
    let validator_count = 8;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), validator_count);

    let num_slots = E::slots_per_epoch() * (E::epochs_per_historical_vector() - 1) as u64;

    // Check we have a non-trivial genesis value
    let genesis_value = *harness
        .chain
        .head()
        .expect("should get head")
        .beacon_state
        .get_randao_mix(Epoch::new(0))
        .expect("randao mix ok");
    assert!(!genesis_value.is_zero());

    harness.extend_chain(
        num_slots as usize - 1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    // Check that genesis value is still present
    assert!(harness
        .chain
        .head()
        .expect("should get head")
        .beacon_state
        .randao_mixes
        .iter()
        .find(|x| **x == genesis_value)
        .is_some());

    // Then upon adding one more block, it isn't
    harness.advance_slot();
    harness.extend_chain(
        1,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );
    assert!(harness
        .chain
        .head()
        .expect("should get head")
        .beacon_state
        .randao_mixes
        .iter()
        .find(|x| **x == genesis_value)
        .is_none());

    check_finalization(&harness, num_slots);
    check_split_slot(&harness, store);
    check_chain_dump(&harness, num_slots + 1);
    check_iterators(&harness);
}

// Check that closing and reopening a freezer DB restores the split slot to its correct value.
#[test]
fn split_slot_restore() {
    let db_path = tempdir().unwrap();

    let split_slot = {
        let store = get_store(&db_path);
        let harness = get_harness(store.clone(), VALIDATOR_COUNT);

        let num_blocks = 4 * E::slots_per_epoch();

        harness.extend_chain(
            num_blocks as usize,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::AllValidators,
        );

        store.get_split_slot()
    };
    assert_ne!(split_slot, Slot::new(0));

    // Re-open the store
    let store = get_store(&db_path);

    assert_eq!(store.get_split_slot(), split_slot);
}

/// Check that the head state's slot matches `expected_slot`.
fn check_slot(harness: &TestHarness, expected_slot: u64) {
    let state = &harness.chain.head().expect("should get head").beacon_state;

    assert_eq!(
        state.slot, expected_slot,
        "head should be at the current slot"
    );
}

/// Check that the chain has finalized under best-case assumptions, and check the head slot.
fn check_finalization(harness: &TestHarness, expected_slot: u64) {
    let state = &harness.chain.head().expect("should get head").beacon_state;

    check_slot(harness, expected_slot);

    assert_eq!(
        state.current_justified_checkpoint.epoch,
        state.current_epoch() - 1,
        "the head should be justified one behind the current epoch"
    );
    assert_eq!(
        state.finalized_checkpoint.epoch,
        state.current_epoch() - 2,
        "the head should be finalized two behind the current epoch"
    );
}

/// Check that the DiskStore's split_slot is equal to the start slot of the last finalized epoch.
fn check_split_slot(harness: &TestHarness, store: Arc<DiskStore<E>>) {
    let split_slot = store.get_split_slot();
    assert_eq!(
        harness
            .chain
            .head()
            .expect("should get head")
            .beacon_state
            .finalized_checkpoint
            .epoch
            .start_slot(E::slots_per_epoch()),
        split_slot
    );
    assert_ne!(split_slot, 0);
}

/// Check that all the states in a chain dump have the correct tree hash.
fn check_chain_dump(harness: &TestHarness, expected_len: u64) {
    let chain_dump = harness.chain.chain_dump().unwrap();

    assert_eq!(chain_dump.len() as u64, expected_len);

    for checkpoint in &chain_dump {
        // Check that the tree hash of the stored state is as expected
        assert_eq!(
            checkpoint.beacon_state_root,
            Hash256::from_slice(&checkpoint.beacon_state.tree_hash_root()),
            "tree hash of stored state is incorrect"
        );

        // Check that looking up the state root with no slot hint succeeds.
        // This tests the state root -> slot mapping.
        assert_eq!(
            harness
                .chain
                .store
                .get_state(&checkpoint.beacon_state_root, None)
                .expect("no error")
                .expect("state exists")
                .slot,
            checkpoint.beacon_state.slot
        );
    }

    // Check the forwards block roots iterator against the chain dump
    let chain_dump_block_roots = chain_dump
        .iter()
        .map(|checkpoint| (checkpoint.beacon_block_root, checkpoint.beacon_block.slot))
        .collect::<Vec<_>>();

    let head = harness.chain.head().expect("should get head");
    let mut forward_block_roots = Store::forwards_block_roots_iterator(
        harness.chain.store.clone(),
        Slot::new(0),
        head.beacon_state,
        head.beacon_block_root,
        &harness.spec,
    )
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

/// Check that state and block root iterators can reach genesis
fn check_iterators(harness: &TestHarness) {
    assert_eq!(
        harness
            .chain
            .rev_iter_state_roots()
            .expect("should get iter")
            .last()
            .map(|(_, slot)| slot),
        Some(Slot::new(0))
    );
    assert_eq!(
        harness
            .chain
            .rev_iter_block_roots()
            .expect("should get iter")
            .last()
            .map(|(_, slot)| slot),
        Some(Slot::new(0))
    );
}
