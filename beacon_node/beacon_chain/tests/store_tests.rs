#![cfg(not(debug_assertions))]

use beacon_chain::attestation_verification::Error as AttnError;
use beacon_chain::builder::BeaconChainBuilder;
use beacon_chain::test_utils::{
    test_spec, AttestationStrategy, BeaconChainHarness, BlockStrategy, DiskHarnessType,
    HARNESS_SLOT_TIME,
};
use beacon_chain::{
    historical_blocks::HistoricalBlockError, migrate::MigratorConfig, BeaconChain,
    BeaconChainError, BeaconChainTypes, BeaconSnapshot, ChainConfig, ServerSentEventHandler,
    WhenSlotSkipped,
};
use lazy_static::lazy_static;
use logging::test_logger;
use maplit::hashset;
use rand::Rng;
use std::collections::HashMap;
use std::collections::HashSet;
use std::convert::TryInto;
use std::sync::Arc;
use store::{
    iter::{BlockRootsIterator, StateRootsIterator},
    HotColdDB, LevelDB, StoreConfig,
};
use tempfile::{tempdir, TempDir};
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
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_disk_store(store)
        .build();
    harness.advance_slot();
    harness
}

#[test]
fn full_participation_no_skips() {
    let num_blocks_produced = E::slots_per_epoch() * 5;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

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
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);
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

    assert_eq!(
        state.slot(),
        num_slots,
        "head should be at the current slot"
    );

    check_split_slot(&harness, store);
    check_chain_dump(&harness, num_blocks_produced + 1);
    check_iterators(&harness);
}

#[test]
fn long_skip() {
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
        .randao_mixes()
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
#[test]
fn split_slot_restore() {
    let db_path = tempdir().unwrap();

    let split_slot = {
        let store = get_store(&db_path);
        let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

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

// Check attestation processing and `load_epoch_boundary_state` in the presence of a split DB.
// This is a bit of a monster test in that it tests lots of different things, but until they're
// tested elsewhere, this is as good a place as any.
#[test]
fn epoch_boundary_state_attestation_processing() {
    let num_blocks_produced = E::slots_per_epoch() * 5;
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    let late_validators = vec![0, 1];
    let timely_validators = (2..LOW_VALIDATOR_COUNT).collect::<Vec<_>>();

    let mut late_attestations = vec![];

    for _ in 0..num_blocks_produced {
        harness.extend_chain(
            1,
            BlockStrategy::OnCanonicalHead,
            AttestationStrategy::SomeValidators(timely_validators.clone()),
        );

        let head = harness.chain.head().expect("head ok");
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
        let block = store.get_block(&block_root).unwrap().expect("block exists");
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
        let finalized_epoch = harness
            .chain
            .head_info()
            .expect("should get head")
            .finalized_checkpoint
            .epoch;

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

#[test]
fn delete_blocks_and_states() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let validators_keypairs =
        types::test_utils::generate_deterministic_keypairs(LOW_VALIDATOR_COUNT);
    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(validators_keypairs)
        .fresh_disk_store(store.clone())
        .build();

    let unforked_blocks: u64 = 4 * E::slots_per_epoch();

    // Finalize an initial portion of the chain.
    let initial_slots: Vec<Slot> = (1..=unforked_blocks).map(Into::into).collect();
    let (state, state_root) = harness.get_current_state_and_root();
    let all_validators = harness.get_all_validators();
    harness.add_attested_blocks_at_slots(state, state_root, &initial_slots, &all_validators);

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
    let results = harness.add_blocks_on_multiple_chains(vec![
        (fork1_state, fork1_slots, honest_validators),
        (fork2_state, fork2_slots, faulty_validators),
    ]);

    let honest_head = results[0].2;
    let faulty_head = results[1].2;

    assert_ne!(honest_head, faulty_head, "forks should be distinct");
    let head_info = harness.chain.head_info().expect("should get head");
    assert_eq!(head_info.slot, unforked_blocks + fork_blocks);

    assert_eq!(
        head_info.block_root,
        honest_head.into(),
        "the honest chain should be the canonical chain",
    );

    let faulty_head_block = store
        .get_block(&faulty_head.into())
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
        StateRootsIterator::new(store.clone(), &faulty_head_state).map(Result::unwrap)
    {
        if slot <= unforked_blocks {
            break;
        }
        store.delete_state(&state_root, slot).unwrap();
        assert_eq!(store.get_state(&state_root, Some(slot)).unwrap(), None);
    }

    // Double-deleting should also be OK (deleting non-existent things is fine)
    for (state_root, slot) in
        StateRootsIterator::new(store.clone(), &faulty_head_state).map(Result::unwrap)
    {
        if slot <= unforked_blocks {
            break;
        }
        store.delete_state(&state_root, slot).unwrap();
    }

    // Deleting the blocks from the fork should remove them completely
    for (block_root, slot) in
        BlockRootsIterator::new(store.clone(), &faulty_head_state).map(Result::unwrap)
    {
        if slot <= unforked_blocks + 1 {
            break;
        }
        store.delete_block(&block_root).unwrap();
        assert_eq!(store.get_block(&block_root).unwrap(), None);
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
fn multi_epoch_fork_valid_blocks_test(
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
        .build();

    let num_fork1_blocks: u64 = num_fork1_blocks_.try_into().unwrap();
    let num_fork2_blocks: u64 = num_fork2_blocks_.try_into().unwrap();

    // Create the initial portion of the chain
    if initial_blocks > 0 {
        let initial_slots: Vec<Slot> = (1..=initial_blocks).map(Into::into).collect();
        let (state, state_root) = harness.get_current_state_and_root();
        let all_validators = harness.get_all_validators();
        harness.add_attested_blocks_at_slots(state, state_root, &initial_slots, &all_validators);
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

    let results = harness.add_blocks_on_multiple_chains(vec![
        (fork1_state, fork1_slots, fork1_validators),
        (fork2_state, fork2_slots, fork2_validators),
    ]);

    let head1 = results[0].2;
    let head2 = results[1].2;

    (db_path, harness, head1.into(), head2.into())
}

// This is the minimal test of block production with different shufflings.
#[test]
fn block_production_different_shuffling_early() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    multi_epoch_fork_valid_blocks_test(
        slots_per_epoch - 2,
        slots_per_epoch + 3,
        slots_per_epoch + 3,
        LOW_VALIDATOR_COUNT / 2,
    );
}

#[test]
fn block_production_different_shuffling_long() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    multi_epoch_fork_valid_blocks_test(
        2 * slots_per_epoch - 2,
        3 * slots_per_epoch,
        3 * slots_per_epoch,
        LOW_VALIDATOR_COUNT / 2,
    );
}

// Check that the op pool safely includes multiple attestations per block when necessary.
// This checks the correctness of the shuffling compatibility memoization.
#[test]
fn multiple_attestations_per_block() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store, HIGH_VALIDATOR_COUNT);

    harness.extend_chain(
        E::slots_per_epoch() as usize * 3,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let head = harness.chain.head().unwrap();
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
                .deconstruct()
                .0
                .body()
                .attestations()
                .len() as u64,
            if slot <= 1 { 0 } else { committees_per_slot }
        );
    }
}

#[test]
fn shuffling_compatible_linear_chain() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // Skip the block at the end of the first epoch.
    let head_block_root = harness.extend_chain(
        4 * E::slots_per_epoch() as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    check_shuffling_compatible(
        &harness,
        &get_state_for_block(&harness, head_block_root),
        head_block_root,
        true,
        true,
        None,
        None,
    );
}

#[test]
fn shuffling_compatible_missing_pivot_block() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);

    // Skip the block at the end of the first epoch.
    harness.extend_chain(
        E::slots_per_epoch() as usize - 2,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );
    harness.advance_slot();
    harness.advance_slot();
    let head_block_root = harness.extend_chain(
        2 * E::slots_per_epoch() as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    check_shuffling_compatible(
        &harness,
        &get_state_for_block(&harness, head_block_root),
        head_block_root,
        true,
        true,
        Some(E::slots_per_epoch() - 2),
        Some(E::slots_per_epoch() - 2),
    );
}

#[test]
fn shuffling_compatible_simple_fork() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    let (db_path, harness, head1, head2) = multi_epoch_fork_valid_blocks_test(
        2 * slots_per_epoch,
        3 * slots_per_epoch,
        3 * slots_per_epoch,
        LOW_VALIDATOR_COUNT / 2,
    );

    let head1_state = get_state_for_block(&harness, head1);
    let head2_state = get_state_for_block(&harness, head2);

    check_shuffling_compatible(&harness, &head1_state, head1, true, true, None, None);
    check_shuffling_compatible(&harness, &head1_state, head2, false, false, None, None);
    check_shuffling_compatible(&harness, &head2_state, head1, false, false, None, None);
    check_shuffling_compatible(&harness, &head2_state, head2, true, true, None, None);

    drop(db_path);
}

#[test]
fn shuffling_compatible_short_fork() {
    let slots_per_epoch = E::slots_per_epoch() as usize;
    let (db_path, harness, head1, head2) = multi_epoch_fork_valid_blocks_test(
        2 * slots_per_epoch - 2,
        slots_per_epoch + 2,
        slots_per_epoch + 2,
        LOW_VALIDATOR_COUNT / 2,
    );

    let head1_state = get_state_for_block(&harness, head1);
    let head2_state = get_state_for_block(&harness, head2);

    check_shuffling_compatible(&harness, &head1_state, head1, true, true, None, None);
    check_shuffling_compatible(&harness, &head1_state, head2, false, true, None, None);
    // NOTE: don't check this case, as block 14 from the first chain appears valid on the second
    // chain due to it matching the second chain's block 15.
    // check_shuffling_compatible(&harness, &head2_state, head1, false, true, None, None);
    check_shuffling_compatible(
        &harness,
        &head2_state,
        head2,
        true,
        true,
        // Required because of the skipped slot.
        Some(2 * E::slots_per_epoch() - 2),
        None,
    );

    drop(db_path);
}

fn get_state_for_block(harness: &TestHarness, block_root: Hash256) -> BeaconState<E> {
    let head_block = harness.chain.get_block(&block_root).unwrap().unwrap();
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
    current_epoch_valid: bool,
    previous_epoch_valid: bool,
    current_epoch_cutoff_slot: Option<u64>,
    previous_epoch_cutoff_slot: Option<u64>,
) {
    let shuffling_lookahead = harness.chain.spec.min_seed_lookahead.as_u64() + 1;
    let current_pivot_slot =
        (head_state.current_epoch() - shuffling_lookahead).end_slot(E::slots_per_epoch());
    let previous_pivot_slot =
        (head_state.previous_epoch() - shuffling_lookahead).end_slot(E::slots_per_epoch());

    for maybe_tuple in harness
        .chain
        .rev_iter_block_roots_from(head_block_root)
        .unwrap()
    {
        let (block_root, slot) = maybe_tuple.unwrap();
        // Shuffling is compatible targeting the current epoch,
        // if slot is greater than or equal to the current epoch pivot block.
        assert_eq!(
            harness.chain.shuffling_is_compatible(
                &block_root,
                head_state.current_epoch(),
                &head_state
            ),
            current_epoch_valid
                && slot >= current_epoch_cutoff_slot.unwrap_or(current_pivot_slot.as_u64())
        );
        // Similarly for the previous epoch
        assert_eq!(
            harness.chain.shuffling_is_compatible(
                &block_root,
                head_state.previous_epoch(),
                &head_state
            ),
            previous_epoch_valid
                && slot >= previous_epoch_cutoff_slot.unwrap_or(previous_pivot_slot.as_u64())
        );
        // Targeting the next epoch should always return false
        assert_eq!(
            harness.chain.shuffling_is_compatible(
                &block_root,
                head_state.current_epoch() + 1,
                &head_state
            ),
            false
        );
        // Targeting two epochs before the current epoch should also always return false
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
#[test]
fn prunes_abandoned_fork_between_two_finalized_checkpoints() {
    const HONEST_VALIDATOR_COUNT: usize = 16 + 0;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 8 - 0;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let validators_keypairs = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let rig = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(validators_keypairs)
        .fresh_ephemeral_store()
        .build();
    let slots_per_epoch = rig.slots_per_epoch();
    let (mut state, state_root) = rig.get_current_state_and_root();

    let canonical_chain_slots: Vec<Slot> = (1..=rig.epoch_start_slot(1)).map(Slot::new).collect();
    let (canonical_chain_blocks_pre_finalization, _, _, new_state) = rig
        .add_attested_blocks_at_slots(
            state,
            state_root,
            &canonical_chain_slots,
            &honest_validators,
        );
    state = new_state;
    let canonical_chain_slot: u64 = rig.get_current_slot().into();

    let stray_slots: Vec<Slot> = (canonical_chain_slot + 1..rig.epoch_start_slot(2))
        .map(Slot::new)
        .collect();
    let (current_state, current_state_root) = rig.get_current_state_and_root();
    let (stray_blocks, stray_states, stray_head, _) = rig.add_attested_blocks_at_slots(
        current_state,
        current_state_root,
        &stray_slots,
        &adversarial_validators,
    );

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
    let (canonical_chain_blocks_post_finalization, _, _, _) = rig.add_attested_blocks_at_slots(
        state,
        state_root,
        &finalization_slots,
        &honest_validators,
    );

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

#[test]
fn pruning_does_not_touch_abandoned_block_shared_with_canonical_chain() {
    const HONEST_VALIDATOR_COUNT: usize = 16 + 0;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 8 - 0;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let validators_keypairs = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let rig = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(validators_keypairs)
        .fresh_ephemeral_store()
        .build();
    let slots_per_epoch = rig.slots_per_epoch();
    let (state, state_root) = rig.get_current_state_and_root();

    // Fill up 0th epoch
    let canonical_chain_slots_zeroth_epoch: Vec<Slot> =
        (1..rig.epoch_start_slot(1)).map(Slot::new).collect();
    let (_, _, _, mut state) = rig.add_attested_blocks_at_slots(
        state,
        state_root,
        &canonical_chain_slots_zeroth_epoch,
        &honest_validators,
    );

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
        );
    let canonical_chain_slot: u64 = rig.get_current_slot().into();

    let stray_chain_slots_first_epoch: Vec<Slot> = (rig.epoch_start_slot(1) + 2
        ..=rig.epoch_start_slot(1) + 2)
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (stray_blocks, stray_states, stray_head, _) = rig.add_attested_blocks_at_slots(
        state.clone(),
        state_root,
        &stray_chain_slots_first_epoch,
        &adversarial_validators,
    );

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
    let (canonical_chain_blocks, _, _, _) = rig.add_attested_blocks_at_slots(
        state,
        state_root,
        &finalization_slots,
        &honest_validators,
    );

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

#[test]
fn pruning_does_not_touch_blocks_prior_to_finalization() {
    const HONEST_VALIDATOR_COUNT: usize = 16;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 8;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let validators_keypairs = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let rig = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(validators_keypairs)
        .fresh_ephemeral_store()
        .build();
    let slots_per_epoch = rig.slots_per_epoch();
    let (mut state, state_root) = rig.get_current_state_and_root();

    // Fill up 0th epoch with canonical chain blocks
    let zeroth_epoch_slots: Vec<Slot> = (1..=rig.epoch_start_slot(1)).map(Slot::new).collect();
    let (canonical_chain_blocks, _, _, new_state) = rig.add_attested_blocks_at_slots(
        state,
        state_root,
        &zeroth_epoch_slots,
        &honest_validators,
    );
    state = new_state;
    let canonical_chain_slot: u64 = rig.get_current_slot().into();

    // Fill up 1st epoch.  Contains a fork.
    let first_epoch_slots: Vec<Slot> = ((rig.epoch_start_slot(1) + 1)..(rig.epoch_start_slot(2)))
        .map(Slot::new)
        .collect();
    let state_root = state.update_tree_hash_cache().unwrap();
    let (stray_blocks, stray_states, stray_head, _) = rig.add_attested_blocks_at_slots(
        state.clone(),
        state_root,
        &first_epoch_slots,
        &adversarial_validators,
    );

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
    let (_, _, _, _) =
        rig.add_attested_blocks_at_slots(state, state_root, &slots, &honest_validators);

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

#[test]
fn prunes_fork_growing_past_youngest_finalized_checkpoint() {
    const HONEST_VALIDATOR_COUNT: usize = 16 + 0;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 8 - 0;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let validators_keypairs = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let rig = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(validators_keypairs)
        .fresh_ephemeral_store()
        .build();
    let (state, state_root) = rig.get_current_state_and_root();

    // Fill up 0th epoch with canonical chain blocks
    let zeroth_epoch_slots: Vec<Slot> = (1..=rig.epoch_start_slot(1)).map(Slot::new).collect();
    let (canonical_blocks_zeroth_epoch, _, _, mut state) = rig.add_attested_blocks_at_slots(
        state,
        state_root,
        &zeroth_epoch_slots,
        &honest_validators,
    );

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
        );
    let (canonical_blocks_first_epoch, _, _, mut canonical_state) =
        rig.add_attested_blocks_at_slots(state, state_root, &slots_first_epoch, &honest_validators);

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
        );

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
    let (canonical_blocks, _, _, _) = rig.add_attested_blocks_at_slots(
        canonical_state,
        canonical_state_root,
        &canonical_slots,
        &honest_validators,
    );

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
#[test]
fn prunes_skipped_slots_states() {
    const HONEST_VALIDATOR_COUNT: usize = 16 + 0;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 8 - 0;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let validators_keypairs = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let rig = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(validators_keypairs)
        .fresh_ephemeral_store()
        .build();
    let (state, state_root) = rig.get_current_state_and_root();

    let canonical_slots_zeroth_epoch: Vec<Slot> =
        (1..=rig.epoch_start_slot(1)).map(Into::into).collect();
    let (canonical_blocks_zeroth_epoch, _, _, mut canonical_state) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &canonical_slots_zeroth_epoch,
            &honest_validators,
        );

    let skipped_slot: Slot = (rig.epoch_start_slot(1) + 1).into();

    let stray_slots: Vec<Slot> = ((skipped_slot + 1).into()..rig.epoch_start_slot(2))
        .map(Into::into)
        .collect();
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    let (stray_blocks, stray_states, _, stray_state) = rig.add_attested_blocks_at_slots(
        canonical_state.clone(),
        canonical_state_root,
        &stray_slots,
        &adversarial_validators,
    );

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
    let (canonical_blocks_post_finalization, _, _, _) = rig.add_attested_blocks_at_slots(
        canonical_state,
        canonical_state_root,
        &canonical_slots,
        &honest_validators,
    );

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
#[test]
fn finalizes_non_epoch_start_slot() {
    const HONEST_VALIDATOR_COUNT: usize = 16 + 0;
    const ADVERSARIAL_VALIDATOR_COUNT: usize = 8 - 0;
    const VALIDATOR_COUNT: usize = HONEST_VALIDATOR_COUNT + ADVERSARIAL_VALIDATOR_COUNT;
    let validators_keypairs = types::test_utils::generate_deterministic_keypairs(VALIDATOR_COUNT);
    let honest_validators: Vec<usize> = (0..HONEST_VALIDATOR_COUNT).collect();
    let adversarial_validators: Vec<usize> = (HONEST_VALIDATOR_COUNT..VALIDATOR_COUNT).collect();
    let rig = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(validators_keypairs)
        .fresh_ephemeral_store()
        .build();
    let (state, state_root) = rig.get_current_state_and_root();

    let canonical_slots_zeroth_epoch: Vec<Slot> =
        (1..rig.epoch_start_slot(1)).map(Into::into).collect();
    let (canonical_blocks_zeroth_epoch, _, _, mut canonical_state) = rig
        .add_attested_blocks_at_slots(
            state.clone(),
            state_root,
            &canonical_slots_zeroth_epoch,
            &honest_validators,
        );

    let skipped_slot: Slot = rig.epoch_start_slot(1).into();

    let stray_slots: Vec<Slot> = ((skipped_slot + 1).into()..rig.epoch_start_slot(2))
        .map(Into::into)
        .collect();
    let canonical_state_root = canonical_state.update_tree_hash_cache().unwrap();
    let (stray_blocks, stray_states, _, stray_state) = rig.add_attested_blocks_at_slots(
        canonical_state.clone(),
        canonical_state_root,
        &stray_slots,
        &adversarial_validators,
    );

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
    let (canonical_blocks_post_finalization, _, _, _) = rig.add_attested_blocks_at_slots(
        canonical_state,
        canonical_state_root,
        &canonical_slots,
        &honest_validators,
    );

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
        let block = harness.chain.get_block(&block_hash.into()).unwrap();
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
        let block = harness.chain.get_block(&block_hash.into()).unwrap();
        assert!(
            block.is_none(),
            "did not expect block {:?} to be in the DB",
            block_hash
        );
    }
}

#[test]
fn prune_single_block_fork() {
    let slots_per_epoch = E::slots_per_epoch();
    pruning_test(3 * slots_per_epoch, 1, slots_per_epoch, 0, 1);
}

#[test]
fn prune_single_block_long_skip() {
    let slots_per_epoch = E::slots_per_epoch();
    pruning_test(
        2 * slots_per_epoch,
        1,
        2 * slots_per_epoch,
        2 * slots_per_epoch as u64,
        1,
    );
}

#[test]
fn prune_shared_skip_states_mid_epoch() {
    let slots_per_epoch = E::slots_per_epoch();
    pruning_test(
        slots_per_epoch + slots_per_epoch / 2,
        1,
        slots_per_epoch,
        2,
        slots_per_epoch - 1,
    );
}

#[test]
fn prune_shared_skip_states_epoch_boundaries() {
    let slots_per_epoch = E::slots_per_epoch();
    pruning_test(slots_per_epoch - 1, 1, slots_per_epoch, 2, slots_per_epoch);
    pruning_test(slots_per_epoch - 1, 2, slots_per_epoch, 1, slots_per_epoch);
    pruning_test(
        2 * slots_per_epoch + slots_per_epoch / 2,
        slots_per_epoch as u64 / 2,
        slots_per_epoch,
        slots_per_epoch as u64 / 2 + 1,
        slots_per_epoch,
    );
    pruning_test(
        2 * slots_per_epoch + slots_per_epoch / 2,
        slots_per_epoch as u64 / 2,
        slots_per_epoch,
        slots_per_epoch as u64 / 2 + 1,
        slots_per_epoch,
    );
    pruning_test(
        2 * slots_per_epoch - 1,
        slots_per_epoch as u64,
        1,
        0,
        2 * slots_per_epoch,
    );
}

/// Generic harness for pruning tests.
fn pruning_test(
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
    let (_, _, _, divergence_state) = harness.add_attested_blocks_at_slots(
        state,
        state_root,
        &slots(start_slot, num_initial_blocks)[..],
        &honest_validators,
    );

    let mut chains = harness.add_blocks_on_multiple_chains(vec![
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
    ]);
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
    harness.add_attested_blocks_at_slots(
        canonical_state,
        canonical_state_root,
        &slots(canonical_slot, num_finalization_blocks),
        &honest_validators,
    );

    // Check that finalization has advanced past the divergence slot.
    assert!(
        harness
            .chain
            .head_info()
            .unwrap()
            .finalized_checkpoint
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

#[test]
fn garbage_collect_temp_states_from_failed_block() {
    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);
    let harness = get_harness(store.clone(), LOW_VALIDATOR_COUNT);
    let slots_per_epoch = E::slots_per_epoch();

    let genesis_state = harness.get_current_state();
    let block_slot = Slot::new(2 * slots_per_epoch);
    let (signed_block, state) = harness.make_block(genesis_state, block_slot);

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
    harness.process_block_result(block).unwrap_err();

    assert_eq!(
        store.iter_temporary_state_roots().count(),
        block_slot.as_usize() - 1
    );

    drop(harness);
    drop(store);

    // On startup, the store should garbage collect all the temporary states.
    let store = get_store(&db_path);
    assert_eq!(store.iter_temporary_state_roots().count(), 0);
}

#[test]
fn weak_subjectivity_sync() {
    // Build an initial chain on one harness, representing a synced node with full history.
    let num_initial_blocks = E::slots_per_epoch() * 11;
    let num_final_blocks = E::slots_per_epoch() * 2;

    let temp1 = tempdir().unwrap();
    let full_store = get_store(&temp1);
    let harness = get_harness(full_store.clone(), LOW_VALIDATOR_COUNT);

    harness.extend_chain(
        num_initial_blocks as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let genesis_state = full_store
        .get_state(&harness.chain.genesis_state_root, Some(Slot::new(0)))
        .unwrap()
        .unwrap();
    let wss_checkpoint = harness.chain.head_info().unwrap().finalized_checkpoint;
    let wss_block = harness.get_block(wss_checkpoint.root.into()).unwrap();
    let wss_state = full_store
        .get_state(&wss_block.state_root(), None)
        .unwrap()
        .unwrap();
    let wss_slot = wss_block.slot();

    // Add more blocks that advance finalization further.
    harness.advance_slot();
    harness.extend_chain(
        num_final_blocks as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let (shutdown_tx, _shutdown_rx) = futures::channel::mpsc::channel(1);
    let log = test_logger();
    let temp2 = tempdir().unwrap();
    let store = get_store(&temp2);

    // Initialise a new beacon chain from the finalized checkpoint
    let beacon_chain = BeaconChainBuilder::new(MinimalEthSpec)
        .store(store.clone())
        .custom_spec(test_spec::<E>())
        .weak_subjectivity_state(wss_state, wss_block.clone(), genesis_state)
        .unwrap()
        .logger(log.clone())
        .store_migrator_config(MigratorConfig::default().blocking())
        .dummy_eth1_backend()
        .expect("should build dummy backend")
        .testing_slot_clock(HARNESS_SLOT_TIME)
        .expect("should configure testing slot clock")
        .shutdown_sender(shutdown_tx)
        .chain_config(ChainConfig::default())
        .event_handler(Some(ServerSentEventHandler::new_with_capacity(
            log.clone(),
            1,
        )))
        .monitor_validators(true, vec![], log)
        .build()
        .expect("should build");

    // Apply blocks forward to reach head.
    let chain_dump = harness.chain.chain_dump().unwrap();
    let new_blocks = &chain_dump[wss_slot.as_usize() + 1..];

    assert_eq!(new_blocks[0].beacon_block.slot(), wss_slot + 1);

    for snapshot in new_blocks {
        let block = &snapshot.beacon_block;
        beacon_chain.slot_clock.set_slot(block.slot().as_u64());
        beacon_chain.process_block(block.clone()).unwrap();
        beacon_chain.fork_choice().unwrap();

        // Check that the new block's state can be loaded correctly.
        let state_root = block.state_root();
        let mut state = beacon_chain
            .store
            .get_state(&state_root, Some(block.slot()))
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
        .import_historical_block_batch(&historical_blocks)
        .unwrap();
    assert_eq!(beacon_chain.store.get_oldest_block_slot(), 0);

    // Resupplying the blocks should not fail, they can be safely ignored.
    beacon_chain
        .import_historical_block_batch(&historical_blocks)
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
    for (block_root, slot) in beacon_chain
        .forwards_iter_block_roots(Slot::new(0))
        .unwrap()
        .map(Result::unwrap)
    {
        let block = store.get_block(&block_root).unwrap().unwrap();
        assert_eq!(block.slot(), slot);
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

    // Anchor slot is still set to the starting slot.
    assert_eq!(store.get_anchor_slot(), Some(wss_slot));

    // Reconstruct states.
    store.clone().reconstruct_historic_states().unwrap();
    assert_eq!(store.get_anchor_slot(), None);
}

#[test]
fn finalizes_after_resuming_from_db() {
    let validator_count = 16;
    let num_blocks_produced = MinimalEthSpec::slots_per_epoch() * 8;
    let first_half = num_blocks_produced / 2;

    let db_path = tempdir().unwrap();
    let store = get_store(&db_path);

    let harness = BeaconChainHarness::builder(MinimalEthSpec)
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_disk_store(store.clone())
        .build();

    harness.advance_slot();

    harness.extend_chain(
        first_half as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    assert!(
        harness
            .chain
            .head()
            .expect("should read head")
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
        .build();

    assert_chains_pretty_much_the_same(&original_chain, &resumed_harness.chain);

    // Set the slot clock of the resumed harness to be in the slot following the previous harness.
    //
    // This allows us to produce the block at the next slot.
    resumed_harness
        .chain
        .slot_clock
        .set_slot(latest_slot.as_u64() + 1);

    resumed_harness.extend_chain(
        (num_blocks_produced - first_half) as usize,
        BlockStrategy::OnCanonicalHead,
        AttestationStrategy::AllValidators,
    );

    let state = &resumed_harness
        .chain
        .head()
        .expect("should read head")
        .beacon_state;
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

#[test]
fn revert_minority_fork_on_resume() {
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

    let all_validators = (0..validator_count).collect::<Vec<usize>>();

    // Chain with no fork epoch configured.
    let db_path1 = tempdir().unwrap();
    let store1 = get_store_with_spec(&db_path1, spec1.clone());
    let harness1 = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec1)
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_disk_store(store1)
        .build();

    // Chain with fork epoch configured.
    let db_path2 = tempdir().unwrap();
    let store2 = get_store_with_spec(&db_path2, spec2.clone());
    let harness2 = BeaconChainHarness::builder(MinimalEthSpec)
        .spec(spec2.clone())
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_disk_store(store2)
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

        let (block, new_state) = harness1.make_block(state, slot);

        harness1.process_block(slot, block.clone()).unwrap();
        harness2.process_block(slot, block.clone()).unwrap();

        state = new_state;
        block_root = block.canonical_root();
    }

    assert_eq!(harness1.chain.head_info().unwrap().slot, fork_slot - 1);
    assert_eq!(harness2.chain.head_info().unwrap().slot, fork_slot - 1);

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
        let (block1, new_state1) = harness1.make_block(state1, slot);
        harness1.process_block(slot, block1).unwrap();
        state1 = new_state1;

        // Majority chain block (all attesters).
        let (block2, new_state2) = harness2.make_block(state2, slot);
        harness2.process_block(slot, block2.clone()).unwrap();

        state2 = new_state2;
        block_root = block2.canonical_root();

        majority_blocks.push(block2);
    }

    let end_slot = fork_slot + post_fork_blocks - 1;
    assert_eq!(harness1.chain.head_info().unwrap().slot, end_slot);
    assert_eq!(harness2.chain.head_info().unwrap().slot, end_slot);

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
                .testing_slot_clock(HARNESS_SLOT_TIME)
                .unwrap();
            builder
                .get_slot_clock()
                .unwrap()
                .set_slot(end_slot.as_u64());
            builder
        }))
        .build();

    // Head should now be just before the fork.
    resumed_harness.chain.fork_choice().unwrap();
    let head = resumed_harness.chain.head_info().unwrap();
    assert_eq!(head.slot, fork_slot - 1);

    // Head track should know the canonical head and the rogue head.
    assert_eq!(resumed_harness.chain.heads().len(), 2);
    assert!(resumed_harness.chain.knows_head(&head.block_root.into()));

    // Apply blocks from the majority chain and trigger finalization.
    let initial_split_slot = resumed_harness.chain.store.get_split_slot();
    for block in &majority_blocks {
        resumed_harness.process_block_result(block.clone()).unwrap();

        // The canonical head should be the block from the majority chain.
        resumed_harness.chain.fork_choice().unwrap();
        let head_info = resumed_harness.chain.head_info().unwrap();
        assert_eq!(head_info.slot, block.slot());
        assert_eq!(head_info.block_root, block.canonical_root());
    }
    let advanced_split_slot = resumed_harness.chain.store.get_split_slot();

    // Check that the migration ran successfully.
    assert!(advanced_split_slot > initial_split_slot);

    // Check that there is only a single head now matching harness2 (the minority chain is gone).
    let heads = resumed_harness.chain.heads();
    assert_eq!(heads, harness2.chain.heads());
    assert_eq!(heads.len(), 1);
}

/// Checks that two chains are the same, for the purpose of these tests.
///
/// Several fields that are hard/impossible to check are ignored (e.g., the store).
fn assert_chains_pretty_much_the_same<T: BeaconChainTypes>(a: &BeaconChain<T>, b: &BeaconChain<T>) {
    assert_eq!(a.spec, b.spec, "spec should be equal");
    assert_eq!(a.op_pool, b.op_pool, "op_pool should be equal");
    assert_eq!(
        a.head().unwrap(),
        b.head().unwrap(),
        "head() should be equal"
    );
    assert_eq!(a.heads(), b.heads(), "heads() should be equal");
    assert_eq!(
        a.genesis_block_root, b.genesis_block_root,
        "genesis_block_root should be equal"
    );

    let slot = a.slot().unwrap();
    assert!(
        a.fork_choice.write().get_head(slot).unwrap()
            == b.fork_choice.write().get_head(slot).unwrap(),
        "fork_choice heads should be equal"
    );
}

/// Check that the head state's slot matches `expected_slot`.
fn check_slot(harness: &TestHarness, expected_slot: u64) {
    let state = &harness.chain.head().expect("should get head").beacon_state;

    assert_eq!(
        state.slot(),
        expected_slot,
        "head should be at the current slot"
    );
}

/// Check that the chain has finalized under best-case assumptions, and check the head slot.
fn check_finalization(harness: &TestHarness, expected_slot: u64) {
    let state = &harness.chain.head().expect("should get head").beacon_state;

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
            .head()
            .expect("should get head")
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
    assert_eq!(
        max_slot,
        Some(harness.chain.head_info().expect("should get head").slot)
    );
    // Assert that the block root iterator reaches the head.
    assert_eq!(
        harness
            .chain
            .forwards_iter_block_roots(Slot::new(0))
            .expect("should get iter")
            .last()
            .map(Result::unwrap)
            .map(|(_, slot)| slot),
        Some(harness.chain.head_info().expect("should get head").slot)
    );
}

fn get_finalized_epoch_boundary_blocks(
    dump: &[BeaconSnapshot<MinimalEthSpec>],
) -> HashSet<SignedBeaconBlockHash> {
    dump.iter()
        .cloned()
        .map(|checkpoint| checkpoint.beacon_state.finalized_checkpoint().root.into())
        .collect()
}

fn get_blocks(dump: &[BeaconSnapshot<MinimalEthSpec>]) -> HashSet<SignedBeaconBlockHash> {
    dump.iter()
        .cloned()
        .map(|checkpoint| checkpoint.beacon_block_root.into())
        .collect()
}
