#![cfg(test)]
use crate::test_utils::*;
use crate::test_utils::{SeedableRng, XorShiftRng};
use beacon_chain::test_utils::{
    interop_genesis_state, test_spec, BeaconChainHarness, EphemeralHarnessType,
};
use beacon_chain::types::{
    test_utils::TestRandom, BeaconState, BeaconStateAltair, BeaconStateBase, BeaconStateError,
    ChainSpec, CloneConfig, Domain, Epoch, EthSpec, FixedVector, Hash256, Keypair, MainnetEthSpec,
    MinimalEthSpec, RelativeEpoch, Slot,
};
use safe_arith::SafeArith;
use ssz::{Decode, Encode};
use state_processing::per_slot_processing;
use std::ops::Mul;
use swap_or_not_shuffle::compute_shuffled_index;
use tree_hash::TreeHash;

pub const MAX_VALIDATOR_COUNT: usize = 129;
pub const SLOT_OFFSET: Slot = Slot::new(1);

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = generate_deterministic_keypairs(MAX_VALIDATOR_COUNT);
}

fn get_harness<E: EthSpec>(
    validator_count: usize,
    slot: Slot,
) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .build();

    let skip_to_slot = slot - SLOT_OFFSET;
    if skip_to_slot > Slot::new(0) {
        let slots = (skip_to_slot.as_u64()..=slot.as_u64())
            .map(Slot::new)
            .collect::<Vec<_>>();
        let state = harness.get_current_state();
        harness.add_attested_blocks_at_slots(
            state,
            Hash256::zero(),
            slots.as_slice(),
            (0..validator_count).collect::<Vec<_>>().as_slice(),
        );
    }
    harness
}

fn build_state<E: EthSpec>(validator_count: usize) -> BeaconState<E> {
    get_harness(validator_count, Slot::new(0))
        .chain
        .head_beacon_state()
        .unwrap()
}

fn test_beacon_proposer_index<T: EthSpec>() {
    let spec = T::default_spec();

    // Get the i'th candidate proposer for the given state and slot
    let ith_candidate = |state: &BeaconState<T>, slot: Slot, i: usize, spec: &ChainSpec| {
        let epoch = slot.epoch(T::slots_per_epoch());
        let seed = state.get_beacon_proposer_seed(slot, spec).unwrap();
        let active_validators = state.get_active_validator_indices(epoch, spec).unwrap();
        active_validators[compute_shuffled_index(
            i,
            active_validators.len(),
            &seed,
            spec.shuffle_round_count,
        )
        .unwrap()]
    };

    // Run a test on the state.
    let test = |state: &BeaconState<T>, slot: Slot, candidate_index: usize| {
        assert_eq!(
            state.get_beacon_proposer_index(slot, &spec),
            Ok(ith_candidate(state, slot, candidate_index, &spec))
        );
    };

    // Test where we have one validator per slot.
    // 0th candidate should be chosen every time.
    let state = build_state(T::slots_per_epoch() as usize);
    for i in 0..T::slots_per_epoch() {
        test(&state, Slot::from(i), 0);
    }

    // Test where we have two validators per slot.
    // 0th candidate should be chosen every time.
    let state = build_state((T::slots_per_epoch() as usize).mul(2));
    for i in 0..T::slots_per_epoch() {
        test(&state, Slot::from(i), 0);
    }

    // Test with two validators per slot, first validator has zero balance.
    let mut state = build_state::<T>((T::slots_per_epoch() as usize).mul(2));
    let slot0_candidate0 = ith_candidate(&state, Slot::new(0), 0, &spec);
    state.validators_mut()[slot0_candidate0].effective_balance = 0;
    test(&state, Slot::new(0), 1);
    for i in 1..T::slots_per_epoch() {
        test(&state, Slot::from(i), 0);
    }
}

#[test]
fn beacon_proposer_index() {
    test_beacon_proposer_index::<MinimalEthSpec>();
}

/// Test that
///
/// 1. Using the cache before it's built fails.
/// 2. Using the cache after it's build passes.
/// 3. Using the cache after it's dropped fails.
fn test_cache_initialization<T: EthSpec>(
    state: &mut BeaconState<T>,
    relative_epoch: RelativeEpoch,
    spec: &ChainSpec,
) {
    let slot = relative_epoch
        .into_epoch(state.slot().epoch(T::slots_per_epoch()))
        .start_slot(T::slots_per_epoch());

    // Build the cache.
    state.build_committee_cache(relative_epoch, spec).unwrap();

    // Assert a call to a cache-using function passes.
    state.get_beacon_committee(slot, 0).unwrap();

    // Drop the cache.
    state.drop_committee_cache(relative_epoch).unwrap();

    // Assert a call to a cache-using function fail.
    assert_eq!(
        state.get_beacon_committee(slot, 0),
        Err(BeaconStateError::CommitteeCacheUninitialized(Some(
            relative_epoch
        )))
    );
}

#[test]
fn cache_initialization() {
    let spec = MinimalEthSpec::default_spec();

    let mut state = build_state::<MinimalEthSpec>(16);

    *state.slot_mut() =
        (MinimalEthSpec::genesis_epoch() + 1).start_slot(MinimalEthSpec::slots_per_epoch());

    test_cache_initialization(&mut state, RelativeEpoch::Previous, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::Current, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::Next, &spec);
}

fn test_clone_config<E: EthSpec>(base_state: &BeaconState<E>, clone_config: CloneConfig) {
    let state = base_state.clone_with(clone_config);
    if clone_config.committee_caches {
        state
            .committee_cache(RelativeEpoch::Previous)
            .expect("committee cache exists");
        state
            .committee_cache(RelativeEpoch::Current)
            .expect("committee cache exists");
        state
            .committee_cache(RelativeEpoch::Next)
            .expect("committee cache exists");
        state
            .total_active_balance()
            .expect("total active balance exists");
    } else {
        state
            .committee_cache(RelativeEpoch::Previous)
            .expect_err("shouldn't exist");
        state
            .committee_cache(RelativeEpoch::Current)
            .expect_err("shouldn't exist");
        state
            .committee_cache(RelativeEpoch::Next)
            .expect_err("shouldn't exist");
    }
    if clone_config.pubkey_cache {
        assert_ne!(state.pubkey_cache().len(), 0);
    } else {
        assert_eq!(state.pubkey_cache().len(), 0);
    }
    if clone_config.exit_cache {
        state
            .exit_cache()
            .check_initialized()
            .expect("exit cache exists");
    } else {
        state
            .exit_cache()
            .check_initialized()
            .expect_err("exit cache doesn't exist");
    }
    if clone_config.tree_hash_cache {
        assert!(state.tree_hash_cache().is_initialized());
    } else {
        assert!(
            !state.tree_hash_cache().is_initialized(),
            "{:?}",
            clone_config
        );
    }
}

#[test]
fn clone_config() {
    let spec = MinimalEthSpec::default_spec();

    let mut state = build_state::<MinimalEthSpec>(16);

    state.build_all_caches(&spec).unwrap();
    state
        .update_tree_hash_cache()
        .expect("should update tree hash cache");

    let num_caches = 4;
    let all_configs = (0..2u8.pow(num_caches)).map(|i| CloneConfig {
        committee_caches: (i & 1) != 0,
        pubkey_cache: ((i >> 1) & 1) != 0,
        exit_cache: ((i >> 2) & 1) != 0,
        tree_hash_cache: ((i >> 3) & 1) != 0,
    });

    for config in all_configs {
        test_clone_config(&state, config);
    }
}

/// Tests committee-specific components
#[cfg(test)]
mod committees {
    use super::*;
    use std::ops::{Add, Div};
    use swap_or_not_shuffle::shuffle_list;

    fn execute_committee_consistency_test<T: EthSpec>(
        state: BeaconState<T>,
        epoch: Epoch,
        validator_count: usize,
        spec: &ChainSpec,
    ) {
        let active_indices: Vec<usize> = (0..validator_count).collect();
        let seed = state.get_seed(epoch, Domain::BeaconAttester, spec).unwrap();
        let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), epoch).unwrap();

        let mut ordered_indices = state
            .get_cached_active_validator_indices(relative_epoch)
            .unwrap()
            .to_vec();
        ordered_indices.sort_unstable();
        assert_eq!(
            active_indices, ordered_indices,
            "Validator indices mismatch"
        );

        let shuffling =
            shuffle_list(active_indices, spec.shuffle_round_count, &seed[..], false).unwrap();

        let mut expected_indices_iter = shuffling.iter();

        // Loop through all slots in the epoch being tested.
        for slot in epoch.slot_iter(T::slots_per_epoch()) {
            let beacon_committees = state.get_beacon_committees_at_slot(slot).unwrap();

            // Assert that the number of committees in this slot is consistent with the reported number
            // of committees in an epoch.
            assert_eq!(
                beacon_committees.len() as u64,
                state
                    .get_epoch_committee_count(relative_epoch)
                    .unwrap()
                    .div(T::slots_per_epoch())
            );

            for (committee_index, bc) in beacon_committees.iter().enumerate() {
                // Assert that indices are assigned sequentially across committees.
                assert_eq!(committee_index as u64, bc.index);
                // Assert that a committee lookup via slot is identical to a committee lookup via
                // index.
                assert_eq!(state.get_beacon_committee(bc.slot, bc.index).unwrap(), *bc);

                // Loop through each validator in the committee.
                for (committee_i, validator_i) in bc.committee.iter().enumerate() {
                    // Assert the validators are assigned contiguously across committees.
                    assert_eq!(
                        *validator_i,
                        *expected_indices_iter.next().unwrap(),
                        "Non-sequential validators."
                    );
                    // Assert a call to `get_attestation_duties` is consistent with a call to
                    // `get_beacon_committees_at_slot`
                    let attestation_duty = state
                        .get_attestation_duties(*validator_i, relative_epoch)
                        .unwrap()
                        .unwrap();
                    assert_eq!(attestation_duty.slot, slot);
                    assert_eq!(attestation_duty.index, bc.index);
                    assert_eq!(attestation_duty.committee_position, committee_i);
                    assert_eq!(attestation_duty.committee_len, bc.committee.len());
                }
            }
        }

        // Assert that all validators were assigned to a committee.
        assert!(expected_indices_iter.next().is_none());
    }

    fn committee_consistency_test<T: EthSpec>(
        validator_count: usize,
        state_epoch: Epoch,
        cache_epoch: RelativeEpoch,
    ) {
        let spec = &T::default_spec();

        let slot = state_epoch.start_slot(T::slots_per_epoch());
        let harness = get_harness::<T>(validator_count, slot);
        let mut new_head_state = harness.get_current_state();

        let distinct_hashes: Vec<Hash256> = (0..T::epochs_per_historical_vector())
            .map(|i| Hash256::from_low_u64_be(i as u64))
            .collect();
        *new_head_state.randao_mixes_mut() = FixedVector::from(distinct_hashes);

        new_head_state
            .force_build_committee_cache(RelativeEpoch::Previous, spec)
            .unwrap();
        new_head_state
            .force_build_committee_cache(RelativeEpoch::Current, spec)
            .unwrap();
        new_head_state
            .force_build_committee_cache(RelativeEpoch::Next, spec)
            .unwrap();

        let cache_epoch = cache_epoch.into_epoch(state_epoch);

        execute_committee_consistency_test(
            new_head_state,
            cache_epoch,
            validator_count as usize,
            spec,
        );
    }

    fn committee_consistency_test_suite<T: EthSpec>(cached_epoch: RelativeEpoch) {
        let spec = T::default_spec();

        let validator_count = spec
            .max_committees_per_slot
            .mul(T::slots_per_epoch() as usize)
            .mul(spec.target_committee_size)
            .add(1);

        committee_consistency_test::<T>(validator_count as usize, Epoch::new(0), cached_epoch);

        committee_consistency_test::<T>(
            validator_count as usize,
            T::genesis_epoch() + 4,
            cached_epoch,
        );

        committee_consistency_test::<T>(
            validator_count as usize,
            T::genesis_epoch()
                + (T::slots_per_historical_root() as u64)
                    .mul(T::slots_per_epoch())
                    .mul(4),
            cached_epoch,
        );
    }

    #[test]
    fn current_epoch_committee_consistency() {
        committee_consistency_test_suite::<MinimalEthSpec>(RelativeEpoch::Current);
    }

    #[test]
    fn previous_epoch_committee_consistency() {
        committee_consistency_test_suite::<MinimalEthSpec>(RelativeEpoch::Previous);
    }

    #[test]
    fn next_epoch_committee_consistency() {
        committee_consistency_test_suite::<MinimalEthSpec>(RelativeEpoch::Next);
    }
}

mod get_outstanding_deposit_len {
    use super::*;

    fn state() -> BeaconState<MinimalEthSpec> {
        get_harness(16, Slot::new(0))
            .chain
            .head_beacon_state()
            .unwrap()
    }

    #[test]
    fn returns_ok() {
        let mut state = state();
        assert_eq!(state.get_outstanding_deposit_len(), Ok(0));

        state.eth1_data_mut().deposit_count = 17;
        *state.eth1_deposit_index_mut() = 16;
        assert_eq!(state.get_outstanding_deposit_len(), Ok(1));
    }

    #[test]
    fn returns_err_if_the_state_is_invalid() {
        let mut state = state();
        // The state is invalid, deposit count is lower than deposit index.
        state.eth1_data_mut().deposit_count = 16;
        *state.eth1_deposit_index_mut() = 17;

        assert_eq!(
            state.get_outstanding_deposit_len(),
            Err(BeaconStateError::InvalidDepositState {
                deposit_count: 16,
                deposit_index: 17,
            })
        );
    }
}

#[test]
fn decode_base_and_altair() {
    type E = MainnetEthSpec;

    let rng = &mut XorShiftRng::from_seed([42; 16]);

    let fork_epoch = Epoch::from_ssz_bytes(&[7, 6, 5, 4, 3, 2, 1, 0]).unwrap();

    let base_epoch = fork_epoch.saturating_sub(1_u64);
    let base_slot = base_epoch.end_slot(E::slots_per_epoch());
    let altair_epoch = fork_epoch;
    let altair_slot = altair_epoch.start_slot(E::slots_per_epoch());

    let mut spec = E::default_spec();
    spec.altair_fork_epoch = Some(altair_epoch);

    // BeaconStateBase
    {
        let good_base_block: BeaconState<MainnetEthSpec> = BeaconState::Base(BeaconStateBase {
            slot: base_slot,
            ..<_>::random_for_test(rng)
        });
        // It's invalid to have a base block with a slot higher than the fork slot.
        let bad_base_block = {
            let mut bad = good_base_block.clone();
            *bad.slot_mut() = altair_slot;
            bad
        };

        assert_eq!(
            BeaconState::from_ssz_bytes(&good_base_block.as_ssz_bytes(), &spec)
                .expect("good base block can be decoded"),
            good_base_block
        );
        <BeaconState<MainnetEthSpec>>::from_ssz_bytes(&bad_base_block.as_ssz_bytes(), &spec)
            .expect_err("bad base block cannot be decoded");
    }

    // BeaconStateAltair
    {
        let good_altair_block: BeaconState<MainnetEthSpec> =
            BeaconState::Altair(BeaconStateAltair {
                slot: altair_slot,
                ..<_>::random_for_test(rng)
            });
        // It's invalid to have an Altair block with a slot lower than the fork slot.
        let bad_altair_block = {
            let mut bad = good_altair_block.clone();
            *bad.slot_mut() = base_slot;
            bad
        };

        assert_eq!(
            BeaconState::from_ssz_bytes(&good_altair_block.as_ssz_bytes(), &spec)
                .expect("good altair block can be decoded"),
            good_altair_block
        );
        <BeaconState<MainnetEthSpec>>::from_ssz_bytes(&bad_altair_block.as_ssz_bytes(), &spec)
            .expect_err("bad altair block cannot be decoded");
    }
}

#[test]
fn tree_hash_cache_linear_history() {
    let mut rng = XorShiftRng::from_seed([42; 16]);

    let mut state: BeaconState<MainnetEthSpec> =
        BeaconState::Base(BeaconStateBase::random_for_test(&mut rng));

    let root = state.update_tree_hash_cache().unwrap();

    assert_eq!(root.as_bytes(), &state.tree_hash_root()[..]);

    /*
     * A cache should hash twice without updating the slot.
     */

    assert_eq!(
        state.update_tree_hash_cache().unwrap(),
        root,
        "tree hash result should be identical on the same slot"
    );

    /*
     * A cache should not hash after updating the slot but not updating the state roots.
     */

    // The tree hash cache needs to be rebuilt since it was dropped when it failed.
    state
        .update_tree_hash_cache()
        .expect("should rebuild cache");

    *state.slot_mut() += 1;

    assert_eq!(
        state.update_tree_hash_cache(),
        Err(BeaconStateError::NonLinearTreeHashCacheHistory),
        "should not build hash without updating the state root"
    );

    /*
     * The cache should update if the slot and state root are updated.
     */

    // The tree hash cache needs to be rebuilt since it was dropped when it failed.
    let root = state
        .update_tree_hash_cache()
        .expect("should rebuild cache");

    *state.slot_mut() += 1;
    state
        .set_state_root(state.slot() - 1, root)
        .expect("should set state root");

    let root = state.update_tree_hash_cache().unwrap();
    assert_eq!(root.as_bytes(), &state.tree_hash_root()[..]);
}

// Check how the cache behaves when there's a distance larger than `SLOTS_PER_HISTORICAL_ROOT`
// since its last update.
#[test]
fn tree_hash_cache_linear_history_long_skip() {
    let validator_count = 128;
    let keypairs = generate_deterministic_keypairs(validator_count);

    let spec = &test_spec::<MinimalEthSpec>();

    // This state has a cache that advances normally each slot.
    let mut state: BeaconState<MinimalEthSpec> = interop_genesis_state(&keypairs, 0, spec).unwrap();

    state.update_tree_hash_cache().unwrap();

    // This state retains its original cache until it is updated after a long skip.
    let mut original_cache_state = state.clone();
    assert!(original_cache_state.tree_hash_cache().is_initialized());

    // Advance the states to a slot beyond the historical state root limit, using the state root
    // from the first state to avoid touching the original state's cache.
    let start_slot = state.slot();
    let target_slot = start_slot
        .safe_add(MinimalEthSpec::slots_per_historical_root() as u64 + 1)
        .unwrap();

    let mut prev_state_root;
    while state.slot() < target_slot {
        prev_state_root = state.update_tree_hash_cache().unwrap();
        per_slot_processing(&mut state, None, spec).unwrap();
        per_slot_processing(&mut original_cache_state, Some(prev_state_root), spec).unwrap();
    }

    // The state with the original cache should still be initialized at the starting slot.
    assert_eq!(
        original_cache_state
            .tree_hash_cache()
            .initialized_slot()
            .unwrap(),
        start_slot
    );

    // Updating the tree hash cache should be successful despite the long skip.
    assert_eq!(
        original_cache_state.update_tree_hash_cache().unwrap(),
        state.update_tree_hash_cache().unwrap()
    );

    assert_eq!(
        original_cache_state
            .tree_hash_cache()
            .initialized_slot()
            .unwrap(),
        target_slot
    );
}
