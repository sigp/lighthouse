#![cfg(test)]
use super::*;
use crate::test_utils::*;
use std::ops::RangeInclusive;

ssz_tests!(FoundationBeaconState);

fn test_beacon_proposer_index<T: EthSpec>() {
    let spec = T::default_spec();
    let relative_epoch = RelativeEpoch::Current;

    // Build a state for testing.
    let build_state = |validator_count: usize| -> BeaconState<T> {
        let builder: TestingBeaconStateBuilder<T> =
            TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(validator_count, &spec);
        let (mut state, _keypairs) = builder.build();
        state.build_committee_cache(relative_epoch, &spec).unwrap();

        state
    };

    // Run a test on the state.
    let test = |state: &BeaconState<T>, slot: Slot, shuffling_index: usize| {
        let shuffling = state.get_shuffling(relative_epoch).unwrap();
        assert_eq!(
            state.get_beacon_proposer_index(slot, relative_epoch, &spec),
            Ok(shuffling[shuffling_index])
        );
    };

    // Test where we have one validator per slot
    let state = build_state(T::slots_per_epoch() as usize);
    for i in 0..T::slots_per_epoch() {
        test(&state, Slot::from(i), i as usize);
    }

    // Test where we have two validators per slot
    let state = build_state(T::slots_per_epoch() as usize * 2);
    for i in 0..T::slots_per_epoch() {
        test(&state, Slot::from(i), i as usize * 2);
    }

    // Test with two validators per slot, first validator has zero balance.
    let mut state = build_state(T::slots_per_epoch() as usize * 2);
    let shuffling = state.get_shuffling(relative_epoch).unwrap().to_vec();
    state.validators[shuffling[0]].effective_balance = 0;
    test(&state, Slot::new(0), 1);
    for i in 1..T::slots_per_epoch() {
        test(&state, Slot::from(i), i as usize * 2);
    }
}

#[test]
fn beacon_proposer_index() {
    test_beacon_proposer_index::<MinimalEthSpec>();
}

/// Should produce (note the set notation brackets):
///
/// (current_epoch - LATEST_ACTIVE_INDEX_ROOTS_LENGTH + ACTIVATION_EXIT_DELAY, current_epoch +
/// ACTIVATION_EXIT_DELAY]
fn active_index_range<T: EthSpec>(current_epoch: Epoch) -> RangeInclusive<Epoch> {
    let delay = T::default_spec().activation_exit_delay;

    let start: i32 =
        current_epoch.as_u64() as i32 - T::epochs_per_historical_vector() as i32 + delay as i32;
    let end = current_epoch + delay;

    let start: Epoch = if start < 0 {
        Epoch::new(0)
    } else {
        Epoch::from(start as u64 + 1)
    };

    start..=end
}

/// Test getting an active index root at the start and end of the valid range, and one either side
/// of that range.
fn test_active_index<T: EthSpec>(state_slot: Slot) {
    let spec = T::default_spec();
    let builder: TestingBeaconStateBuilder<T> =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(16, &spec);
    let (mut state, _keypairs) = builder.build();
    state.slot = state_slot;

    let range = active_index_range::<T>(state.current_epoch());

    let modulo = |epoch: Epoch| epoch.as_usize() % T::epochs_per_historical_vector();

    // Test the start and end of the range.
    assert_eq!(
        state.get_active_index_root_index(*range.start(), &spec, AllowNextEpoch::False),
        Ok(modulo(*range.start()))
    );
    assert_eq!(
        state.get_active_index_root_index(*range.end(), &spec, AllowNextEpoch::False),
        Ok(modulo(*range.end()))
    );

    // One either side of the range.
    if state.current_epoch() > 0 {
        // Test is invalid on epoch zero, cannot subtract from zero.
        assert_eq!(
            state.get_active_index_root_index(*range.start() - 1, &spec, AllowNextEpoch::False),
            Err(Error::EpochOutOfBounds)
        );
    }
    assert_eq!(
        state.get_active_index_root_index(*range.end() + 1, &spec, AllowNextEpoch::False),
        Err(Error::EpochOutOfBounds)
    );
}

#[test]
fn get_active_index_root_index() {
    test_active_index::<MainnetEthSpec>(Slot::new(0));

    let epoch = Epoch::from(MainnetEthSpec::epochs_per_historical_vector() * 4);
    let slot = epoch.start_slot(MainnetEthSpec::slots_per_epoch());
    test_active_index::<MainnetEthSpec>(slot);
}

/// Test that
///
/// 1. Using the cache before it's built fails.
/// 2. Using the cache after it's build passes.
/// 3. Using the cache after it's dropped fails.
fn test_cache_initialization<'a, T: EthSpec>(
    state: &'a mut BeaconState<T>,
    relative_epoch: RelativeEpoch,
    spec: &ChainSpec,
) {
    let slot = relative_epoch
        .into_epoch(state.slot.epoch(T::slots_per_epoch()))
        .start_slot(T::slots_per_epoch());

    // Assuming the cache isn't already built, assert that a call to a cache-using function fails.
    assert_eq!(
        state.get_attestation_duties(0, relative_epoch),
        Err(BeaconStateError::CommitteeCacheUninitialized(
            relative_epoch
        ))
    );

    // Build the cache.
    state.build_committee_cache(relative_epoch, spec).unwrap();

    // Assert a call to a cache-using function passes.
    let _ = state
        .get_beacon_proposer_index(slot, relative_epoch, spec)
        .unwrap();

    // Drop the cache.
    state.drop_committee_cache(relative_epoch);

    // Assert a call to a cache-using function fail.
    assert_eq!(
        state.get_beacon_proposer_index(slot, relative_epoch, spec),
        Err(BeaconStateError::CommitteeCacheUninitialized(
            relative_epoch
        ))
    );
}

#[test]
fn cache_initialization() {
    let spec = MinimalEthSpec::default_spec();

    let builder: TestingBeaconStateBuilder<MinimalEthSpec> =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(16, &spec);
    let (mut state, _keypairs) = builder.build();

    state.slot =
        (MinimalEthSpec::genesis_epoch() + 1).start_slot(MinimalEthSpec::slots_per_epoch());

    test_cache_initialization(&mut state, RelativeEpoch::Previous, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::Current, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::Next, &spec);
}

#[test]
fn tree_hash_cache() {
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use tree_hash::TreeHash;

    let mut rng = XorShiftRng::from_seed([42; 16]);

    let mut state: FoundationBeaconState = BeaconState::random_for_test(&mut rng);

    let root = state.update_tree_hash_cache().unwrap();

    assert_eq!(root.as_bytes(), &state.tree_hash_root()[..]);

    state.slot += 1;

    let root = state.update_tree_hash_cache().unwrap();
    assert_eq!(root.as_bytes(), &state.tree_hash_root()[..]);
}

/// Tests committee-specific components
#[cfg(test)]
mod committees {
    use super::*;
    use crate::beacon_state::MinimalEthSpec;
    use swap_or_not_shuffle::shuffle_list;

    fn execute_committee_consistency_test<T: EthSpec>(
        state: BeaconState<T>,
        epoch: Epoch,
        validator_count: usize,
        spec: &ChainSpec,
    ) {
        let active_indices: Vec<usize> = (0..validator_count).collect();
        let seed = state.get_seed(epoch, spec).unwrap();
        let relative_epoch = RelativeEpoch::from_epoch(state.current_epoch(), epoch).unwrap();
        let start_shard =
            CommitteeCache::compute_start_shard(&state, relative_epoch, active_indices.len(), spec);

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
        let mut expected_shards_iter =
            (0..T::ShardCount::to_u64()).map(|i| (start_shard + i) % T::ShardCount::to_u64());

        // Loop through all slots in the epoch being tested.
        for slot in epoch.slot_iter(T::slots_per_epoch()) {
            let crosslink_committees = state.get_crosslink_committees_at_slot(slot).unwrap();

            // Assert that the number of committees in this slot is consistent with the reported number
            // of committees in an epoch.
            assert_eq!(
                crosslink_committees.len() as u64,
                state.get_committee_count(relative_epoch).unwrap() / T::slots_per_epoch()
            );

            for cc in crosslink_committees {
                // Assert that shards are assigned contiguously across committees.
                assert_eq!(expected_shards_iter.next().unwrap(), cc.shard);
                // Assert that a committee lookup via slot is identical to a committee lookup via
                // shard.
                assert_eq!(
                    state
                        .get_crosslink_committee_for_shard(cc.shard, relative_epoch)
                        .unwrap(),
                    cc
                );

                // Loop through each validator in the committee.
                for (committee_i, validator_i) in cc.committee.iter().enumerate() {
                    // Assert the validators are assigned contiguously across committees.
                    assert_eq!(
                        *validator_i,
                        *expected_indices_iter.next().unwrap(),
                        "Non-sequential validators."
                    );
                    // Assert a call to `get_attestation_duties` is consistent with a call to
                    // `get_crosslink_committees_at_slot`
                    let attestation_duty = state
                        .get_attestation_duties(*validator_i, relative_epoch)
                        .unwrap()
                        .unwrap();
                    assert_eq!(attestation_duty.slot, slot);
                    assert_eq!(attestation_duty.shard, cc.shard);
                    assert_eq!(attestation_duty.committee_index, committee_i);
                    assert_eq!(attestation_duty.committee_len, cc.committee.len());
                }
            }
        }

        // Assert that all validators were assigned to a committee.
        assert!(expected_indices_iter.next().is_none());

        // Assert that all shards were assigned to a committee.
        assert!(expected_shards_iter.next().is_none());
    }

    fn committee_consistency_test<T: EthSpec>(
        validator_count: usize,
        state_epoch: Epoch,
        cache_epoch: RelativeEpoch,
    ) {
        let spec = &T::default_spec();

        let mut builder = TestingBeaconStateBuilder::from_single_keypair(
            validator_count,
            &Keypair::random(),
            spec,
        );

        let slot = state_epoch.start_slot(T::slots_per_epoch());
        builder.teleport_to_slot(slot);

        let (mut state, _keypairs): (BeaconState<T>, _) = builder.build();

        let distinct_hashes: Vec<Hash256> = (0..T::epochs_per_historical_vector())
            .map(|i| Hash256::from_low_u64_be(i as u64))
            .collect();
        state.randao_mixes = FixedVector::from(distinct_hashes);

        state
            .build_committee_cache(RelativeEpoch::Previous, spec)
            .unwrap();
        state
            .build_committee_cache(RelativeEpoch::Current, spec)
            .unwrap();
        state
            .build_committee_cache(RelativeEpoch::Next, spec)
            .unwrap();

        let cache_epoch = cache_epoch.into_epoch(state_epoch);

        execute_committee_consistency_test(state, cache_epoch, validator_count as usize, &spec);
    }

    fn committee_consistency_test_suite<T: EthSpec>(cached_epoch: RelativeEpoch) {
        let spec = T::default_spec();

        let validator_count = (T::shard_count() * spec.target_committee_size) + 1;

        committee_consistency_test::<T>(validator_count as usize, Epoch::new(0), cached_epoch);

        committee_consistency_test::<T>(
            validator_count as usize,
            T::genesis_epoch() + 4,
            cached_epoch,
        );

        committee_consistency_test::<T>(
            validator_count as usize,
            T::genesis_epoch() + T::slots_per_historical_root() as u64 * T::slots_per_epoch() * 4,
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
