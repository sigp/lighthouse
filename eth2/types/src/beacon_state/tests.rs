#![cfg(test)]
use super::*;
use crate::beacon_state::FewValidatorsEthSpec;
use crate::test_utils::*;
use std::ops::RangeInclusive;

ssz_tests!(FoundationBeaconState);
cached_tree_hash_tests!(FoundationBeaconState);

/// Should produce (note the set notation brackets):
///
/// (current_epoch - LATEST_ACTIVE_INDEX_ROOTS_LENGTH + ACTIVATION_EXIT_DELAY, current_epoch +
/// ACTIVATION_EXIT_DELAY]
fn active_index_range<T: EthSpec>(current_epoch: Epoch) -> RangeInclusive<Epoch> {
    let delay = T::spec().activation_exit_delay;

    let start: i32 =
        current_epoch.as_u64() as i32 - T::latest_active_index_roots() as i32 + delay as i32;
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
    let spec = T::spec();
    let builder: TestingBeaconStateBuilder<T> =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(16, &spec);
    let (mut state, _keypairs) = builder.build();
    state.slot = state_slot;

    let range = active_index_range::<T>(state.current_epoch());

    let modulo = |epoch: Epoch| epoch.as_usize() % T::latest_active_index_roots();

    // Test the start and end of the range.
    assert_eq!(
        state.get_active_index_root_index(*range.start(), &spec),
        Ok(modulo(*range.start()))
    );
    assert_eq!(
        state.get_active_index_root_index(*range.end(), &spec),
        Ok(modulo(*range.end()))
    );

    // One either side of the range.
    if state.current_epoch() > 0 {
        // Test is invalid on epoch zero, cannot subtract from zero.
        assert_eq!(
            state.get_active_index_root_index(*range.start() - 1, &spec),
            Err(Error::EpochOutOfBounds)
        );
    }
    assert_eq!(
        state.get_active_index_root_index(*range.end() + 1, &spec),
        Err(Error::EpochOutOfBounds)
    );
}

#[test]
fn get_active_index_root_index() {
    test_active_index::<FoundationEthSpec>(Slot::new(0));

    let epoch = Epoch::from(FoundationEthSpec::latest_active_index_roots() * 4);
    let slot = epoch.start_slot(FoundationEthSpec::slots_per_epoch());
    test_active_index::<FoundationEthSpec>(slot);
}

/*
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
        .into_epoch(state.slot.epoch(spec.slots_per_epoch))
        .start_slot(spec.slots_per_epoch);

    // Assuming the cache isn't already built, assert that a call to a cache-using function fails.
    assert_eq!(
        state.get_attestation_duties(0, spec),
        Err(BeaconStateError::EpochCacheUninitialized(relative_epoch))
    );

    // Build the cache.
    state
        .build_current_epoch_cache(relative_epoch, spec)
        .unwrap();

    // Assert a call to a cache-using function passes.
    let _ = state
        .get_beacon_proposer_index(slot, relative_epoch, spec)
        .unwrap();

    // Drop the cache.
    state.drop_cache(relative_epoch);

    // Assert a call to a cache-using function fail.
    assert_eq!(
        state.get_beacon_proposer_index(slot, relative_epoch, spec),
        Err(BeaconStateError::EpochCacheUninitialized(relative_epoch))
    );
}

#[test]
fn cache_initialization() {
    let spec = FewValidatorsEthSpec::spec();

    let builder: TestingBeaconStateBuilder<FewValidatorsEthSpec> =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(16, &spec);
    let (mut state, _keypairs) = builder.build();

    state.slot = (spec.genesis_epoch + 1).start_slot(spec.slots_per_epoch);

    test_cache_initialization(&mut state, RelativeEpoch::Previous, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::Current, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::NextWithRegistryChange, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::NextWithoutRegistryChange, &spec);
}
*/

#[test]
fn tree_hash_cache() {
    use crate::test_utils::{SeedableRng, TestRandom, XorShiftRng};
    use tree_hash::TreeHash;

    let mut rng = XorShiftRng::from_seed([42; 16]);

    let mut state: FoundationBeaconState = BeaconState::random_for_test(&mut rng);

    let root = state.update_tree_hash_cache().unwrap();

    assert_eq!(root.as_bytes(), &state.tree_hash_root()[..]);

    state.slot = state.slot + 1;

    let root = state.update_tree_hash_cache().unwrap();
    assert_eq!(root.as_bytes(), &state.tree_hash_root()[..]);
}
