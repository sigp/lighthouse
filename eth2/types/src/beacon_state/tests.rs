#![cfg(test)]
use super::*;
use crate::test_utils::*;

ssz_tests!(BeaconState);

/// Test that
///
/// 1. Using the cache before it's built fails.
/// 2. Using the cache after it's build passes.
/// 3. Using the cache after it's dropped fails.
fn test_cache_initialization<'a>(
    state: &'a mut BeaconState,
    relative_epoch: RelativeEpoch,
    spec: &ChainSpec,
) {
    let slot = relative_epoch
        .into_epoch(state.slot.epoch(spec.slots_per_epoch))
        .start_slot(spec.slots_per_epoch);

    // Assuming the cache isn't already built, assert that a call to a cache-using function fails.
    assert_eq!(
        state.get_beacon_proposer_index(slot, relative_epoch, spec),
        Err(BeaconStateError::EpochCacheUninitialized(relative_epoch))
    );

    // Build the cache.
    state.build_epoch_cache(relative_epoch, spec).unwrap();

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
    let spec = ChainSpec::few_validators();
    let (mut state, _keypairs) =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(16, &spec).build();

    state.slot = (spec.genesis_epoch + 1).start_slot(spec.slots_per_epoch);

    test_cache_initialization(&mut state, RelativeEpoch::Previous, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::Current, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::NextWithRegistryChange, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::NextWithoutRegistryChange, &spec);
}
