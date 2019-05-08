#![cfg(test)]
use super::*;
use crate::beacon_state::FewValidatorsStateTypes;
use crate::test_utils::*;

ssz_tests!(FoundationBeaconState);
cached_tree_hash_tests!(FoundationBeaconState);

/// Test that
///
/// 1. Using the cache before it's built fails.
/// 2. Using the cache after it's build passes.
/// 3. Using the cache after it's dropped fails.
fn test_cache_initialization<'a, T: BeaconStateTypes>(
    state: &'a mut BeaconState<T>,
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
    let spec = FewValidatorsStateTypes::spec();

    let builder: TestingBeaconStateBuilder<FewValidatorsStateTypes> =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(16, &spec);
    let (mut state, _keypairs) = builder.build();

    state.slot = (spec.genesis_epoch + 1).start_slot(spec.slots_per_epoch);

    test_cache_initialization(&mut state, RelativeEpoch::Previous, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::Current, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::NextWithRegistryChange, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::NextWithoutRegistryChange, &spec);
}

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
