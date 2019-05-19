#![cfg(test)]

use super::*;
use crate::beacon_state::FewValidatorsEthSpec;
use crate::test_utils::*;
use swap_or_not_shuffle::shuffle_list;

fn execute_sane_cache_test<T: EthSpec>(
    state: BeaconState<T>,
    epoch: Epoch,
    validator_count: usize,
    spec: &ChainSpec,
) {
    let active_indices: Vec<usize> = (0..validator_count).collect();
    let seed = state.generate_seed(epoch, spec).unwrap();
    let start_shard = 0;
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
    let mut expected_shards_iter = (start_shard..start_shard + T::shard_count() as u64).into_iter();

    // Loop through all slots in the epoch being tested.
    for slot in epoch.slot_iter(spec.slots_per_epoch) {
        let crosslink_committees = state.get_crosslink_committees_at_slot(slot).unwrap();

        // Assert that the number of committees in this slot is consistent with the reported number
        // of committees in an epoch.
        assert_eq!(
            crosslink_committees.len() as u64,
            state.get_epoch_committee_count(relative_epoch).unwrap() / T::slots_per_epoch()
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
            for &i in cc.committee {
                // Assert the validators are assigned contiguously across committees.
                assert_eq!(
                    i,
                    *expected_indices_iter.next().unwrap(),
                    "Non-sequential validators."
                );
            }
        }
    }

    // Assert that all validators were assigned to a committee.
    assert!(expected_indices_iter.next().is_none());

    // Assert that all shards were assigned to a committee.
    assert!(expected_shards_iter.next().is_none());
}

fn sane_cache_test<T: EthSpec>(
    validator_count: usize,
    state_epoch: Epoch,
    cache_epoch: RelativeEpoch,
) {
    let spec = &T::spec();

    let mut builder =
        TestingBeaconStateBuilder::from_single_keypair(validator_count, &Keypair::random(), spec);

    let slot = state_epoch.start_slot(spec.slots_per_epoch);
    builder.teleport_to_slot(slot, spec);

    let (mut state, _keypairs): (BeaconState<T>, _) = builder.build();

    state
        .build_epoch_cache(RelativeEpoch::Previous, spec)
        .unwrap();
    state
        .build_epoch_cache(RelativeEpoch::Current, spec)
        .unwrap();
    state.build_epoch_cache(RelativeEpoch::Next, spec).unwrap();

    let cache_epoch = cache_epoch.into_epoch(state_epoch);

    execute_sane_cache_test(state, cache_epoch, validator_count as usize, &spec);
}

fn sane_cache_test_suite<T: EthSpec>(cached_epoch: RelativeEpoch) {
    let spec = T::spec();

    let validator_count = (spec.shard_count * spec.target_committee_size) + 1;

    sane_cache_test::<T>(validator_count as usize, Epoch::new(0), cached_epoch);

    sane_cache_test::<T>(
        validator_count as usize,
        spec.genesis_epoch + 4,
        cached_epoch,
    );

    sane_cache_test::<T>(
        validator_count as usize,
        spec.genesis_epoch + T::slots_per_historical_root() as u64 * T::slots_per_epoch() * 4,
        cached_epoch,
    );
}

#[test]
fn current_epoch_suite() {
    sane_cache_test_suite::<FewValidatorsEthSpec>(RelativeEpoch::Current);
}

#[test]
fn previous_epoch_suite() {
    sane_cache_test_suite::<FewValidatorsEthSpec>(RelativeEpoch::Previous);
}

#[test]
fn next_epoch_suite() {
    sane_cache_test_suite::<FewValidatorsEthSpec>(RelativeEpoch::Next);
}
