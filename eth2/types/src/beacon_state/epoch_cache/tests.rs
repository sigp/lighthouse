#![cfg(test)]

use super::*;
use crate::test_utils::*;
use swap_or_not_shuffle::shuffle_list;

fn do_sane_cache_test(
    state: BeaconState,
    epoch: Epoch,
    relative_epoch: RelativeEpoch,
    validator_count: usize,
    expected_seed: Hash256,
    expected_shuffling_start: u64,
    spec: &ChainSpec,
) {
    let active_indices: Vec<usize> = (0..validator_count).collect();

    assert_eq!(
        &active_indices[..],
        state
            .get_cached_active_validator_indices(relative_epoch, &spec)
            .unwrap(),
        "Validator indices mismatch"
    );

    let shuffling = shuffle_list(
        active_indices,
        spec.shuffle_round_count,
        &expected_seed[..],
        true,
    )
    .unwrap();

    let committees_per_epoch = spec.get_epoch_committee_count(shuffling.len());
    let committees_per_slot = committees_per_epoch / spec.slots_per_epoch;

    let mut expected_indices_iter = shuffling.iter();
    let mut shard_counter = expected_shuffling_start;

    for (i, slot) in epoch.slot_iter(spec.slots_per_epoch).enumerate() {
        let crosslink_committees_at_slot =
            state.get_crosslink_committees_at_slot(slot, &spec).unwrap();

        assert_eq!(
            crosslink_committees_at_slot.len(),
            committees_per_slot as usize,
            "Bad committees per slot ({})",
            i
        );

        for c in crosslink_committees_at_slot {
            assert_eq!(c.shard, shard_counter, "Bad shard");
            shard_counter += 1;
            shard_counter %= spec.shard_count;

            for &i in &c.committee {
                assert_eq!(
                    i,
                    *expected_indices_iter.next().unwrap(),
                    "Non-sequential validators."
                );
            }
        }
    }
}

fn setup_sane_cache_test(validator_count: usize, spec: &ChainSpec) -> BeaconState {
    let mut builder =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(validator_count, spec);

    let epoch = spec.genesis_epoch + 4;
    let slot = epoch.start_slot(spec.slots_per_epoch);
    builder.teleport_to_slot(slot, spec);

    let (mut state, _keypairs) = builder.build();

    state.current_shuffling_start_shard = 0;
    state.current_shuffling_seed = Hash256::from_slice(&[1; 32]);

    state.previous_shuffling_start_shard = spec.shard_count - 1;
    state.previous_shuffling_seed = Hash256::from_slice(&[2; 32]);

    state
        .build_epoch_cache(RelativeEpoch::Previous, spec)
        .unwrap();
    state
        .build_epoch_cache(RelativeEpoch::Current, spec)
        .unwrap();
    state
        .build_epoch_cache(RelativeEpoch::NextWithRegistryChange, spec)
        .unwrap();
    state
        .build_epoch_cache(RelativeEpoch::NextWithoutRegistryChange, spec)
        .unwrap();

    state
}

#[test]
fn builds_sane_current_epoch_cache() {
    let mut spec = ChainSpec::few_validators();
    spec.shard_count = 4;
    let validator_count = (spec.shard_count * spec.target_committee_size) + 1;
    let state = setup_sane_cache_test(validator_count as usize, &spec);
    do_sane_cache_test(
        state.clone(),
        state.current_epoch(&spec),
        RelativeEpoch::Current,
        validator_count as usize,
        state.current_shuffling_seed,
        state.current_shuffling_start_shard,
        &spec,
    );
}

#[test]
fn builds_sane_previous_epoch_cache() {
    let mut spec = ChainSpec::few_validators();
    spec.shard_count = 2;
    let validator_count = (spec.shard_count * spec.target_committee_size) + 1;
    let state = setup_sane_cache_test(validator_count as usize, &spec);
    do_sane_cache_test(
        state.clone(),
        state.previous_epoch(&spec),
        RelativeEpoch::Previous,
        validator_count as usize,
        state.previous_shuffling_seed,
        state.previous_shuffling_start_shard,
        &spec,
    );
}

#[test]
fn builds_sane_next_without_update_epoch_cache() {
    let mut spec = ChainSpec::few_validators();
    spec.shard_count = 2;
    let validator_count = (spec.shard_count * spec.target_committee_size) + 1;
    let mut state = setup_sane_cache_test(validator_count as usize, &spec);
    state.validator_registry_update_epoch = state.slot.epoch(spec.slots_per_epoch);
    do_sane_cache_test(
        state.clone(),
        state.next_epoch(&spec),
        RelativeEpoch::NextWithoutRegistryChange,
        validator_count as usize,
        state.current_shuffling_seed,
        state.current_shuffling_start_shard,
        &spec,
    );
}
