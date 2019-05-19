#![cfg(test)]
use super::*;
use crate::{test_utils::*, *};

fn new_state<T: EthSpec>(validator_count: usize, slot: Slot) -> BeaconState<T> {
    let spec = &T::spec();

    let mut builder =
        TestingBeaconStateBuilder::from_single_keypair(validator_count, &Keypair::random(), spec);

    builder.teleport_to_slot(slot, spec);

    let (state, _keypairs) = builder.build();

    state
}

#[test]
fn fails_without_validators() {
    let state = new_state::<FewValidatorsEthSpec>(0, Slot::new(0));
    let spec = &FewValidatorsEthSpec::spec();

    assert_eq!(
        EpochCache::initialized(&state, state.current_epoch(), &spec),
        Err(BeaconStateError::InsufficientValidators)
    );
}

#[test]
fn initializes_with_the_right_epoch() {
    let state = new_state::<FewValidatorsEthSpec>(16, Slot::new(0));
    let spec = &FewValidatorsEthSpec::spec();

    let cache = EpochCache::default();
    assert_eq!(cache.initialized_epoch, None);

    let cache = EpochCache::initialized(&state, state.current_epoch(), &spec).unwrap();
    assert_eq!(cache.initialized_epoch, Some(state.current_epoch()));

    let cache = EpochCache::initialized(&state, state.previous_epoch(), &spec).unwrap();
    assert_eq!(cache.initialized_epoch, Some(state.previous_epoch()));

    let cache = EpochCache::initialized(&state, state.next_epoch(), &spec).unwrap();
    assert_eq!(cache.initialized_epoch, Some(state.next_epoch()));
}

#[test]
fn shuffles_for_the_right_epoch() {
    let num_validators = FewValidatorsEthSpec::minimum_validator_count() * 2;
    let epoch = Epoch::new(100_000_000);
    let slot = epoch.start_slot(FewValidatorsEthSpec::slots_per_epoch());

    let mut state = new_state::<FewValidatorsEthSpec>(num_validators, slot);
    let spec = &FewValidatorsEthSpec::spec();

    let distinct_hashes: Vec<Hash256> = (0..FewValidatorsEthSpec::latest_randao_mixes_length())
        .into_iter()
        .map(|i| Hash256::from(i as u64))
        .collect();

    state.latest_randao_mixes = FixedLenVec::from(distinct_hashes);

    let previous_seed = state.generate_seed(state.previous_epoch(), spec).unwrap();
    let current_seed = state.generate_seed(state.current_epoch(), spec).unwrap();
    let next_seed = state.generate_seed(state.next_epoch(), spec).unwrap();

    assert!((previous_seed != current_seed) && (current_seed != next_seed));

    let shuffling_with_seed = |seed: Hash256| {
        shuffle_list(
            (0..num_validators).collect(),
            spec.shuffle_round_count,
            &seed[..],
            false,
        )
        .unwrap()
    };

    let cache = EpochCache::initialized(&state, state.current_epoch(), spec).unwrap();
    assert_eq!(cache.shuffling, shuffling_with_seed(current_seed));

    let cache = EpochCache::initialized(&state, state.previous_epoch(), spec).unwrap();
    assert_eq!(cache.shuffling, shuffling_with_seed(previous_seed));

    let cache = EpochCache::initialized(&state, state.next_epoch(), spec).unwrap();
    assert_eq!(cache.shuffling, shuffling_with_seed(next_seed));
}
