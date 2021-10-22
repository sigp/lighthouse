#![cfg(test)]
use crate::test_utils::*;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_chain::types::*;
use swap_or_not_shuffle::shuffle_list;

pub const VALIDATOR_COUNT: usize = 16;

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = generate_deterministic_keypairs(VALIDATOR_COUNT);
}

fn get_harness<E: EthSpec>(validator_count: usize) -> BeaconChainHarness<EphemeralHarnessType<E>> {
    let harness = BeaconChainHarness::builder(E::default())
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .build();
    harness.advance_slot();
    harness
}

#[test]
fn default_values() {
    let cache = CommitteeCache::default();

    assert!(!cache.is_initialized_at(Epoch::new(0)));
    assert!(&cache.active_validator_indices().is_empty());
    assert_eq!(cache.get_beacon_committee(Slot::new(0), 0), None);
    assert_eq!(cache.get_attestation_duties(0), None);
    assert_eq!(cache.active_validator_count(), 0);
    assert_eq!(cache.epoch_committee_count(), 0);
    assert!(cache.get_beacon_committees_at_slot(Slot::new(0)).is_err());
}

fn new_state<T: EthSpec>(validator_count: usize, slot: Slot) -> BeaconState<T> {
    let harness = get_harness(validator_count);
    let head_state = harness.get_current_state();
    if slot > Slot::new(0) {
        harness.add_attested_blocks_at_slots(
            head_state,
            Hash256::zero(),
            (1..slot.as_u64())
                .map(Slot::new)
                .collect::<Vec<_>>()
                .as_slice(),
            (0..validator_count).collect::<Vec<_>>().as_slice(),
        );
    }
    harness.get_current_state()
}

#[test]
#[should_panic]
fn fails_without_validators() {
    new_state::<MinimalEthSpec>(0, Slot::new(0));
}

#[test]
fn initializes_with_the_right_epoch() {
    let state = new_state::<MinimalEthSpec>(16, Slot::new(0));
    let spec = &MinimalEthSpec::default_spec();

    let cache = CommitteeCache::default();
    assert!(!cache.is_initialized_at(state.current_epoch()));

    let cache = CommitteeCache::initialized(&state, state.current_epoch(), spec).unwrap();
    assert!(cache.is_initialized_at(state.current_epoch()));

    let cache = CommitteeCache::initialized(&state, state.previous_epoch(), spec).unwrap();
    assert!(cache.is_initialized_at(state.previous_epoch()));

    let cache = CommitteeCache::initialized(&state, state.next_epoch().unwrap(), spec).unwrap();
    assert!(cache.is_initialized_at(state.next_epoch().unwrap()));
}

#[test]
fn shuffles_for_the_right_epoch() {
    let num_validators = MinimalEthSpec::minimum_validator_count() * 2;
    let epoch = Epoch::new(6);
    let slot = epoch.start_slot(MinimalEthSpec::slots_per_epoch());

    let mut state = new_state::<MinimalEthSpec>(num_validators, slot);
    let spec = &MinimalEthSpec::default_spec();

    let distinct_hashes: Vec<Hash256> = (0..MinimalEthSpec::epochs_per_historical_vector())
        .map(|i| Hash256::from_low_u64_be(i as u64))
        .collect();

    *state.randao_mixes_mut() = FixedVector::from(distinct_hashes);

    let previous_seed = state
        .get_seed(state.previous_epoch(), Domain::BeaconAttester, spec)
        .unwrap();
    let current_seed = state
        .get_seed(state.current_epoch(), Domain::BeaconAttester, spec)
        .unwrap();
    let next_seed = state
        .get_seed(state.next_epoch().unwrap(), Domain::BeaconAttester, spec)
        .unwrap();

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

    let assert_shuffling_positions_accurate = |cache: &CommitteeCache| {
        for (i, v) in cache.shuffling().iter().enumerate() {
            assert_eq!(
                cache.shuffled_position(*v).unwrap(),
                i,
                "Shuffling position inaccurate"
            );
        }
    };

    let cache = CommitteeCache::initialized(&state, state.current_epoch(), spec).unwrap();
    assert_eq!(cache.shuffling(), shuffling_with_seed(current_seed));
    assert_shuffling_positions_accurate(&cache);

    let cache = CommitteeCache::initialized(&state, state.previous_epoch(), spec).unwrap();
    assert_eq!(cache.shuffling(), shuffling_with_seed(previous_seed));
    assert_shuffling_positions_accurate(&cache);

    let cache = CommitteeCache::initialized(&state, state.next_epoch().unwrap(), spec).unwrap();
    assert_eq!(cache.shuffling(), shuffling_with_seed(next_seed));
    assert_shuffling_positions_accurate(&cache);
}
