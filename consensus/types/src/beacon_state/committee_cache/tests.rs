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

async fn new_state<T: EthSpec>(validator_count: usize, slot: Slot) -> BeaconState<T> {
    let harness = get_harness(validator_count);
    let head_state = harness.get_current_state();
    if slot > Slot::new(0) {
        harness
            .add_attested_blocks_at_slots(
                head_state,
                Hash256::zero(),
                (1..=slot.as_u64())
                    .map(Slot::new)
                    .collect::<Vec<_>>()
                    .as_slice(),
                (0..validator_count).collect::<Vec<_>>().as_slice(),
            )
            .await;
    }
    harness.get_current_state()
}

#[tokio::test]
#[should_panic]
async fn fails_without_validators() {
    new_state::<MinimalEthSpec>(0, Slot::new(0)).await;
}

#[tokio::test]
async fn initializes_with_the_right_epoch() {
    let state = new_state::<MinimalEthSpec>(16, Slot::new(0)).await;
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

#[tokio::test]
async fn shuffles_for_the_right_epoch() {
    let num_validators = MinimalEthSpec::minimum_validator_count() * 2;
    let epoch = Epoch::new(6);
    let slot = epoch.start_slot(MinimalEthSpec::slots_per_epoch());

    let mut state = new_state::<MinimalEthSpec>(num_validators, slot).await;
    let spec = &MinimalEthSpec::default_spec();

    assert_eq!(state.current_epoch(), epoch);

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

    // We can initialize the committee cache at recent epochs in the past, and one epoch into the
    // future.
    for e in (0..=epoch.as_u64() + 1).map(Epoch::new) {
        let seed = state.get_seed(e, Domain::BeaconAttester, spec).unwrap();
        let cache = CommitteeCache::initialized(&state, e, spec)
            .unwrap_or_else(|_| panic!("failed at epoch {}", e));
        assert_eq!(cache.shuffling(), shuffling_with_seed(seed));
        assert_shuffling_positions_accurate(&cache);
    }

    // We should *not* be able to build a committee cache for the epoch after the next epoch.
    assert_eq!(
        CommitteeCache::initialized(&state, epoch + 2, spec),
        Err(BeaconStateError::EpochOutOfBounds)
    );
}

#[tokio::test]
async fn min_randao_epoch_correct() {
    let num_validators = MinimalEthSpec::minimum_validator_count() * 2;
    let current_epoch = Epoch::new(MinimalEthSpec::epochs_per_historical_vector() as u64 * 2);

    let mut state = new_state::<MinimalEthSpec>(
        num_validators,
        Epoch::new(1).start_slot(MinimalEthSpec::slots_per_epoch()),
    )
    .await;

    // Override the epoch so that there's some room to move.
    *state.slot_mut() = current_epoch.start_slot(MinimalEthSpec::slots_per_epoch());
    assert_eq!(state.current_epoch(), current_epoch);

    // The min_randao_epoch should be the minimum epoch such that `get_randao_mix` returns `Ok`.
    let min_randao_epoch = state.min_randao_epoch();
    state.get_randao_mix(min_randao_epoch).unwrap();
    state.get_randao_mix(min_randao_epoch - 1).unwrap_err();
    state.get_randao_mix(min_randao_epoch + 1).unwrap();
}
