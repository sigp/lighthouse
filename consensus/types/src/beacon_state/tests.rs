#![cfg(test)]
use crate::test_utils::*;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use beacon_chain::types::{
    test_utils::TestRandom, BeaconState, BeaconStateAltair, BeaconStateBase, BeaconStateError,
    ChainSpec, Domain, Epoch, EthSpec, Hash256, Keypair, MainnetEthSpec, MinimalEthSpec,
    RelativeEpoch, Slot, Vector,
};
use lazy_static::lazy_static;
use ssz::Encode;
use std::ops::Mul;
use swap_or_not_shuffle::compute_shuffled_index;

pub const MAX_VALIDATOR_COUNT: usize = 129;
pub const SLOT_OFFSET: Slot = Slot::new(1);

lazy_static! {
    /// A cached set of keys.
    static ref KEYPAIRS: Vec<Keypair> = generate_deterministic_keypairs(MAX_VALIDATOR_COUNT);
}

async fn get_harness<E: EthSpec>(
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
        harness
            .add_attested_blocks_at_slots(
                state,
                Hash256::zero(),
                slots.as_slice(),
                (0..validator_count).collect::<Vec<_>>().as_slice(),
            )
            .await;
    }
    harness
}

async fn build_state<E: EthSpec>(validator_count: usize) -> BeaconState<E> {
    get_harness(validator_count, Slot::new(0))
        .await
        .chain
        .head_beacon_state_cloned()
}

async fn test_beacon_proposer_index<E: EthSpec>() {
    let spec = E::default_spec();

    // Get the i'th candidate proposer for the given state and slot
    let ith_candidate = |state: &BeaconState<E>, slot: Slot, i: usize, spec: &ChainSpec| {
        let epoch = slot.epoch(E::slots_per_epoch());
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
    let test = |state: &BeaconState<E>, slot: Slot, candidate_index: usize| {
        assert_eq!(
            state.get_beacon_proposer_index(slot, &spec),
            Ok(ith_candidate(state, slot, candidate_index, &spec))
        );
    };

    // Test where we have one validator per slot.
    // 0th candidate should be chosen every time.
    let state = build_state(E::slots_per_epoch() as usize).await;
    for i in 0..E::slots_per_epoch() {
        test(&state, Slot::from(i), 0);
    }

    // Test where we have two validators per slot.
    // 0th candidate should be chosen every time.
    let state = build_state((E::slots_per_epoch() as usize).mul(2)).await;
    for i in 0..E::slots_per_epoch() {
        test(&state, Slot::from(i), 0);
    }

    // Test with two validators per slot, first validator has zero balance.
    let mut state = build_state::<E>((E::slots_per_epoch() as usize).mul(2)).await;
    let slot0_candidate0 = ith_candidate(&state, Slot::new(0), 0, &spec);
    state
        .validators_mut()
        .get_mut(slot0_candidate0)
        .unwrap()
        .effective_balance = 0;
    test(&state, Slot::new(0), 1);
    for i in 1..E::slots_per_epoch() {
        test(&state, Slot::from(i), 0);
    }
}

#[tokio::test]
async fn beacon_proposer_index() {
    test_beacon_proposer_index::<MinimalEthSpec>().await;
}

/// Test that
///
/// 1. Using the cache before it's built fails.
/// 2. Using the cache after it's build passes.
/// 3. Using the cache after it's dropped fails.
fn test_cache_initialization<E: EthSpec>(
    state: &mut BeaconState<E>,
    relative_epoch: RelativeEpoch,
    spec: &ChainSpec,
) {
    let slot = relative_epoch
        .into_epoch(state.slot().epoch(E::slots_per_epoch()))
        .start_slot(E::slots_per_epoch());

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

#[tokio::test]
async fn cache_initialization() {
    let spec = MinimalEthSpec::default_spec();

    let mut state = build_state::<MinimalEthSpec>(16).await;

    *state.slot_mut() =
        (MinimalEthSpec::genesis_epoch() + 1).start_slot(MinimalEthSpec::slots_per_epoch());

    test_cache_initialization(&mut state, RelativeEpoch::Previous, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::Current, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::Next, &spec);
}

/// Tests committee-specific components
#[cfg(test)]
mod committees {
    use super::*;
    use std::ops::{Add, Div};
    use swap_or_not_shuffle::shuffle_list;

    fn execute_committee_consistency_test<E: EthSpec>(
        state: BeaconState<E>,
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
        for slot in epoch.slot_iter(E::slots_per_epoch()) {
            let beacon_committees = state.get_beacon_committees_at_slot(slot).unwrap();

            // Assert that the number of committees in this slot is consistent with the reported number
            // of committees in an epoch.
            assert_eq!(
                beacon_committees.len() as u64,
                state
                    .get_epoch_committee_count(relative_epoch)
                    .unwrap()
                    .div(E::slots_per_epoch())
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

    async fn committee_consistency_test<E: EthSpec>(
        validator_count: usize,
        state_epoch: Epoch,
        cache_epoch: RelativeEpoch,
    ) {
        let spec = &E::default_spec();

        let slot = state_epoch.start_slot(E::slots_per_epoch());
        let harness = get_harness::<E>(validator_count, slot).await;
        let mut new_head_state = harness.get_current_state();

        let distinct_hashes =
            (0..E::epochs_per_historical_vector()).map(|i| Hash256::from_low_u64_be(i as u64));
        *new_head_state.randao_mixes_mut() = Vector::try_from_iter(distinct_hashes).unwrap();

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

        execute_committee_consistency_test(new_head_state, cache_epoch, validator_count, spec);
    }

    async fn committee_consistency_test_suite<E: EthSpec>(cached_epoch: RelativeEpoch) {
        let spec = E::default_spec();

        let validator_count = spec
            .max_committees_per_slot
            .mul(E::slots_per_epoch() as usize)
            .mul(spec.target_committee_size)
            .add(1);

        committee_consistency_test::<E>(validator_count, Epoch::new(0), cached_epoch).await;

        committee_consistency_test::<E>(validator_count, E::genesis_epoch() + 4, cached_epoch)
            .await;

        committee_consistency_test::<E>(
            validator_count,
            E::genesis_epoch()
                + (E::slots_per_historical_root() as u64)
                    .mul(E::slots_per_epoch())
                    .mul(4),
            cached_epoch,
        )
        .await;
    }

    #[tokio::test]
    async fn current_epoch_committee_consistency() {
        committee_consistency_test_suite::<MinimalEthSpec>(RelativeEpoch::Current).await;
    }

    #[tokio::test]
    async fn previous_epoch_committee_consistency() {
        committee_consistency_test_suite::<MinimalEthSpec>(RelativeEpoch::Previous).await;
    }

    #[tokio::test]
    async fn next_epoch_committee_consistency() {
        committee_consistency_test_suite::<MinimalEthSpec>(RelativeEpoch::Next).await;
    }
}

mod get_outstanding_deposit_len {
    use super::*;

    async fn state() -> BeaconState<MinimalEthSpec> {
        get_harness(16, Slot::new(0))
            .await
            .chain
            .head_beacon_state_cloned()
    }

    #[tokio::test]
    async fn returns_ok() {
        let mut state = state().await;
        assert_eq!(state.get_outstanding_deposit_len(), Ok(0));

        state.eth1_data_mut().deposit_count = 17;
        *state.eth1_deposit_index_mut() = 16;
        assert_eq!(state.get_outstanding_deposit_len(), Ok(1));
    }

    #[tokio::test]
    async fn returns_err_if_the_state_is_invalid() {
        let mut state = state().await;
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
    let spec = E::default_spec();

    let rng = &mut XorShiftRng::from_seed([42; 16]);

    let fork_epoch = spec.altair_fork_epoch.unwrap();

    let base_epoch = fork_epoch.saturating_sub(1_u64);
    let base_slot = base_epoch.end_slot(E::slots_per_epoch());
    let altair_epoch = fork_epoch;
    let altair_slot = altair_epoch.start_slot(E::slots_per_epoch());

    // BeaconStateBase
    {
        let good_base_state: BeaconState<MainnetEthSpec> = BeaconState::Base(BeaconStateBase {
            slot: base_slot,
            ..<_>::random_for_test(rng)
        });
        // It's invalid to have a base state with a slot higher than the fork slot.
        let bad_base_state = {
            let mut bad = good_base_state.clone();
            *bad.slot_mut() = altair_slot;
            bad
        };

        assert_eq!(
            BeaconState::from_ssz_bytes(&good_base_state.as_ssz_bytes(), &spec)
                .expect("good base state can be decoded"),
            good_base_state
        );
        <BeaconState<MainnetEthSpec>>::from_ssz_bytes(&bad_base_state.as_ssz_bytes(), &spec)
            .expect_err("bad base state cannot be decoded");
    }

    // BeaconStateAltair
    {
        let good_altair_state: BeaconState<MainnetEthSpec> =
            BeaconState::Altair(BeaconStateAltair {
                slot: altair_slot,
                ..<_>::random_for_test(rng)
            });
        // It's invalid to have an Altair state with a slot lower than the fork slot.
        let bad_altair_state = {
            let mut bad = good_altair_state.clone();
            *bad.slot_mut() = base_slot;
            bad
        };

        assert_eq!(
            BeaconState::from_ssz_bytes(&good_altair_state.as_ssz_bytes(), &spec)
                .expect("good altair state can be decoded"),
            good_altair_state
        );
        <BeaconState<MainnetEthSpec>>::from_ssz_bytes(&bad_altair_state.as_ssz_bytes(), &spec)
            .expect_err("bad altair state cannot be decoded");
    }
}
