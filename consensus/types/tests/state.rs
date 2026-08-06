#![cfg(test)]
use std::ops::Mul;
use std::sync::LazyLock;

use arbitrary::Arbitrary;
use beacon_chain::test_utils::{BeaconChainHarness, EphemeralHarnessType};
use bls::Keypair;
use fixed_bytes::FixedBytesExtended;
#[cfg(feature = "spec-minimal")]
use milhouse::Vector;
use ssz::Encode;
use swap_or_not_shuffle::compute_shuffled_index;
use types::test_utils::generate_deterministic_keypairs;
use types::*;

pub const MAX_VALIDATOR_COUNT: usize = 129;
pub const SLOT_OFFSET: Slot = Slot::new(1);

/// A cached set of keys.
static KEYPAIRS: LazyLock<Vec<Keypair>> =
    LazyLock::new(|| generate_deterministic_keypairs(MAX_VALIDATOR_COUNT));

async fn get_harness(
    validator_count: usize,
    slot: Slot,
) -> BeaconChainHarness<EphemeralHarnessType> {
    let harness = BeaconChainHarness::builder()
        .default_spec()
        .keypairs(KEYPAIRS[0..validator_count].to_vec())
        .fresh_ephemeral_store()
        .mock_execution_layer()
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
                slots.as_slice(),
                (0..validator_count).collect::<Vec<_>>().as_slice(),
            )
            .await;
    }
    harness
}

async fn build_state(validator_count: usize) -> BeaconState {
    get_harness(validator_count, Slot::new(0))
        .await
        .chain
        .head_beacon_state_cloned()
}

async fn test_beacon_proposer_index() {
    let spec = Spec::default_spec();

    // Get the i'th candidate proposer for the given state and slot
    let ith_candidate = |state: &BeaconState, slot: Slot, i: usize, spec: &ChainSpec| {
        let epoch = slot.epoch(Spec::slots_per_epoch());
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
    let test = |state: &BeaconState, slot: Slot, candidate_index: usize| {
        assert_eq!(
            state.get_beacon_proposer_index(slot, &spec),
            Ok(ith_candidate(state, slot, candidate_index, &spec))
        );
    };

    // Test where we have one validator per slot.
    // 0th candidate should be chosen every time.
    let state = build_state(Spec::SLOTS_PER_EPOCH).await;
    for i in 0..Spec::slots_per_epoch() {
        test(&state, Slot::from(i), 0);
    }

    // Test where we have two validators per slot.
    // 0th candidate should be chosen every time.
    let state = build_state((Spec::SLOTS_PER_EPOCH).mul(2)).await;
    for i in 0..Spec::slots_per_epoch() {
        test(&state, Slot::from(i), 0);
    }

    // Test with two validators per slot, first validator has zero balance.
    let mut state = build_state((Spec::SLOTS_PER_EPOCH).mul(2)).await;
    let slot0_candidate0 = ith_candidate(&state, Slot::new(0), 0, &spec);
    state
        .validators_mut()
        .get_mut(slot0_candidate0)
        .unwrap()
        .effective_balance = 0;
    test(&state, Slot::new(0), 1);
    for i in 1..Spec::slots_per_epoch() {
        test(&state, Slot::from(i), 0);
    }
}

#[tokio::test]
async fn beacon_proposer_index() {
    test_beacon_proposer_index().await;
}

/// Test that
///
/// 1. Using the cache before it's built fails.
/// 2. Using the cache after it's build passes.
/// 3. Using the cache after it's dropped fails.
fn test_cache_initialization(
    state: &mut BeaconState,
    relative_epoch: RelativeEpoch,
    spec: &ChainSpec,
) {
    let slot = relative_epoch
        .into_epoch(state.slot().epoch(Spec::slots_per_epoch()))
        .start_slot(Spec::slots_per_epoch());

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
    let spec = Spec::default_spec();

    let mut state = build_state(16).await;

    *state.slot_mut() = Epoch::new(Spec::genesis_epoch() + 1).start_slot(Spec::slots_per_epoch());

    test_cache_initialization(&mut state, RelativeEpoch::Previous, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::Current, &spec);
    test_cache_initialization(&mut state, RelativeEpoch::Next, &spec);
}

/// Tests committee-specific components
#[cfg(test)]
#[cfg(feature = "spec-minimal")]
mod committees {
    use super::*;
    use std::ops::{Add, Div};
    use swap_or_not_shuffle::shuffle_list;

    fn execute_committee_consistency_test(
        state: BeaconState,
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
        for slot in epoch.slot_iter(Spec::slots_per_epoch()) {
            let beacon_committees = state.get_beacon_committees_at_slot(slot).unwrap();

            // Assert that the number of committees in this slot is consistent with the reported number
            // of committees in an epoch.
            assert_eq!(
                beacon_committees.len() as u64,
                state
                    .get_epoch_committee_count(relative_epoch)
                    .unwrap()
                    .div(Spec::slots_per_epoch())
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

    async fn committee_consistency_test(
        validator_count: usize,
        state_epoch: Epoch,
        cache_epoch: RelativeEpoch,
    ) {
        let spec = &Spec::default_spec();

        let slot = state_epoch.start_slot(Spec::slots_per_epoch());
        let harness = get_harness(validator_count, slot).await;
        let mut new_head_state = harness.get_current_state();

        let distinct_hashes =
            (0..Spec::epochs_per_historical_vector()).map(Hash256::from_low_u64_be);
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

    async fn committee_consistency_test_suite(cached_epoch: RelativeEpoch) {
        let spec = Spec::default_spec();

        let validator_count = spec
            .max_committees_per_slot
            .mul(Spec::SLOTS_PER_EPOCH)
            .mul(spec.target_committee_size)
            .add(1);

        committee_consistency_test(validator_count, Epoch::new(0), cached_epoch).await;

        committee_consistency_test(
            validator_count,
            Epoch::new(Spec::genesis_epoch() + 4),
            cached_epoch,
        )
        .await;

        committee_consistency_test(
            validator_count,
            Epoch::new(Spec::genesis_epoch())
                + (Spec::slots_per_historical_root())
                    .mul(Spec::slots_per_epoch())
                    .mul(4),
            cached_epoch,
        )
        .await;
    }

    #[tokio::test]
    async fn current_epoch_committee_consistency() {
        committee_consistency_test_suite(RelativeEpoch::Current).await;
    }

    #[tokio::test]
    async fn previous_epoch_committee_consistency() {
        committee_consistency_test_suite(RelativeEpoch::Previous).await;
    }

    #[tokio::test]
    async fn next_epoch_committee_consistency() {
        committee_consistency_test_suite(RelativeEpoch::Next).await;
    }
}

#[test]
fn decode_base_and_altair() {
    let mut spec = Spec::default_spec();
    spec.altair_fork_epoch = spec.altair_fork_epoch.or(Some(Epoch::new(1)));

    let mut u = types::test_utils::test_unstructured();

    let fork_epoch = spec.altair_fork_epoch.unwrap();

    let base_epoch = fork_epoch.saturating_sub(1_u64);
    let base_slot = base_epoch.end_slot(Spec::slots_per_epoch());
    let altair_epoch = fork_epoch;
    let altair_slot = altair_epoch.start_slot(Spec::slots_per_epoch());

    // BeaconStateBase
    {
        let good_base_state: BeaconState = BeaconState::Base(BeaconStateBase {
            slot: base_slot,
            ..<_>::arbitrary(&mut u).unwrap()
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
        BeaconState::from_ssz_bytes(&bad_base_state.as_ssz_bytes(), &spec)
            .expect_err("bad base state cannot be decoded");
    }

    // BeaconStateAltair
    {
        let good_altair_state: BeaconState = BeaconState::Altair(BeaconStateAltair {
            slot: altair_slot,
            ..<_>::arbitrary(&mut u).unwrap()
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
        BeaconState::from_ssz_bytes(&bad_altair_state.as_ssz_bytes(), &spec)
            .expect_err("bad altair state cannot be decoded");
    }
}
