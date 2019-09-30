#![cfg(test)]
use super::*;
use crate::{test_utils::*, *};
use serde_derive::{Deserialize, Serialize};
use ssz_types::typenum::*;

#[test]
fn default_values() {
    let cache = CommitteeCache::default();

    assert_eq!(cache.is_initialized_at(Epoch::new(0)), false);
    assert!(&cache.active_validator_indices().is_empty());
    assert_eq!(cache.get_crosslink_committee_for_shard(0), None);
    assert_eq!(cache.get_attestation_duties(0), None);
    assert_eq!(cache.active_validator_count(), 0);
    assert_eq!(cache.epoch_committee_count(), 0);
    assert_eq!(cache.epoch_start_shard(), 0);
    assert_eq!(cache.get_crosslink_committees_for_slot(Slot::new(0)), None);
    assert_eq!(cache.first_committee_at_slot(Slot::new(0)), None);
}

fn new_state<T: EthSpec>(validator_count: usize, slot: Slot) -> BeaconState<T> {
    let spec = &T::default_spec();

    let mut builder =
        TestingBeaconStateBuilder::from_single_keypair(validator_count, &Keypair::random(), spec);

    builder.teleport_to_slot(slot);

    let (state, _keypairs) = builder.build();

    state
}

#[test]
fn fails_without_validators() {
    let state = new_state::<MinimalEthSpec>(0, Slot::new(0));
    let spec = &MinimalEthSpec::default_spec();

    assert_eq!(
        CommitteeCache::initialized(&state, state.current_epoch(), &spec),
        Err(BeaconStateError::InsufficientValidators)
    );
}

#[test]
fn initializes_with_the_right_epoch() {
    let state = new_state::<MinimalEthSpec>(16, Slot::new(0));
    let spec = &MinimalEthSpec::default_spec();

    let cache = CommitteeCache::default();
    assert_eq!(cache.initialized_epoch, None);

    let cache = CommitteeCache::initialized(&state, state.current_epoch(), &spec).unwrap();
    assert_eq!(cache.initialized_epoch, Some(state.current_epoch()));

    let cache = CommitteeCache::initialized(&state, state.previous_epoch(), &spec).unwrap();
    assert_eq!(cache.initialized_epoch, Some(state.previous_epoch()));

    let cache = CommitteeCache::initialized(&state, state.next_epoch(), &spec).unwrap();
    assert_eq!(cache.initialized_epoch, Some(state.next_epoch()));
}

#[test]
fn shuffles_for_the_right_epoch() {
    use crate::EthSpec;

    let num_validators = MinimalEthSpec::minimum_validator_count() * 2;
    let epoch = Epoch::new(100_000_000);
    let slot = epoch.start_slot(MinimalEthSpec::slots_per_epoch());

    let mut state = new_state::<MinimalEthSpec>(num_validators, slot);
    let spec = &MinimalEthSpec::default_spec();

    let distinct_hashes: Vec<Hash256> = (0..MinimalEthSpec::epochs_per_historical_vector())
        .map(|i| Hash256::from_low_u64_be(i as u64))
        .collect();

    state.randao_mixes = FixedVector::from(distinct_hashes);

    let previous_seed = state.get_seed(state.previous_epoch(), spec).unwrap();
    let current_seed = state.get_seed(state.current_epoch(), spec).unwrap();
    let next_seed = state.get_seed(state.next_epoch(), spec).unwrap();

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
        for (i, v) in cache.shuffling.iter().enumerate() {
            assert_eq!(
                cache.shuffling_positions[*v].unwrap().get() - 1,
                i,
                "Shuffling position inaccurate"
            );
        }
    };

    let cache = CommitteeCache::initialized(&state, state.current_epoch(), spec).unwrap();
    assert_eq!(cache.shuffling, shuffling_with_seed(current_seed));
    assert_shuffling_positions_accurate(&cache);

    let cache = CommitteeCache::initialized(&state, state.previous_epoch(), spec).unwrap();
    assert_eq!(cache.shuffling, shuffling_with_seed(previous_seed));
    assert_shuffling_positions_accurate(&cache);

    let cache = CommitteeCache::initialized(&state, state.next_epoch(), spec).unwrap();
    assert_eq!(cache.shuffling, shuffling_with_seed(next_seed));
    assert_shuffling_positions_accurate(&cache);
}

#[test]
fn can_start_on_any_shard() {
    let num_validators = MinimalEthSpec::minimum_validator_count() * 2;
    let epoch = Epoch::new(100_000_000);
    let slot = epoch.start_slot(MinimalEthSpec::slots_per_epoch());

    let mut state = new_state::<MinimalEthSpec>(num_validators, slot);
    let spec = &MinimalEthSpec::default_spec();

    let target_committee_size = MinimalEthSpec::default_spec().target_committee_size;

    let shard_delta = MinimalEthSpec::get_shard_delta(num_validators, target_committee_size);
    let shard_count = MinimalEthSpec::shard_count() as u64;

    for i in 0..MinimalEthSpec::shard_count() as u64 {
        state.start_shard = i;

        let cache = CommitteeCache::initialized(&state, state.current_epoch(), spec).unwrap();
        assert_eq!(cache.shuffling_start_shard, i);

        let cache = CommitteeCache::initialized(&state, state.previous_epoch(), spec).unwrap();
        assert_eq!(
            cache.shuffling_start_shard,
            (i + shard_count - shard_delta) % shard_count
        );

        let cache = CommitteeCache::initialized(&state, state.next_epoch(), spec).unwrap();
        assert_eq!(cache.shuffling_start_shard, (i + shard_delta) % shard_count);
    }
}

/// This spec has more shards than slots in an epoch, permitting epochs where not all shards are
/// included in the committee.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
pub struct ExcessShardsEthSpec;

impl EthSpec for ExcessShardsEthSpec {
    type ShardCount = U128;
    type SlotsPerEpoch = U8;
    type MaxPendingAttestations = U1024;

    params_from_eth_spec!(MinimalEthSpec {
        JustificationBitsLength,
        MaxValidatorsPerCommittee,
        GenesisEpoch,
        SlotsPerEth1VotingPeriod,
        SlotsPerHistoricalRoot,
        EpochsPerHistoricalVector,
        EpochsPerSlashingsVector,
        HistoricalRootsLimit,
        ValidatorRegistryLimit,
        MaxProposerSlashings,
        MaxAttesterSlashings,
        MaxAttestations,
        MaxDeposits,
        MaxVoluntaryExits,
        MaxTransfers
    });

    fn default_spec() -> ChainSpec {
        ChainSpec::minimal()
    }
}

#[test]
fn starts_on_the_correct_shard() {
    let spec = &ExcessShardsEthSpec::default_spec();

    let num_validators = spec.target_committee_size * ExcessShardsEthSpec::shard_count();

    let epoch = Epoch::new(100_000_000);
    let slot = epoch.start_slot(ExcessShardsEthSpec::slots_per_epoch());

    let mut state = new_state::<ExcessShardsEthSpec>(num_validators, slot);

    let validator_count = state.validators.len();

    let previous_epoch = state.previous_epoch();
    let current_epoch = state.current_epoch();
    let next_epoch = state.next_epoch();

    for (i, mut v) in state.validators.iter_mut().enumerate() {
        let epoch = if i < validator_count / 4 {
            previous_epoch
        } else if i < validator_count / 2 {
            current_epoch
        } else {
            next_epoch
        };

        v.activation_epoch = epoch;
    }

    assert_eq!(
        get_active_validator_count(&state.validators, previous_epoch),
        validator_count / 4
    );
    assert_eq!(
        get_active_validator_count(&state.validators, current_epoch),
        validator_count / 2
    );
    assert_eq!(
        get_active_validator_count(&state.validators, next_epoch),
        validator_count
    );

    let previous_shards = ExcessShardsEthSpec::get_committee_count(
        get_active_validator_count(&state.validators, previous_epoch),
        spec.target_committee_size,
    );
    let current_shards = ExcessShardsEthSpec::get_committee_count(
        get_active_validator_count(&state.validators, current_epoch),
        spec.target_committee_size,
    );
    let next_shards = ExcessShardsEthSpec::get_committee_count(
        get_active_validator_count(&state.validators, next_epoch),
        spec.target_committee_size,
    );

    assert_eq!(
        previous_shards as usize,
        ExcessShardsEthSpec::shard_count() / 4
    );
    assert_eq!(
        current_shards as usize,
        ExcessShardsEthSpec::shard_count() / 2
    );
    assert_eq!(next_shards as usize, ExcessShardsEthSpec::shard_count());

    let shard_count = ExcessShardsEthSpec::shard_count();
    for i in 0..ExcessShardsEthSpec::shard_count() {
        state.start_shard = i as u64;

        let cache = CommitteeCache::initialized(&state, state.current_epoch(), spec).unwrap();
        assert_eq!(cache.shuffling_start_shard as usize, i);

        let cache = CommitteeCache::initialized(&state, state.previous_epoch(), spec).unwrap();
        assert_eq!(
            cache.shuffling_start_shard as usize,
            (i + shard_count - previous_shards) % shard_count
        );

        let cache = CommitteeCache::initialized(&state, state.next_epoch(), spec).unwrap();
        assert_eq!(
            cache.shuffling_start_shard as usize,
            (i + current_shards) % shard_count
        );
    }
}
