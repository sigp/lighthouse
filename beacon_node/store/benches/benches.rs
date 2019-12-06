use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main, Benchmark};
use rayon::prelude::*;
use ssz::{Decode, Encode};
use std::convert::TryInto;
use store::BeaconStateStorageContainer;
use types::{
    test_utils::generate_deterministic_keypair, BeaconState, Epoch, Eth1Data, EthSpec, Hash256,
    MainnetEthSpec, Validator,
};

fn get_state<E: EthSpec>(validator_count: usize) -> BeaconState<E> {
    let spec = &E::default_spec();
    let eth1_data = Eth1Data {
        deposit_root: Hash256::zero(),
        deposit_count: 0,
        block_hash: Hash256::zero(),
    };

    let mut state = BeaconState::new(0, eth1_data, spec);

    for i in 0..validator_count {
        state.balances.push(i as u64).expect("should add balance");
    }

    state.validators = (0..validator_count)
        .into_iter()
        .collect::<Vec<_>>()
        .par_iter()
        .map(|&i| Validator {
            pubkey: generate_deterministic_keypair(i).pk.into(),
            withdrawal_credentials: Hash256::from_low_u64_le(i as u64),
            effective_balance: spec.max_effective_balance,
            slashed: false,
            activation_eligibility_epoch: Epoch::new(0),
            activation_epoch: Epoch::new(0),
            exit_epoch: Epoch::from(u64::max_value()),
            withdrawable_epoch: Epoch::from(u64::max_value()),
        })
        .collect::<Vec<_>>()
        .into();

    state.build_all_caches(spec).expect("should build caches");

    state
}

fn all_benches(c: &mut Criterion) {
    let validator_count = 16_384;
    let state = get_state::<MainnetEthSpec>(validator_count);
    let storage_container = BeaconStateStorageContainer::new(&state);
    let state_bytes = storage_container.as_ssz_bytes();

    let inner_state = state.clone();
    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new("encode/beacon_state", move |b| {
            b.iter_batched_ref(
                || inner_state.clone(),
                |state| black_box(BeaconStateStorageContainer::new(state).as_ssz_bytes()),
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let inner_state = state.clone();
    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new("encode/beacon_state/tree_hash_cache", move |b| {
            b.iter_batched_ref(
                || inner_state.tree_hash_cache.clone(),
                |tree_hash_cache| black_box(tree_hash_cache.as_ssz_bytes()),
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let inner_state = state.clone();
    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new("encode/beacon_state/committee_cache[0]", move |b| {
            b.iter_batched_ref(
                || inner_state.committee_caches[0].clone(),
                |committee_cache| black_box(committee_cache.as_ssz_bytes()),
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new("decode/beacon_state", move |b| {
            b.iter_batched_ref(
                || state_bytes.clone(),
                |bytes| {
                    let state: BeaconState<MainnetEthSpec> =
                        BeaconStateStorageContainer::from_ssz_bytes(&bytes)
                            .expect("should decode")
                            .try_into()
                            .expect("should convert into state");
                    black_box(state)
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );
}

criterion_group!(benches, all_benches,);
criterion_main!(benches);
