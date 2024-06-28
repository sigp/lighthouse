use criterion::{black_box, criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion};
use milhouse::List;
use rayon::prelude::*;
use ssz::Encode;
use std::sync::Arc;
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
        state
            .balances_mut()
            .push(i as u64)
            .expect("should add balance");
    }

    *state.validators_mut() = List::new(
        (0..validator_count)
            .collect::<Vec<_>>()
            .par_iter()
            .map(|&i| Validator {
                pubkey: generate_deterministic_keypair(i).pk.compress(),
                withdrawal_credentials: Hash256::from_low_u64_le(i as u64),
                effective_balance: spec.max_effective_balance,
                slashed: false,
                activation_eligibility_epoch: Epoch::new(0),
                activation_epoch: Epoch::new(0),
                exit_epoch: Epoch::from(u64::MAX),
                withdrawable_epoch: Epoch::from(u64::MAX),
            })
            .collect(),
    )
    .unwrap();

    state
}

fn all_benches(c: &mut Criterion) {
    let validator_count = 16_384;
    let spec = Arc::new(MainnetEthSpec::default_spec());

    let mut g = c.benchmark_group("types");
    g.sample_size(10);

    let mut state = get_state::<MainnetEthSpec>(validator_count);
    state.build_caches(&spec).expect("should build caches");
    let state_bytes = state.as_ssz_bytes();

    let inner_state = state.clone();
    g.bench_with_input(
        BenchmarkId::new("encode/beacon_state", validator_count),
        &inner_state,
        |b, state| {
            b.iter_batched_ref(
                || state.clone(),
                |state| black_box(state.as_ssz_bytes()),
                BatchSize::SmallInput,
            )
        },
    );

    g.bench_with_input(
        BenchmarkId::new("decode/beacon_state", validator_count),
        &(state_bytes.clone(), spec.clone()),
        |b, (bytes, spec)| {
            b.iter_batched_ref(
                || (bytes.clone(), spec.clone()),
                |(bytes, spec)| {
                    let state: BeaconState<MainnetEthSpec> =
                        BeaconState::from_ssz_bytes(&bytes, &spec).expect("should decode");
                    black_box(state)
                },
                BatchSize::SmallInput,
            )
        },
    );

    let inner_state = state.clone();
    g.bench_with_input(
        BenchmarkId::new("clone/beacon_state", validator_count),
        &inner_state,
        |b, state| {
            b.iter_batched_ref(
                || state.clone(),
                |state| black_box(state.clone()),
                BatchSize::SmallInput,
            )
        },
    );

    let inner_state = state.clone();
    g.bench_with_input(
        BenchmarkId::new(
            "initialized_cached_tree_hash_without_changes/beacon_state",
            validator_count,
        ),
        &inner_state,
        |b, state| {
            b.iter_batched_ref(
                || state.clone(),
                |state| black_box(state.update_tree_hash_cache()),
                BatchSize::SmallInput,
            )
        },
    );

    let mut inner_state = state.clone();
    inner_state.drop_all_caches().unwrap();
    g.bench_with_input(
        BenchmarkId::new(
            "non_initialized_cached_tree_hash/beacon_state",
            validator_count,
        ),
        &inner_state,
        |b, state| {
            b.iter_batched_ref(
                || state.clone(),
                |state| {
                    black_box(
                        state
                            .update_tree_hash_cache()
                            .expect("should update tree hash"),
                    )
                },
                BatchSize::SmallInput,
            )
        },
    );

    let inner_state = state.clone();
    g.bench_with_input(
        BenchmarkId::new(
            "initialized_cached_tree_hash_with_new_validators/beacon_state",
            validator_count,
        ),
        &inner_state,
        |b, state| {
            b.iter_batched_ref(
                || {
                    let mut state = state.clone();
                    for _ in 0..16 {
                        state
                            .validators_mut()
                            .push(Validator::default())
                            .expect("should push validator");
                        state
                            .balances_mut()
                            .push(32_000_000_000)
                            .expect("should push balance");
                    }
                    state
                },
                |state| black_box(state.update_tree_hash_cache()),
                BatchSize::SmallInput,
            )
        },
    );
}

criterion_group!(benches, all_benches);
criterion_main!(benches);
