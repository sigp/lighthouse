use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main, Benchmark};
use rayon::prelude::*;
use ssz::{Decode, Encode};
use types::{
    test_utils::generate_deterministic_keypair, BeaconState, Eth1Data, EthSpec, Hash256,
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
            effective_balance: i as u64,
            slashed: i % 2 == 0,
            activation_eligibility_epoch: i.into(),
            activation_epoch: i.into(),
            exit_epoch: i.into(),
            withdrawable_epoch: i.into(),
        })
        .collect::<Vec<_>>()
        .into();

    state
}

fn all_benches(c: &mut Criterion) {
    let validator_count = 16_384;
    let state = get_state::<MainnetEthSpec>(validator_count);
    let state_bytes = state.as_ssz_bytes();

    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new("encode/beacon_state", move |b| {
            b.iter_batched_ref(
                || state.clone(),
                |state| black_box(state.as_ssz_bytes()),
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
                        BeaconState::from_ssz_bytes(&bytes).expect("should decode");
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
