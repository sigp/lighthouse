use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main, Benchmark};
use env_logger::{Builder, Env};
use test_harness::BeaconChainHarness;
use types::{ChainSpec, Hash256};

fn mid_epoch_state_transition(c: &mut Criterion) {
    Builder::from_env(Env::default().default_filter_or("debug")).init();

    let validator_count = 1000;
    let mut rig = BeaconChainHarness::new(ChainSpec::foundation(), validator_count);

    let epoch_depth = (rig.spec.epoch_length * 2) + (rig.spec.epoch_length / 2);

    for _ in 0..epoch_depth {
        rig.advance_chain_with_block();
    }

    let state = rig.beacon_chain.state.read().clone();

    assert!((state.slot + 1) % rig.spec.epoch_length != 0);

    c.bench_function("mid-epoch state transition 10k validators", move |b| {
        let state = state.clone();
        b.iter(|| {
            let mut state = state.clone();
            black_box(state.per_slot_processing(Hash256::zero(), &rig.spec))
        })
    });
}

fn epoch_boundary_state_transition(c: &mut Criterion) {
    // Builder::from_env(Env::default().default_filter_or("debug")).init();

    let validator_count = 10000;
    let mut rig = BeaconChainHarness::new(ChainSpec::foundation(), validator_count);

    let epoch_depth = rig.spec.epoch_length * 2;

    for _ in 0..(epoch_depth - 1) {
        rig.advance_chain_with_block();
    }

    let state = rig.beacon_chain.state.read().clone();

    assert_eq!((state.slot + 1) % rig.spec.epoch_length, 0);

    c.bench(
        "routines",
        Benchmark::new("routine_1", move |b| {
            let state = state.clone();
            b.iter(|| {
                let mut state = state.clone();
                black_box(black_box(
                    state.per_slot_processing(Hash256::zero(), &rig.spec),
                ))
            })
        })
        .sample_size(5),
    );

    /*
    c.bench_function("mid-epoch state transition 10k validators", move |b| {
        let state = state.clone();
        b.iter(|| {
            let mut state = state.clone();
            black_box(black_box(
                state.per_slot_processing(Hash256::zero(), &rig.spec),
            ))
        })
    });
    */
}

criterion_group!(
    benches,
    // mid_epoch_state_transition,
    epoch_boundary_state_transition
);
criterion_main!(benches);
