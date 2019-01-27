use criterion::Criterion;
use criterion::{criterion_group, criterion_main};
use test_harness::BeaconChainHarness;
use types::ChainSpec;

fn mid_epoch_state_transition(c: &mut Criterion) {
    let validator_count = 2;
    let mut rig = BeaconChainHarness::new(ChainSpec::foundation(), validator_count);

    let two_and_half_epochs = (rig.spec.epoch_length * 2) + (rig.spec.epoch_length / 2);

    for _ in 0..two_and_half_epochs {
        rig.advance_chain_with_block();
    }

    let block = rig.advance_chain_without_block();
    let state = rig.beacon_chain.canonical_head().beacon_state.clone();

    c.bench_function("mid-epoch state transition 10k validators", move |b| {
        let block = block.clone();
        let state = state.clone();
        b.iter(|| {
            rig.beacon_chain
                .state_transition(state.clone(), &block.clone())
        })
    });
}

fn epoch_boundary_state_transition(c: &mut Criterion) {
    let validator_count = 10_000;
    let mut rig = BeaconChainHarness::new(ChainSpec::foundation(), validator_count);

    let three_epochs = rig.spec.epoch_length * 3;

    for _ in 0..(three_epochs - 1) {
        rig.advance_chain_with_block();
    }

    let state = rig.beacon_chain.canonical_head().beacon_state.clone();
    assert_eq!(
        state.slot % rig.spec.epoch_length,
        rig.spec.epoch_length - 1,
    );
    let block = rig.advance_chain_without_block();

    c.bench_function("epoch boundary state transition 10k validators", move |b| {
        let block = block.clone();
        let state = state.clone();
        b.iter(|| {
            let state = rig
                .beacon_chain
                .state_transition(state.clone(), &block.clone())
                .unwrap();
            assert_eq!(state.slot % rig.spec.epoch_length, 0);
        })
    });
}

criterion_group!(
    benches,
    mid_epoch_state_transition,
    epoch_boundary_state_transition
);
criterion_main!(benches);
