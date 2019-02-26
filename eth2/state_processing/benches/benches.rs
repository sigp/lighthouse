use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main};
// use env_logger::{Builder, Env};
use state_processing::SlotProcessable;
use types::beacon_state::BeaconStateBuilder;
use types::*;

fn epoch_processing(c: &mut Criterion) {
    // Builder::from_env(Env::default().default_filter_or("debug")).init();

    let mut builder = BeaconStateBuilder::new(8);
    builder.spec = ChainSpec::few_validators();

    builder.build().unwrap();
    builder.teleport_to_end_of_epoch(builder.spec.genesis_epoch + 4);

    let mut state = builder.cloned_state();

    // Build all the caches so the following state does _not_ include the cache-building time.
    state
        .build_epoch_cache(RelativeEpoch::Previous, &builder.spec)
        .unwrap();
    state
        .build_epoch_cache(RelativeEpoch::Current, &builder.spec)
        .unwrap();
    state
        .build_epoch_cache(RelativeEpoch::Next, &builder.spec)
        .unwrap();

    let cached_state = state.clone();

    // Drop all the caches so the following state includes the cache-building time.
    state.drop_cache(RelativeEpoch::Previous);
    state.drop_cache(RelativeEpoch::Current);
    state.drop_cache(RelativeEpoch::Next);

    let cacheless_state = state;

    let spec_a = builder.spec.clone();
    let spec_b = builder.spec.clone();

    c.bench_function("epoch processing with pre-built caches", move |b| {
        b.iter_with_setup(
            || cached_state.clone(),
            |mut state| black_box(state.per_slot_processing(Hash256::zero(), &spec_a).unwrap()),
        )
    });

    c.bench_function("epoch processing without pre-built caches", move |b| {
        b.iter_with_setup(
            || cacheless_state.clone(),
            |mut state| black_box(state.per_slot_processing(Hash256::zero(), &spec_b).unwrap()),
        )
    });
}

criterion_group!(benches, epoch_processing,);
criterion_main!(benches);
