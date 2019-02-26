use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main};
// use env_logger::{Builder, Env};
use state_processing::SlotProcessable;
use types::{beacon_state::BeaconStateBuilder, ChainSpec, Hash256};

fn epoch_processing(c: &mut Criterion) {
    // Builder::from_env(Env::default().default_filter_or("debug")).init();

    let mut builder = BeaconStateBuilder::with_random_validators(8);
    builder.spec = ChainSpec::few_validators();

    builder.genesis().unwrap();
    builder.teleport_to_end_of_epoch(builder.spec.genesis_epoch + 4);

    let state = builder.build().unwrap();

    c.bench_function("epoch processing", move |b| {
        let spec = &builder.spec;
        b.iter_with_setup(
            || state.clone(),
            |mut state| black_box(state.per_slot_processing(Hash256::zero(), spec).unwrap()),
        )
    });
}

criterion_group!(benches, epoch_processing,);
criterion_main!(benches);
