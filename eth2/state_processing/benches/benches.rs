use criterion::Benchmark;
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};
use types::test_utils::TestingBeaconStateBuilder;
use types::*;

mod bench_block_processing;
mod bench_epoch_processing;

pub const VALIDATOR_COUNT: usize = 300_032;

pub fn state_processing(c: &mut Criterion) {
    bench_block_processing::bench_block_processing_n_validators(c, VALIDATOR_COUNT);
    bench_epoch_processing::bench_epoch_processing_n_validators(c, VALIDATOR_COUNT);
}

pub fn key_loading(c: &mut Criterion) {
    let validator_count = 1000;

    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new("generated", move |b| {
            b.iter_batched(
                || (),
                |_| {
                    TestingBeaconStateBuilder::from_deterministic_keypairs(
                        validator_count,
                        &ChainSpec::foundation(),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    // Note: path needs to be relative to where cargo is executed from.
    c.bench(
        &format!("{}_validators", validator_count),
        Benchmark::new("from_file", move |b| {
            b.iter_batched(
                || (),
                |_| {
                    TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(
                        validator_count,
                        &ChainSpec::foundation(),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );
}

// criterion_group!(benches, state_processing, key_loading);
criterion_group!(benches, key_loading);
criterion_main!(benches);
