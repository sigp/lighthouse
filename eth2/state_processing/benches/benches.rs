use criterion::Benchmark;
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};
use env_logger::{Builder, Env};
use types::test_utils::TestingBeaconStateBuilder;
use types::*;

mod bench_block_processing;
mod bench_epoch_processing;

pub const VALIDATOR_COUNT: usize = 300_032;

// `LOG_LEVEL == "debug"` gives logs, but they're very noisy and slow down benching.
pub const LOG_LEVEL: &str = "";

pub fn state_processing(c: &mut Criterion) {
    if LOG_LEVEL != "" {
        Builder::from_env(Env::default().default_filter_or(LOG_LEVEL)).init();
    }

    bench_epoch_processing::bench_epoch_processing_n_validators(c, VALIDATOR_COUNT);
    bench_block_processing::bench_block_processing_n_validators(c, VALIDATOR_COUNT);
}

criterion_group!(benches, state_processing);
criterion_main!(benches);
