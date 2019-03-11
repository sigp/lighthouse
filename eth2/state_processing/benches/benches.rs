use criterion::Criterion;
use criterion::{criterion_group, criterion_main};

mod bench_block_processing;
mod bench_epoch_processing;

pub const VALIDATOR_COUNT: usize = 300_032;

pub fn state_processing(c: &mut Criterion) {
    bench_block_processing::bench_block_processing_n_validators(c, VALIDATOR_COUNT);
    bench_epoch_processing::bench_epoch_processing_n_validators(c, VALIDATOR_COUNT);
}

criterion_group!(benches, state_processing,);
criterion_main!(benches);
