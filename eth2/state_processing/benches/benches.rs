use criterion::Criterion;
use criterion::{criterion_group, criterion_main};

mod block_processing_benches;
mod epoch_processing_benches;

pub const VALIDATOR_COUNT: usize = 300_032;

pub fn state_processing(c: &mut Criterion) {
    block_processing_benches::bench_block_processing_n_validators(c, VALIDATOR_COUNT);
    epoch_processing_benches::bench_epoch_processing_n_validators(c, VALIDATOR_COUNT);
}

criterion_group!(benches, state_processing,);
criterion_main!(benches);
