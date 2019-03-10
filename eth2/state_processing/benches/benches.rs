use criterion::{criterion_group, criterion_main};

mod block_processing_benches;
mod epoch_processing_benches;

criterion_group!(
    benches,
    epoch_processing_benches::epoch_processing_16k_validators,
    block_processing_benches::block_processing_16k_validators,
);
criterion_main!(benches);
