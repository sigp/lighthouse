use criterion::{criterion_group, criterion_main};

mod epoch_processing_benches;

use epoch_processing_benches::epoch_processing_16k_validators;

criterion_group!(benches, epoch_processing_16k_validators);
criterion_main!(benches);
