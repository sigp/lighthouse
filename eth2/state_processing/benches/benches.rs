use block_benching_builder::BlockBenchingBuilder;
use criterion::Criterion;
use criterion::{criterion_group, criterion_main};
use env_logger::{Builder, Env};
use log::info;
use types::*;

mod bench_block_processing;
mod bench_epoch_processing;
mod block_benching_builder;

pub const VALIDATOR_COUNT: usize = 16_384;

// `LOG_LEVEL == "info"` gives handy messages.
pub const LOG_LEVEL: &str = "info";

/// Build a worst-case block and benchmark processing it.
pub fn block_processing_worst_case(c: &mut Criterion) {
    if LOG_LEVEL != "" {
        Builder::from_env(Env::default().default_filter_or(LOG_LEVEL)).init();
    }
    info!(
        "Building worst case block bench with {} validators",
        VALIDATOR_COUNT
    );

    // Use the specifications from the Eth2.0 spec.
    let spec = ChainSpec::foundation();

    // Create a builder for configuring the block and state for benching.
    let mut bench_builder = BlockBenchingBuilder::new(VALIDATOR_COUNT, &spec);

    // Set the number of included operations to be maximum (e.g., `MAX_ATTESTATIONS`, etc.)
    bench_builder.maximize_block_operations(&spec);

    // Set the state and block to be in the last slot of the 4th epoch.
    let last_slot_of_epoch = (spec.genesis_epoch + 4).end_slot(T::slots_per_epoch());
    bench_builder.set_slot(last_slot_of_epoch, &spec);

    // Build all the state caches so the build times aren't included in the benches.
    bench_builder.build_caches(&spec);

    // Generate the block and state then run benches.
    let (block, state) = bench_builder.build(&spec);
    bench_block_processing::bench_block_processing(
        c,
        &block,
        &state,
        &spec,
        &format!("{}_validators/worst_case", VALIDATOR_COUNT),
    );
}

/// Build a reasonable-case block and benchmark processing it.
pub fn block_processing_reasonable_case(c: &mut Criterion) {
    info!(
        "Building reasonable case block bench with {} validators",
        VALIDATOR_COUNT
    );

    // Use the specifications from the Eth2.0 spec.
    let spec = ChainSpec::foundation();

    // Create a builder for configuring the block and state for benching.
    let mut bench_builder = BlockBenchingBuilder::new(VALIDATOR_COUNT, &spec);

    // Set the number of included operations to what we might expect normally.
    bench_builder.num_proposer_slashings = 0;
    bench_builder.num_attester_slashings = 0;
    bench_builder.num_attestations = (spec.shard_count / T::slots_per_epoch()) as usize;
    bench_builder.num_deposits = 2;
    bench_builder.num_exits = 2;
    bench_builder.num_transfers = 2;

    // Set the state and block to be in the last slot of the 4th epoch.
    let last_slot_of_epoch = (spec.genesis_epoch + 4).end_slot(T::slots_per_epoch());
    bench_builder.set_slot(last_slot_of_epoch, &spec);

    // Build all the state caches so the build times aren't included in the benches.
    bench_builder.build_caches(&spec);

    // Generate the block and state then run benches.
    let (block, state) = bench_builder.build(&spec);
    bench_block_processing::bench_block_processing(
        c,
        &block,
        &state,
        &spec,
        &format!("{}_validators/reasonable_case", VALIDATOR_COUNT),
    );
}

pub fn state_processing(c: &mut Criterion) {
    bench_epoch_processing::bench_epoch_processing_n_validators(c, VALIDATOR_COUNT);
}

criterion_group!(
    benches,
    block_processing_reasonable_case,
    block_processing_worst_case,
    state_processing
);
criterion_main!(benches);
