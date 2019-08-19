#[macro_use]
extern crate lazy_static;
extern crate env_logger;

use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main, Benchmark};
use state_processing::{test_utils::BlockBuilder, SignatureStrategy};
use types::{EthSpec, MainnetEthSpec, MinimalEthSpec, Slot, Unsigned};

const VALIDATOR_COUNT: usize = 300_032;

lazy_static! {}

fn bench_suite<T: EthSpec>(c: &mut Criterion, spec_desc: &str) {
    let spec = T::default_spec();
    let mut builder: BlockBuilder<T> = BlockBuilder::new(VALIDATOR_COUNT, &spec);
    // builder.num_attestations = T::MaxAttestations::to_usize();
    builder.num_attestations = 16;
    builder.set_slot(Slot::from(T::slots_per_epoch() * 3 - 2));
    builder.build_caches(&spec);
    let (block, state) = builder.build(&spec);

    let local_block = block.clone();
    let local_state = state.clone();
    let local_spec = spec.clone();
    c.bench(
        &format!("{}/{}_validators", spec_desc, VALIDATOR_COUNT),
        Benchmark::new("per_block_processing", move |b| {
            b.iter_batched_ref(
                || (local_spec.clone(), local_state.clone(), local_block.clone()),
                |(spec, ref mut state, block)| {
                    black_box(
                        state_processing::per_block_processing::<T>(
                            state,
                            &block,
                            SignatureStrategy::VerifyIndividual,
                            &spec,
                        )
                        .expect("block processing should succeed"),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let local_block = block.clone();
    let local_state = state.clone();
    let local_spec = spec.clone();
    c.bench(
        &format!("{}/{}_validators", spec_desc, VALIDATOR_COUNT),
        Benchmark::new("process_block_header", move |b| {
            b.iter_batched_ref(
                || (local_spec.clone(), local_state.clone(), local_block.clone()),
                |(spec, ref mut state, block)| {
                    black_box(
                        state_processing::per_block_processing::process_block_header::<T>(
                            state,
                            &block,
                            SignatureStrategy::VerifyIndividual,
                            &spec,
                        )
                        .expect("process_block_header should succeed"),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let local_block = block.clone();
    let local_state = state.clone();
    let local_spec = spec.clone();
    c.bench(
        &format!("{}/{}_validators", spec_desc, VALIDATOR_COUNT),
        Benchmark::new("verify_block_signature", move |b| {
            b.iter_batched_ref(
                || (local_spec.clone(), local_state.clone(), local_block.clone()),
                |(spec, ref mut state, block)| {
                    black_box(
                        state_processing::per_block_processing::verify_block_signature::<T>(
                            state, &block, &spec,
                        )
                        .expect("verify_block_signature should succeed"),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let local_block = block.clone();
    let local_state = state.clone();
    let local_spec = spec.clone();
    c.bench(
        &format!("{}/{}_validators", spec_desc, VALIDATOR_COUNT),
        Benchmark::new("process_attestations", move |b| {
            b.iter_batched_ref(
                || (local_spec.clone(), local_state.clone(), local_block.clone()),
                |(spec, ref mut state, block)| {
                    black_box(
                        state_processing::per_block_processing::process_attestations::<T>(
                            state,
                            &block.body.attestations,
                            &spec,
                        )
                        .expect("attestation processing should succeed"),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let local_block = block.clone();
    let local_state = state.clone();
    let local_spec = spec.clone();
    c.bench(
        &format!("{}/{}_validators", spec_desc, VALIDATOR_COUNT),
        Benchmark::new("verify_attestation", move |b| {
            b.iter_batched_ref(
                || {
                    let attestation = &local_block.body.attestations[0];

                    (local_spec.clone(), local_state.clone(), attestation.clone())
                },
                |(spec, ref mut state, attestation)| {
                    black_box(
                        state_processing::per_block_processing::verify_attestation(
                            state,
                            &attestation,
                            spec,
                        )
                        .expect("should verify attestation"),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let local_block = block.clone();
    let local_state = state.clone();
    c.bench(
        &format!("{}/{}_validators", spec_desc, VALIDATOR_COUNT),
        Benchmark::new("get_indexed_attestation", move |b| {
            b.iter_batched_ref(
                || {
                    let attestation = &local_block.body.attestations[0];

                    (local_state.clone(), attestation.clone())
                },
                |(ref mut state, attestation)| {
                    black_box(
                        state_processing::common::get_indexed_attestation(state, &attestation)
                            .expect("should get indexed attestation"),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let local_block = block.clone();
    let local_state = state.clone();
    let local_spec = spec.clone();
    c.bench(
        &format!("{}/{}_validators", spec_desc, VALIDATOR_COUNT),
        Benchmark::new("is_valid_indexed_attestation_with_signature", move |b| {
            b.iter_batched_ref(
                || {
                    let attestation = &local_block.body.attestations[0];
                    let indexed_attestation = state_processing::common::get_indexed_attestation(
                        &local_state,
                        &attestation,
                    )
                    .expect("should get indexed attestation");

                    (
                        local_spec.clone(),
                        local_state.clone(),
                        indexed_attestation.clone(),
                    )
                },
                |(spec, ref mut state, indexed_attestation)| {
                    black_box(
                        state_processing::per_block_processing::is_valid_indexed_attestation(
                            state,
                            &indexed_attestation,
                            spec,
                        )
                        .expect("should run is_valid_indexed_attestation"),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let local_block = block.clone();
    let local_state = state.clone();
    let local_spec = spec.clone();
    c.bench(
        &format!("{}/{}_validators", spec_desc, VALIDATOR_COUNT),
        Benchmark::new("is_valid_indexed_attestation_without_signature", move |b| {
            b.iter_batched_ref(
                || {
                    let attestation = &local_block.body.attestations[0];
                    let indexed_attestation = state_processing::common::get_indexed_attestation(
                        &local_state,
                        &attestation,
                    )
                    .expect("should get indexed attestation");

                    (
                        local_spec.clone(),
                        local_state.clone(),
                        indexed_attestation.clone(),
                    )
                },
                |(spec, ref mut state, indexed_attestation)| {
                    black_box(
                        state_processing::per_block_processing::is_valid_indexed_attestation_without_signature(
                            state,
                            &indexed_attestation,
                            spec,
                        )
                        .expect("should run is_valid_indexed_attestation_without_signature"),
                    )
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let local_block = block.clone();
    let local_state = state.clone();
    c.bench(
        &format!("{}/{}_validators", spec_desc, VALIDATOR_COUNT),
        Benchmark::new("get_attesting_indices", move |b| {
            b.iter_batched_ref(
                || {
                    let attestation = &local_block.body.attestations[0];

                    (local_state.clone(), attestation.clone())
                },
                |(ref mut state, attestation)| {
                    black_box(state_processing::common::get_attesting_indices(
                        state,
                        &attestation.data,
                        &attestation.aggregation_bits,
                    ))
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );
}

fn all_benches(c: &mut Criterion) {
    env_logger::init();

    // bench_suite::<MinimalEthSpec>(c, "minimal");
    bench_suite::<MainnetEthSpec>(c, "mainnet");
}

criterion_group!(benches, all_benches,);
criterion_main!(benches);
