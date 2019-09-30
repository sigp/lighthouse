extern crate env_logger;

use criterion::Criterion;
use criterion::{black_box, criterion_group, criterion_main, Benchmark};
use ssz::Encode;
use state_processing::{test_utils::BlockBuilder, BlockSignatureStrategy, VerifySignatures};
use types::{BeaconBlock, BeaconState, ChainSpec, EthSpec, MainnetEthSpec, MinimalEthSpec, Slot};

pub const VALIDATORS_LOW: usize = 32_768;
pub const VALIDATORS_HIGH: usize = 300_032;

fn all_benches(c: &mut Criterion) {
    env_logger::init();

    average_bench::<MinimalEthSpec>(c, "minimal", VALIDATORS_LOW);
    average_bench::<MainnetEthSpec>(c, "mainnet", VALIDATORS_LOW);
    average_bench::<MainnetEthSpec>(c, "mainnet", VALIDATORS_HIGH);

    worst_bench::<MinimalEthSpec>(c, "minimal", VALIDATORS_LOW);
    worst_bench::<MainnetEthSpec>(c, "mainnet", VALIDATORS_LOW);
    worst_bench::<MainnetEthSpec>(c, "mainnet", VALIDATORS_HIGH);
}

/// Run a bench with a average complexity block.
fn average_bench<T: EthSpec>(c: &mut Criterion, spec_desc: &str, validator_count: usize) {
    let spec = &T::default_spec();

    let (block, state) = get_average_block(validator_count, spec);
    bench_block::<T>(c, block, state, spec, spec_desc, "average_complexity_block");
}

/// Run a bench with a highly complex block.
fn worst_bench<T: EthSpec>(c: &mut Criterion, spec_desc: &str, validator_count: usize) {
    let mut spec = &mut T::default_spec();

    // Allows the exits to be processed sucessfully.
    spec.persistent_committee_period = 0;

    let (block, state) = get_worst_block(validator_count, spec);
    bench_block::<T>(c, block, state, spec, spec_desc, "high_complexity_block");
}

/// Return a block and state where the block has "average" complexity. I.e., the number of
/// operations we'd generally expect to see.
fn get_average_block<T: EthSpec>(
    validator_count: usize,
    spec: &ChainSpec,
) -> (BeaconBlock<T>, BeaconState<T>) {
    let mut builder: BlockBuilder<T> = BlockBuilder::new(validator_count, &spec);
    // builder.num_attestations = T::MaxAttestations::to_usize();
    builder.num_attestations = 16;
    builder.set_slot(Slot::from(T::slots_per_epoch() * 3 - 2));
    builder.build_caches(&spec);
    builder.build(&spec)
}

/// Return a block and state where the block has the "worst" complexity. The block is not
/// _guaranteed_ to be the worst possible complexity, it just has the max possible operations.
fn get_worst_block<T: EthSpec>(
    validator_count: usize,
    spec: &ChainSpec,
) -> (BeaconBlock<T>, BeaconState<T>) {
    let mut builder: BlockBuilder<T> = BlockBuilder::new(validator_count, &spec);
    builder.maximize_block_operations();

    // FIXME: enable deposits once we can generate them with valid proofs.
    builder.num_deposits = 0;

    builder.set_slot(Slot::from(T::slots_per_epoch() * 3 - 2));
    builder.build_caches(&spec);
    builder.build(&spec)
}

#[allow(clippy::unit_arg)]
fn bench_block<T: EthSpec>(
    c: &mut Criterion,
    block: BeaconBlock<T>,
    state: BeaconState<T>,
    spec: &ChainSpec,
    spec_desc: &str,
    block_desc: &str,
) {
    let validator_count = state.validators.len();

    let title = &format!(
        "{}/{}_validators/{}",
        spec_desc, validator_count, block_desc
    );

    let local_block = block.clone();
    let local_state = state.clone();
    let local_spec = spec.clone();
    c.bench(
        &title,
        Benchmark::new(
            "per_block_processing/individual_signature_verification",
            move |b| {
                b.iter_batched_ref(
                    || (local_spec.clone(), local_state.clone(), local_block.clone()),
                    |(spec, ref mut state, block)| {
                        black_box(
                            state_processing::per_block_processing::<T>(
                                state,
                                &block,
                                None,
                                BlockSignatureStrategy::VerifyIndividual,
                                &spec,
                            )
                            .expect("block processing should succeed"),
                        )
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        )
        .sample_size(10),
    );

    let local_block = block.clone();
    let local_state = state.clone();
    let local_spec = spec.clone();
    c.bench(
        &title,
        Benchmark::new(
            "per_block_processing/bulk_signature_verification",
            move |b| {
                b.iter_batched_ref(
                    || (local_spec.clone(), local_state.clone(), local_block.clone()),
                    |(spec, ref mut state, block)| {
                        black_box(
                            state_processing::per_block_processing::<T>(
                                state,
                                &block,
                                None,
                                BlockSignatureStrategy::VerifyBulk,
                                &spec,
                            )
                            .expect("block processing should succeed"),
                        )
                    },
                    criterion::BatchSize::SmallInput,
                )
            },
        )
        .sample_size(10),
    );

    let local_block = block.clone();
    let local_state = state.clone();
    let local_spec = spec.clone();
    c.bench(
        &title,
        Benchmark::new("per_block_processing/no_signature_verification", move |b| {
            b.iter_batched_ref(
                || (local_spec.clone(), local_state.clone(), local_block.clone()),
                |(spec, ref mut state, block)| {
                    black_box(
                        state_processing::per_block_processing::<T>(
                            state,
                            &block,
                            None,
                            BlockSignatureStrategy::NoVerification,
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
        &title,
        Benchmark::new("process_block_header", move |b| {
            b.iter_batched_ref(
                || (local_spec.clone(), local_state.clone(), local_block.clone()),
                |(spec, ref mut state, block)| {
                    black_box(
                        state_processing::per_block_processing::process_block_header::<T>(
                            state,
                            &block,
                            None,
                            VerifySignatures::True,
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
        &title,
        Benchmark::new("verify_block_signature", move |b| {
            b.iter_batched_ref(
                || (local_spec.clone(), local_state.clone(), local_block.clone()),
                |(spec, ref mut state, block)| {
                    black_box(
                        state_processing::per_block_processing::verify_block_signature::<T>(
                            state, &block, None, &spec,
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
        &title,
        Benchmark::new("process_attestations", move |b| {
            b.iter_batched_ref(
                || (local_spec.clone(), local_state.clone(), local_block.clone()),
                |(spec, ref mut state, block)| {
                    black_box(
                        state_processing::per_block_processing::process_attestations::<T>(
                            state,
                            &block.body.attestations,
                            VerifySignatures::True,
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
        &title,
        Benchmark::new("verify_attestation", move |b| {
            b.iter_batched_ref(
                || {
                    let attestation = &local_block.body.attestations[0];

                    (local_spec.clone(), local_state.clone(), attestation.clone())
                },
                |(spec, ref mut state, attestation)| {
                    black_box(
                        state_processing::per_block_processing::verify_attestation_for_block_inclusion(
                            state,
                            &attestation,
                            VerifySignatures::True,
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
        &title,
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
        &title,
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
                            VerifySignatures::True,
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
        &title,
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
                        state_processing::per_block_processing::is_valid_indexed_attestation(
                            state,
                            &indexed_attestation,
                            VerifySignatures::False,
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
        &title,
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

    let local_block = block.clone();
    c.bench(
        &title,
        Benchmark::new("ssz_serialize_block", move |b| {
            b.iter_batched_ref(
                || (),
                |_| black_box(local_block.as_ssz_bytes()),
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let local_block = block.clone();
    c.bench(
        &title,
        Benchmark::new("ssz_block_len", move |b| {
            b.iter_batched_ref(
                || (),
                |_| black_box(local_block.ssz_bytes_len()),
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );
}

criterion_group!(benches, all_benches,);
criterion_main!(benches);
