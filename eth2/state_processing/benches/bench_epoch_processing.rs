use criterion::Criterion;
use criterion::{black_box, Benchmark};
use state_processing::{
    per_epoch_processing,
    per_epoch_processing::{
        clean_attestations, initialize_validator_statuses, process_crosslinks, process_eth1_data,
        process_justification, process_rewards_and_penalities, process_validator_registry,
        update_active_tree_index_roots, update_latest_slashed_balances,
    },
};
use tree_hash::TreeHash;
use types::test_utils::TestingBeaconStateBuilder;
use types::*;

pub const BENCHING_SAMPLE_SIZE: usize = 10;
pub const SMALL_BENCHING_SAMPLE_SIZE: usize = 10;

/// Run the benchmarking suite on a foundation spec with 16,384 validators.
pub fn bench_epoch_processing_n_validators(c: &mut Criterion, validator_count: usize) {
    let spec = ChainSpec::mainnet();

    let mut builder =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(validator_count, &spec);

    // Set the state to be just before an epoch transition.
    let target_slot = (T::genesis_epoch() + 4).end_slot(T::slots_per_epoch());
    builder.teleport_to_slot(target_slot, &spec);

    // Builds all caches; benches will not contain shuffling/committee building times.
    builder.build_caches(&spec).unwrap();

    // Inserts one attestation with full participation for each committee able to include an
    // attestation in this state.
    builder.insert_attestations(&spec);

    let (state, _keypairs) = builder.build();

    // Assert that the state has an attestations for each committee that is able to include an
    // attestation in the state.
    let committees_per_epoch = spec.get_epoch_committee_count(validator_count);
    let committees_per_slot = committees_per_epoch / T::slots_per_epoch();
    let previous_epoch_attestations = committees_per_epoch;
    let current_epoch_attestations =
        committees_per_slot * (T::slots_per_epoch() - spec.min_attestation_inclusion_delay);
    assert_eq!(
        state.latest_attestations.len() as u64,
        previous_epoch_attestations + current_epoch_attestations,
        "The state should have an attestation for each committee."
    );

    // Assert that we will run the first arm of process_rewards_and_penalties
    let epochs_since_finality = state.next_epoch(&spec) - state.finalized_epoch;
    assert_eq!(
        epochs_since_finality, 4,
        "Epochs since finality should be 4"
    );

    bench_epoch_processing(c, &state, &spec, &format!("{}_validators", validator_count));
}

/// Run the detailed benchmarking suite on the given `BeaconState`.
///
/// `desc` will be added to the title of each bench.
fn bench_epoch_processing(c: &mut Criterion, state: &BeaconState, spec: &ChainSpec, desc: &str) {
    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("{}/epoch_processing", desc),
        Benchmark::new("process_eth1_data", move |b| {
            b.iter_batched(
                || state_clone.clone(),
                |mut state| {
                    process_eth1_data(&mut state, &spec_clone);
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("{}/epoch_processing", desc),
        Benchmark::new("initialize_validator_statuses", move |b| {
            b.iter_batched(
                || state_clone.clone(),
                |mut state| {
                    initialize_validator_statuses(&mut state, &spec_clone).unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    let attesters = initialize_validator_statuses(&state, &spec).unwrap();
    c.bench(
        &format!("{}/epoch_processing", desc),
        Benchmark::new("process_justification", move |b| {
            b.iter_batched(
                || state_clone.clone(),
                |mut state| {
                    process_justification(&mut state, &attesters.total_balances, &spec_clone);
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("{}/epoch_processing", desc),
        Benchmark::new("process_crosslinks", move |b| {
            b.iter_batched(
                || state_clone.clone(),
                |mut state| black_box(process_crosslinks(&mut state, &spec_clone).unwrap()),
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let mut state_clone = state.clone();
    let spec_clone = spec.clone();
    let attesters = initialize_validator_statuses(&state, &spec).unwrap();
    let winning_root_for_shards = process_crosslinks(&mut state_clone, &spec).unwrap();
    c.bench(
        &format!("{}/epoch_processing", desc),
        Benchmark::new("process_rewards_and_penalties", move |b| {
            b.iter_batched(
                || (state_clone.clone(), attesters.clone()),
                |(mut state, mut attesters)| {
                    process_rewards_and_penalities(
                        &mut state,
                        &mut attesters,
                        &winning_root_for_shards,
                        &spec_clone,
                    )
                    .unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(SMALL_BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("{}/epoch_processing", desc),
        Benchmark::new("process_ejections", move |b| {
            b.iter_batched(
                || state_clone.clone(),
                |mut state| {
                    state.process_ejections(&spec_clone);
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("{}/epoch_processing", desc),
        Benchmark::new("process_validator_registry", move |b| {
            b.iter_batched(
                || state_clone.clone(),
                |mut state| {
                    process_validator_registry(&mut state, &spec_clone).unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("{}/epoch_processing", desc),
        Benchmark::new("update_active_tree_index_roots", move |b| {
            b.iter_batched(
                || state_clone.clone(),
                |mut state| {
                    update_active_tree_index_roots(&mut state, &spec_clone).unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("{}/epoch_processing", desc),
        Benchmark::new("update_latest_slashed_balances", move |b| {
            b.iter_batched(
                || state_clone.clone(),
                |mut state| {
                    update_latest_slashed_balances(&mut state, &spec_clone);
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("{}/epoch_processing", desc),
        Benchmark::new("clean_attestations", move |b| {
            b.iter_batched(
                || state_clone.clone(),
                |mut state| {
                    clean_attestations(&mut state, &spec_clone);
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("{}/epoch_processing", desc),
        Benchmark::new("per_epoch_processing", move |b| {
            b.iter_batched(
                || state_clone.clone(),
                |mut state| black_box(per_epoch_processing(&mut state, &spec_clone).unwrap()),
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(SMALL_BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    c.bench(
        &format!("{}/epoch_processing", desc),
        Benchmark::new("tree_hash_state", move |b| {
            b.iter(|| black_box(state_clone.tree_hash_root()))
        })
        .sample_size(SMALL_BENCHING_SAMPLE_SIZE),
    );
}
