use benching_utils::BeaconStateBencher;
use criterion::Criterion;
use criterion::{black_box, Benchmark};
use ssz::TreeHash;
use state_processing::{
    per_epoch_processing,
    per_epoch_processing::{
        calculate_active_validator_indices, calculate_attester_sets, clean_attestations,
        process_crosslinks, process_eth1_data, process_justification,
        process_rewards_and_penalities, process_validator_registry, update_active_tree_index_roots,
        update_latest_slashed_balances,
    },
};
use types::{validator_registry::get_active_validator_indices, *};

pub const BENCHING_SAMPLE_SIZE: usize = 100;
pub const SMALL_BENCHING_SAMPLE_SIZE: usize = 10;

/// Run the benchmarking suite on a foundation spec with 16,384 validators.
pub fn epoch_processing_16k_validators(c: &mut Criterion) {
    let spec = ChainSpec::foundation();

    let validator_count = 16_384;

    let mut builder = BeaconStateBencher::new(validator_count, &spec);

    // Set the state to be just before an epoch transition.
    let target_slot = (spec.genesis_epoch + 4).end_slot(spec.slots_per_epoch);
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
    let committees_per_slot = committees_per_epoch / spec.slots_per_epoch;
    let previous_epoch_attestations = committees_per_epoch;
    let current_epoch_attestations =
        committees_per_slot * (spec.slots_per_epoch - spec.min_attestation_inclusion_delay);
    assert_eq!(
        state.latest_attestations.len() as u64,
        previous_epoch_attestations + current_epoch_attestations,
        "The state should have an attestation for each committee."
    );

    // Assert that each attestation in the state has full participation.
    let committee_size = validator_count / committees_per_epoch as usize;
    for a in &state.latest_attestations {
        assert_eq!(
            a.aggregation_bitfield.num_set_bits(),
            committee_size,
            "Each attestation in the state should have full participation"
        );
    }

    // Assert that we will run the first arm of process_rewards_and_penalities
    let epochs_since_finality = state.next_epoch(&spec) - state.finalized_epoch;
    assert_eq!(
        epochs_since_finality, 4,
        "Epochs since finality should be 4"
    );

    bench_epoch_processing(c, &state, &spec, "16k_validators");
}

/// Run the detailed benchmarking suite on the given `BeaconState`.
///
/// `desc` will be added to the title of each bench.
fn bench_epoch_processing(c: &mut Criterion, state: &BeaconState, spec: &ChainSpec, desc: &str) {
    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("calculate_active_validator_indices", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |mut state| black_box(calculate_active_validator_indices(&mut state, &spec_clone)),
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    let active_validator_indices = calculate_active_validator_indices(&state, &spec);
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("calculate_current_total_balance", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |state| {
                    black_box(state.get_total_balance(&active_validator_indices[..], &spec_clone))
                },
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("calculate_previous_total_balance", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |state| {
                    black_box(state.get_total_balance(
                        &get_active_validator_indices(
                            &state.validator_registry,
                            state.previous_epoch(&spec_clone),
                        )[..],
                        &spec_clone,
                    ))
                },
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("process_eth1_data", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |mut state| black_box(process_eth1_data(&mut state, &spec_clone)),
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("calculate_attester_sets", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |mut state| black_box(calculate_attester_sets(&mut state, &spec_clone).unwrap()),
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    let previous_epoch = state.previous_epoch(&spec);
    let attesters = calculate_attester_sets(&state, &spec).unwrap();
    let active_validator_indices = calculate_active_validator_indices(&state, &spec);
    let current_total_balance = state.get_total_balance(&active_validator_indices[..], &spec);
    let previous_total_balance = state.get_total_balance(
        &get_active_validator_indices(&state.validator_registry, previous_epoch)[..],
        &spec,
    );
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("process_justification", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |mut state| {
                    black_box(process_justification(
                        &mut state,
                        current_total_balance,
                        previous_total_balance,
                        attesters.previous_epoch_boundary.balance,
                        attesters.current_epoch_boundary.balance,
                        &spec_clone,
                    ))
                },
            )
        })
        .sample_size(10),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("process_crosslinks", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |mut state| black_box(process_crosslinks(&mut state, &spec_clone).unwrap()),
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let mut state_clone = state.clone();
    let spec_clone = spec.clone();
    let previous_epoch = state.previous_epoch(&spec);
    let attesters = calculate_attester_sets(&state, &spec).unwrap();
    let active_validator_indices = calculate_active_validator_indices(&state, &spec);
    let previous_total_balance = state.get_total_balance(
        &get_active_validator_indices(&state.validator_registry, previous_epoch)[..],
        &spec,
    );
    let winning_root_for_shards = process_crosslinks(&mut state_clone, &spec).unwrap();
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("process_rewards_and_penalties", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |mut state| {
                    black_box(
                        process_rewards_and_penalities(
                            &mut state,
                            &active_validator_indices,
                            &attesters,
                            previous_total_balance,
                            &winning_root_for_shards,
                            &spec_clone,
                        )
                        .unwrap(),
                    )
                },
            )
        })
        .sample_size(SMALL_BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("process_ejections", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |mut state| black_box(state.process_ejections(&spec_clone)),
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let mut state_clone = state.clone();
    let spec_clone = spec.clone();
    let previous_epoch = state.previous_epoch(&spec);
    let attesters = calculate_attester_sets(&state, &spec).unwrap();
    let active_validator_indices = calculate_active_validator_indices(&state, &spec);
    let current_total_balance = state.get_total_balance(&active_validator_indices[..], spec);
    let previous_total_balance = state.get_total_balance(
        &get_active_validator_indices(&state.validator_registry, previous_epoch)[..],
        &spec,
    );
    assert_eq!(
        state_clone.finalized_epoch, state_clone.validator_registry_update_epoch,
        "The last registry update should be at the last finalized epoch."
    );
    process_justification(
        &mut state_clone,
        current_total_balance,
        previous_total_balance,
        attesters.previous_epoch_boundary.balance,
        attesters.current_epoch_boundary.balance,
        spec,
    );
    assert!(
        state_clone.finalized_epoch > state_clone.validator_registry_update_epoch,
        "The state should have been finalized."
    );
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("process_validator_registry", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |mut state| black_box(process_validator_registry(&mut state, &spec_clone)),
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("update_active_tree_index_roots", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |mut state| {
                    black_box(update_active_tree_index_roots(&mut state, &spec_clone).unwrap())
                },
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("update_latest_slashed_balances", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |mut state| black_box(update_latest_slashed_balances(&mut state, &spec_clone)),
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("clean_attestations", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |mut state| black_box(clean_attestations(&mut state, &spec_clone)),
            )
        })
        .sample_size(BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    let spec_clone = spec.clone();
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("per_epoch_processing", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |mut state| black_box(per_epoch_processing(&mut state, &spec_clone).unwrap()),
            )
        })
        .sample_size(SMALL_BENCHING_SAMPLE_SIZE),
    );

    let state_clone = state.clone();
    c.bench(
        &format!("epoch_process_with_caches_{}", desc),
        Benchmark::new("tree_hash_state", move |b| {
            b.iter_with_setup(
                || state_clone.clone(),
                |state| black_box(state.hash_tree_root()),
            )
        })
        .sample_size(SMALL_BENCHING_SAMPLE_SIZE),
    );
}
