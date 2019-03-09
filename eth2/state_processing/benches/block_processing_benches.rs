use benching_utils::{BeaconBlockBencher, BeaconStateBencher};
use criterion::Criterion;
use criterion::{black_box, Benchmark};
use state_processing::{
    per_block_processing,
    per_block_processing::{
        process_attestations, process_attester_slashings, process_deposits, process_eth1_data,
        process_exits, process_proposer_slashings, process_randao, process_transfers,
        verify_block_signature,
    },
};
use types::*;

/// Run the benchmarking suite on a foundation spec with 16,384 validators.
pub fn block_processing_16k_validators(c: &mut Criterion) {
    let spec = ChainSpec::foundation();

    let validator_count = 16_384;

    let (state, keypairs) = build_state(validator_count, &spec);
    let block = build_block(&state, &keypairs, &spec);

    bench_block_processing(
        c,
        &block,
        &state,
        &spec,
        &format!("{}_validators", validator_count),
    );
}

fn build_state(validator_count: usize, spec: &ChainSpec) -> (BeaconState, Vec<Keypair>) {
    let mut builder = BeaconStateBencher::new(validator_count, &spec);

    // Set the state to be just before an epoch transition.
    let target_slot = (spec.genesis_epoch + 4).end_slot(spec.slots_per_epoch);
    builder.teleport_to_slot(target_slot, &spec);

    // Builds all caches; benches will not contain shuffling/committee building times.
    builder.build_caches(&spec).unwrap();

    builder.build()
}

fn build_block(state: &BeaconState, keypairs: &[Keypair], spec: &ChainSpec) -> BeaconBlock {
    let mut builder = BeaconBlockBencher::new(spec);

    builder.set_slot(state.slot);

    let proposer_index = state.get_beacon_proposer_index(state.slot, spec).unwrap();
    let keypair = &keypairs[proposer_index];

    builder.set_randao_reveal(&keypair.sk, &state.fork, spec);

    builder.build(&keypair.sk, &state.fork, spec)
}

/// Run the detailed benchmarking suite on the given `BeaconState`.
///
/// `desc` will be added to the title of each bench.
fn bench_block_processing(
    c: &mut Criterion,
    initial_block: &BeaconBlock,
    initial_state: &BeaconState,
    initial_spec: &ChainSpec,
    desc: &str,
) {
    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("block_processing_{}", desc),
        Benchmark::new("verify_block_signature", move |b| {
            b.iter_with_setup(
                || state.clone(),
                |mut state| black_box(verify_block_signature(&mut state, &block, &spec).unwrap()),
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("block_processing_{}", desc),
        Benchmark::new("process_randao", move |b| {
            b.iter_with_setup(
                || state.clone(),
                |mut state| black_box(process_randao(&mut state, &block, &spec).unwrap()),
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    c.bench(
        &format!("block_processing_{}", desc),
        Benchmark::new("process_eth1_data", move |b| {
            b.iter_with_setup(
                || state.clone(),
                |mut state| black_box(process_eth1_data(&mut state, &block.eth1_data).unwrap()),
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("block_processing_{}", desc),
        Benchmark::new("process_proposer_slashings", move |b| {
            b.iter_with_setup(
                || state.clone(),
                |mut state| {
                    black_box(
                        process_proposer_slashings(
                            &mut state,
                            &block.body.proposer_slashings,
                            &spec,
                        )
                        .unwrap(),
                    )
                },
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("block_processing_{}", desc),
        Benchmark::new("process_attester_slashings", move |b| {
            b.iter_with_setup(
                || state.clone(),
                |mut state| {
                    black_box(
                        process_attester_slashings(
                            &mut state,
                            &block.body.attester_slashings,
                            &spec,
                        )
                        .unwrap(),
                    )
                },
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("block_processing_{}", desc),
        Benchmark::new("process_attestations", move |b| {
            b.iter_with_setup(
                || state.clone(),
                |mut state| {
                    black_box(
                        process_attestations(&mut state, &block.body.attestations, &spec).unwrap(),
                    )
                },
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("block_processing_{}", desc),
        Benchmark::new("process_deposits", move |b| {
            b.iter_with_setup(
                || state.clone(),
                |mut state| {
                    black_box(process_deposits(&mut state, &block.body.deposits, &spec).unwrap())
                },
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("block_processing_{}", desc),
        Benchmark::new("process_exits", move |b| {
            b.iter_with_setup(
                || state.clone(),
                |mut state| {
                    black_box(
                        process_exits(&mut state, &block.body.voluntary_exits, &spec).unwrap(),
                    )
                },
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("block_processing_{}", desc),
        Benchmark::new("process_transfers", move |b| {
            b.iter_with_setup(
                || state.clone(),
                |mut state| {
                    black_box(process_transfers(&mut state, &block.body.transfers, &spec).unwrap())
                },
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("block_processing_{}", desc),
        Benchmark::new("per_block_processing", move |b| {
            b.iter_with_setup(
                || state.clone(),
                |mut state| black_box(per_block_processing(&mut state, &block, &spec).unwrap()),
            )
        })
        .sample_size(10),
    );

    let mut state = initial_state.clone();
    state.drop_cache(RelativeEpoch::Previous);
    let spec = initial_spec.clone();
    c.bench(
        &format!("block_processing_{}", desc),
        Benchmark::new("build_previous_state_epoch_cache", move |b| {
            b.iter_with_setup(
                || state.clone(),
                |mut state| {
                    black_box(
                        state
                            .build_epoch_cache(RelativeEpoch::Previous, &spec)
                            .unwrap(),
                    )
                },
            )
        })
        .sample_size(10),
    );

    let mut state = initial_state.clone();
    state.drop_cache(RelativeEpoch::Current);
    let spec = initial_spec.clone();
    c.bench(
        &format!("block_processing_{}", desc),
        Benchmark::new("build_current_state_epoch_cache", move |b| {
            b.iter_with_setup(
                || state.clone(),
                |mut state| {
                    black_box(
                        state
                            .build_epoch_cache(RelativeEpoch::Current, &spec)
                            .unwrap(),
                    )
                },
            )
        })
        .sample_size(10),
    );
}
