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
use tree_hash::TreeHash;
use types::*;

/// Run the detailed benchmarking suite on the given `BeaconState`.
///
/// `desc` will be added to the title of each bench.
pub fn bench_block_processing(
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
        &format!("{}/block_processing", desc),
        Benchmark::new("verify_block_signature", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    verify_block_signature(&mut state, &block, &spec).unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("process_randao", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    process_randao(&mut state, &block, &spec).unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("process_eth1_data", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    process_eth1_data(&mut state, &block.eth1_data).unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("process_proposer_slashings", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    process_proposer_slashings(&mut state, &block.body.proposer_slashings, &spec)
                        .unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("process_attester_slashings", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    process_attester_slashings(&mut state, &block.body.attester_slashings, &spec)
                        .unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("process_attestations", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    process_attestations(&mut state, &block.body.attestations, &spec).unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("process_deposits", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    process_deposits(&mut state, &block.body.deposits, &spec).unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("process_exits", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    process_exits(&mut state, &block.body.voluntary_exits, &spec).unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("process_transfers", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    process_transfers(&mut state, &block.body.transfers, &spec).unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let state = initial_state.clone();
    let block = initial_block.clone();
    let spec = initial_spec.clone();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("per_block_processing", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    per_block_processing(&mut state, &block, &spec).unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let mut state = initial_state.clone();
    state.drop_cache(RelativeEpoch::Previous);
    let spec = initial_spec.clone();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("build_previous_state_epoch_cache", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    state
                        .build_epoch_cache(RelativeEpoch::Previous, &spec)
                        .unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let mut state = initial_state.clone();
    state.drop_cache(RelativeEpoch::Current);
    let spec = initial_spec.clone();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("build_current_state_epoch_cache", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    state
                        .build_epoch_cache(RelativeEpoch::Current, &spec)
                        .unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let mut state = initial_state.clone();
    state.drop_pubkey_cache();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("build_pubkey_cache", move |b| {
            b.iter_batched(
                || state.clone(),
                |mut state| {
                    state.update_pubkey_cache().unwrap();
                    state
                },
                criterion::BatchSize::SmallInput,
            )
        })
        .sample_size(10),
    );

    let block = initial_block.clone();
    c.bench(
        &format!("{}/block_processing", desc),
        Benchmark::new("tree_hash_block", move |b| {
            b.iter(|| black_box(block.tree_hash_root()))
        })
        .sample_size(10),
    );
}
