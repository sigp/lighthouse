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

    let (mut state, keypairs) = build_state(validator_count, &spec);
    let block = build_block(&mut state, &keypairs, &spec);

    assert_eq!(
        block.body.proposer_slashings.len(),
        spec.max_proposer_slashings as usize,
        "The block should have the maximum possible proposer slashings"
    );

    assert_eq!(
        block.body.attester_slashings.len(),
        spec.max_attester_slashings as usize,
        "The block should have the maximum possible attester slashings"
    );

    for attester_slashing in &block.body.attester_slashings {
        let len_1 = attester_slashing
            .slashable_attestation_1
            .validator_indices
            .len();
        let len_2 = attester_slashing
            .slashable_attestation_1
            .validator_indices
            .len();
        assert!(
            (len_1 == len_2) && (len_2 == spec.max_indices_per_slashable_vote as usize),
            "Each attester slashing should have the maximum possible validator indices"
        );
    }

    assert_eq!(
        block.body.attestations.len(),
        spec.max_attestations as usize,
        "The block should have the maximum possible attestations."
    );

    assert_eq!(
        block.body.deposits.len(),
        spec.max_deposits as usize,
        "The block should have the maximum possible deposits."
    );

    assert_eq!(
        block.body.voluntary_exits.len(),
        spec.max_voluntary_exits as usize,
        "The block should have the maximum possible voluntary exits."
    );

    assert_eq!(
        block.body.transfers.len(),
        spec.max_transfers as usize,
        "The block should have the maximum possible transfers."
    );

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

fn build_block(state: &mut BeaconState, keypairs: &[Keypair], spec: &ChainSpec) -> BeaconBlock {
    let mut builder = BeaconBlockBencher::new(spec);

    builder.set_slot(state.slot);

    let proposer_index = state.get_beacon_proposer_index(state.slot, spec).unwrap();
    let keypair = &keypairs[proposer_index];

    builder.set_randao_reveal(&keypair.sk, &state.fork, spec);

    // Used as a stream of validator indices for use in slashings, exits, etc.
    let mut validators_iter = (0..keypairs.len() as u64).into_iter();

    // Insert the maximum possible number of `ProposerSlashing` objects.
    for _ in 0..spec.max_proposer_slashings {
        let validator_index = validators_iter.next().expect("Insufficient validators.");

        builder.insert_proposer_slashing(
            validator_index,
            &keypairs[validator_index as usize].sk,
            &state.fork,
            spec,
        );
    }

    // Insert the maximum possible number of `AttesterSlashing` objects
    for _ in 0..spec.max_attester_slashings {
        let mut attesters: Vec<u64> = vec![];
        let mut secret_keys: Vec<&SecretKey> = vec![];

        for _ in 0..spec.max_indices_per_slashable_vote {
            let validator_index = validators_iter.next().expect("Insufficient validators.");

            attesters.push(validator_index);
            secret_keys.push(&keypairs[validator_index as usize].sk);
        }

        builder.insert_attester_slashing(&attesters, &secret_keys, &state.fork, spec);
    }

    // Insert the maximum possible number of `Attestation` objects.
    let all_secret_keys: Vec<&SecretKey> = keypairs.iter().map(|keypair| &keypair.sk).collect();
    builder
        .fill_with_attestations(state, &all_secret_keys, spec)
        .unwrap();

    // Insert the maximum possible number of `Deposit` objects.
    for i in 0..spec.max_deposits {
        builder.insert_deposit(32_000_000_000, state.deposit_index + i, spec);
    }

    // Insert the maximum possible number of `Exit` objects.
    for _ in 0..spec.max_voluntary_exits {
        let validator_index = validators_iter.next().expect("Insufficient validators.");

        builder.insert_exit(
            state,
            validator_index,
            &keypairs[validator_index as usize].sk,
            spec,
        );
    }

    // Insert the maximum possible number of `Transfer` objects.
    for _ in 0..spec.max_transfers {
        let validator_index = validators_iter.next().expect("Insufficient validators.");

        // Manually set the validator to be withdrawn.
        state.validator_registry[validator_index as usize].withdrawable_epoch =
            state.previous_epoch(spec);

        builder.insert_transfer(
            state,
            validator_index,
            validator_index,
            1,
            keypairs[validator_index as usize].clone(),
            spec,
        );
    }

    let mut block = builder.build(&keypair.sk, &state.fork, spec);

    // Set the eth1 data to be different from the state.
    block.eth1_data.block_hash = Hash256::from_slice(&vec![42; 32]);

    block
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
