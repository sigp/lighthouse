use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fixed_bytes::FixedBytesExtended;
use proto_array::{Block, ExecutionStatus, JustifiedBalances, ProtoArrayForkChoice};
use std::collections::BTreeSet;
use std::time::Duration;
use types::{
    AttestationShufflingId, Checkpoint, Epoch, EthSpec, ExecutionBlockHash, Hash256,
    MainnetEthSpec, Slot,
};

fn get_root(i: u64) -> Hash256 {
    Hash256::from_low_u64_be(i)
}

fn get_hash(i: u64) -> ExecutionBlockHash {
    ExecutionBlockHash::from_root(get_root(i))
}

/// Build a linear chain of `num_blocks` blocks.
fn build_chain(num_blocks: u64, gloas: bool) -> (ProtoArrayForkChoice, types::ChainSpec) {
    let mut spec = MainnetEthSpec::default_spec();
    let gloas_fork_slot = 32;
    if gloas {
        spec.gloas_fork_epoch = Some(Epoch::new(1));
    }

    let finalized_checkpoint = Checkpoint {
        epoch: Epoch::new(0),
        root: get_root(0),
    };
    let junk_shuffling_id = AttestationShufflingId::from_components(Epoch::new(0), Hash256::zero());

    let mut fork_choice = ProtoArrayForkChoice::new::<MainnetEthSpec>(
        Slot::new(0),
        Slot::new(0),
        Hash256::zero(),
        finalized_checkpoint,
        finalized_checkpoint,
        junk_shuffling_id.clone(),
        junk_shuffling_id.clone(),
        ExecutionStatus::Optimistic(ExecutionBlockHash::zero()),
        None,
        None,
        0,
        &spec,
    )
    .expect("should create fork choice");

    for i in 1..=num_blocks {
        let is_gloas = gloas && i >= gloas_fork_slot;
        let block = Block {
            slot: Slot::new(i),
            root: get_root(i),
            parent_root: Some(get_root(i - 1)),
            state_root: Hash256::zero(),
            target_root: get_root(0),
            current_epoch_shuffling_id: junk_shuffling_id.clone(),
            next_epoch_shuffling_id: junk_shuffling_id.clone(),
            justified_checkpoint: finalized_checkpoint,
            finalized_checkpoint,
            execution_status: ExecutionStatus::Optimistic(ExecutionBlockHash::zero()),
            unrealized_justified_checkpoint: Some(finalized_checkpoint),
            unrealized_finalized_checkpoint: Some(finalized_checkpoint),
            execution_payload_parent_hash: if is_gloas {
                Some(get_hash(i - 1))
            } else {
                None
            },
            execution_payload_block_hash: if is_gloas { Some(get_hash(i)) } else { None },
            proposer_index: Some(0),
        };

        fork_choice
            .process_block::<MainnetEthSpec>(block, Slot::new(i), &spec, Duration::ZERO)
            .expect("should process block");
    }

    (fork_choice, spec)
}

fn bench_find_head(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_head");
    let equivocating_indices = BTreeSet::new();
    let finalized_checkpoint = Checkpoint {
        epoch: Epoch::new(0),
        root: get_root(0),
    };
    let balances = JustifiedBalances::from_effective_balances(vec![1; 64]).unwrap();

    // 216k = ~1 month non-finality mainnet, 518k = ~1 month non-finality Gnosis.
    // Must survive extended non-finality (500k+ blocks).
    for (label, gloas) in [("pre_gloas", false), ("gloas", true)] {
        for &num_blocks in &[100, 1_000, 10_000, 50_000, 216_000, 518_000] {
            let (mut fork_choice, spec) = build_chain(num_blocks, gloas);

            group.bench_function(BenchmarkId::new(label, num_blocks), |b| {
                b.iter(|| {
                    fork_choice
                        .find_head::<MainnetEthSpec>(
                            finalized_checkpoint,
                            finalized_checkpoint,
                            &balances,
                            Hash256::zero(),
                            &equivocating_indices,
                            Slot::new(num_blocks),
                            &spec,
                        )
                        .expect("should find head")
                });
            });
        }
    }

    group.finish();
}

criterion_group!(benches, bench_find_head);
criterion_main!(benches);
