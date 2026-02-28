//! Benchmarks for the Fast Confirmation Rule (FCR).
//!
//! Measures performance of the core FCR algorithms at various validator set sizes
//! using a synthetic linear chain built via `ProtoArrayForkChoice`.

use std::collections::BTreeSet;

use beacon_chain::fast_confirmation::{BalanceSourceData, FastConfirmationRule};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fixed_bytes::FixedBytesExtended;
use proto_array::core::{ProtoArray, VoteTracker};
use proto_array::{Block, ExecutionStatus, JustifiedBalances, ProtoArrayForkChoice};
use types::*;

type E = MainnetEthSpec;

const GWEI_PER_ETH: u64 = 1_000_000_000;
const BALANCE: u64 = 32 * GWEI_PER_ETH;
/// Number of blocks in the linear chain (genesis + 9 more).
const NUM_BLOCKS: usize = 10;

/// All data needed to run an FCR benchmark iteration.
struct BenchData {
    proto_array: ProtoArray,
    votes: Vec<VoteTracker>,
    balance_source: BalanceSourceData,
    fcr: FastConfirmationRule,
    head_root: Hash256,
    finalized_checkpoint: Checkpoint,
    justified_checkpoint: Checkpoint,
    unrealized_justified_checkpoint: Checkpoint,
    current_slot: Slot,
    equivocating_indices: BTreeSet<u64>,
    block_roots: Vec<Hash256>,
}

/// Build a synthetic linear chain with `num_validators` all voting for the head.
///
/// Chain layout (all in epoch 0 for MainnetEthSpec):
///   genesis(slot 0) → block_1(slot 1) → ... → block_9(slot 9)
///   current_slot = 10
///   finalized = justified = genesis
///   All validators vote for head (slot 9)
fn build_chain(num_validators: usize) -> BenchData {
    let spec = E::default_spec();
    let genesis_root = Hash256::from_low_u64_be(1);

    let finalized_checkpoint = Checkpoint {
        epoch: Epoch::new(0),
        root: genesis_root,
    };
    let justified_checkpoint = finalized_checkpoint;

    let shuffling_id = AttestationShufflingId::from_components(Epoch::new(0), genesis_root);

    let mut fc = ProtoArrayForkChoice::new::<E>(
        Slot::new(0),    // current_slot
        Slot::new(0),    // finalized_block_slot
        Hash256::zero(), // finalized_block_state_root
        justified_checkpoint,
        finalized_checkpoint,
        shuffling_id.clone(),
        shuffling_id.clone(),
        ExecutionStatus::irrelevant(),
    )
    .expect("create fork choice");

    let mut block_roots = vec![genesis_root];

    // Add blocks at slots 1 through NUM_BLOCKS-1.
    for i in 1..NUM_BLOCKS {
        let root = Hash256::from_low_u64_be((i + 1) as u64);
        let parent_root = block_roots[i - 1];
        let slot = Slot::new(i as u64);

        let block = Block {
            slot,
            root,
            parent_root: Some(parent_root),
            state_root: Hash256::zero(),
            target_root: genesis_root, // epoch 0 target
            current_epoch_shuffling_id: shuffling_id.clone(),
            next_epoch_shuffling_id: shuffling_id.clone(),
            justified_checkpoint,
            finalized_checkpoint,
            execution_status: ExecutionStatus::irrelevant(),
            unrealized_justified_checkpoint: Some(justified_checkpoint),
            unrealized_finalized_checkpoint: Some(finalized_checkpoint),
        };

        fc.process_block::<E>(block, slot, justified_checkpoint, finalized_checkpoint)
            .expect("process block");

        block_roots.push(root);
    }

    let head_root = *block_roots.last().unwrap();
    let current_slot = Slot::new(NUM_BLOCKS as u64);

    // All validators attest to the head.
    for val_idx in 0..num_validators {
        fc.process_attestation(val_idx, head_root, Epoch::new(0))
            .expect("process attestation");
    }

    // Materialize votes: find_head swaps next_root → current_root in VoteTrackers.
    let balances = JustifiedBalances::from_effective_balances(vec![BALANCE; num_validators])
        .expect("justified balances");

    fc.find_head::<E>(
        justified_checkpoint,
        finalized_checkpoint,
        &balances,
        Hash256::zero(), // no proposer boost
        &BTreeSet::new(),
        current_slot,
        &spec,
    )
    .expect("find head");

    // Extract proto_array and votes.
    let proto_array = fc.core_proto_array().clone();
    let votes = fc.votes().to_vec();

    // Build balance source.
    let total_active_balance = BALANCE.saturating_mul(num_validators as u64);
    let balance_source = BalanceSourceData {
        checkpoint: justified_checkpoint,
        total_active_balance,
        effective_balances: vec![BALANCE; num_validators],
    };

    // Build FCR state.
    let unrealized_justified_checkpoint = justified_checkpoint;
    let mut fcr = FastConfirmationRule::new(finalized_checkpoint, 25);
    fcr.previous_slot_head = head_root;
    fcr.current_slot_head = head_root;
    fcr.current_balance_source = balance_source.clone();
    fcr.previous_balance_source = balance_source.clone();
    fcr.current_epoch_observed_justified_checkpoint = justified_checkpoint;
    fcr.previous_epoch_observed_justified_checkpoint = justified_checkpoint;

    // Synthetic committee slot assignments: spread validators across the epoch.
    let spe = E::slots_per_epoch() as usize;
    let mut assignments = vec![Slot::new(0); num_validators * 2];
    for val_idx in 0..num_validators {
        assignments[val_idx * 2] = Slot::new((val_idx % spe) as u64);
        assignments[val_idx * 2 + 1] = Slot::new((val_idx % spe) as u64);
    }
    fcr.set_head_slot_assignments(assignments);

    BenchData {
        proto_array,
        votes,
        balance_source,
        fcr,
        head_root,
        finalized_checkpoint,
        justified_checkpoint,
        unrealized_justified_checkpoint,
        current_slot,
        equivocating_indices: BTreeSet::new(),
        block_roots,
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// The O(V × depth) bottleneck: counts support weight via ancestor walks.
fn bench_get_attestation_score(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_attestation_score");

    for &n in &[64, 16_000, 100_000, 500_000] {
        let data = build_chain(n);
        let block_root = data.block_roots[NUM_BLOCKS / 2];

        if n >= 100_000 {
            group.sample_size(10);
        }

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                data.fcr.get_attestation_score(
                    &data.balance_source,
                    block_root,
                    &data.proto_array,
                    &data.votes,
                    &data.equivocating_indices,
                )
            })
        });
    }
    group.finish();
}

/// The core safety predicate for a single block.
fn bench_is_one_confirmed(c: &mut Criterion) {
    let mut group = c.benchmark_group("is_one_confirmed");

    for &n in &[64, 16_000, 100_000, 500_000] {
        let data = build_chain(n);
        let block_root = data.block_roots[NUM_BLOCKS / 2];

        if n >= 100_000 {
            group.sample_size(10);
        }

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                data.fcr.is_one_confirmed::<E>(
                    &data.balance_source,
                    block_root,
                    data.current_slot,
                    &data.proto_array,
                    &data.votes,
                    &data.equivocating_indices,
                )
            })
        });
    }
    group.finish();
}

/// FFG scoring function: counts target checkpoint support.
fn bench_get_current_target_score(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_current_target_score");

    for &n in &[64, 16_000, 100_000, 500_000] {
        let data = build_chain(n);

        if n >= 100_000 {
            group.sample_size(10);
        }

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                data.fcr.get_current_target_score::<E>(
                    data.head_root,
                    data.current_slot,
                    &data.proto_array,
                    &data.votes,
                    &data.equivocating_indices,
                )
            })
        });
    }
    group.finish();
}

/// Batch precomputation of attestation scores for the full chain.
fn bench_precompute_chain_scores(c: &mut Criterion) {
    let mut group = c.benchmark_group("precompute_chain_scores");

    for &n in &[64, 16_000, 100_000, 500_000] {
        let data = build_chain(n);
        let genesis_root = data.block_roots[0];

        if n >= 100_000 {
            group.sample_size(10);
        }

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                data.fcr.precompute_chain_attestation_scores(
                    data.head_root,
                    genesis_root,
                    &data.balance_source,
                    &data.proto_array,
                    &data.votes,
                    &data.equivocating_indices,
                )
            })
        });
    }
    group.finish();
}

/// Full confirmation algorithm: walks the chain calling is_one_confirmed per block.
fn bench_get_latest_confirmed(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_latest_confirmed");

    for &n in &[64, 16_000, 100_000, 500_000] {
        let data = build_chain(n);

        if n >= 100_000 {
            group.sample_size(10);
        }

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                data.fcr.get_latest_confirmed::<E>(
                    data.head_root,
                    &data.finalized_checkpoint,
                    &data.justified_checkpoint,
                    &data.unrealized_justified_checkpoint,
                    data.current_slot,
                    &data.proto_array,
                    &data.votes,
                    &data.equivocating_indices,
                )
            })
        });
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_get_attestation_score,
    bench_is_one_confirmed,
    bench_get_current_target_score,
    bench_precompute_chain_scores,
    bench_get_latest_confirmed,
);
criterion_main!(benches);
