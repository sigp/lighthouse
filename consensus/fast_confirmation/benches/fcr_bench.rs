//! Benchmarks for the Fast Confirmation Rule (FCR).
//!
//! Measures performance of the core FCR algorithms at various validator set sizes
//! using a synthetic linear chain built via `ProtoArrayForkChoice`.

use std::collections::BTreeSet;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use fast_confirmation::{BalanceSourceData, CheckpointAndBalance, FastConfirmationRule};
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
        None, // execution_payload_parent_hash
        None, // execution_payload_block_hash
        0,    // proposer_index
        &spec,
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
            execution_payload_parent_hash: None,
            execution_payload_block_hash: None,
            proposer_index: Some(0),
            payload_received: false,
        };

        fc.process_block::<E>(block, slot, &spec, Duration::from_secs(0))
            .expect("process block");

        block_roots.push(root);
    }

    let head_root = *block_roots.last().unwrap();
    let current_slot = Slot::new(NUM_BLOCKS as u64);

    // Model mainnet: each validator last attested in a different recent slot, so
    // validators vote for different recent block roots, scattered by validator index.
    // This defeats a single-entry vote-root cache (the realistic case), unlike an
    // all-vote-for-head scenario which is the trivial best case.
    let voteable = &block_roots[1..]; // non-genesis blocks
    for val_idx in 0..num_validators {
        let voted = voteable[val_idx % voteable.len()];
        fc.process_attestation(val_idx, voted, Slot::new(0), false)
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
        dependent_root: justified_checkpoint.root,
        total_active_balance,
        effective_balances: vec![BALANCE; num_validators],
        slashed: vec![false; num_validators],
    };

    // Build FCR state. `new` builds head assignments/balances from the state; the bench overwrites
    // balances below, so a committee-cache-ready empty state suffices.
    let unrealized_justified_checkpoint = justified_checkpoint;
    let mut seed_state = BeaconState::<E>::new(0, Default::default(), &spec);
    for relative_epoch in [
        RelativeEpoch::Previous,
        RelativeEpoch::Current,
        RelativeEpoch::Next,
    ] {
        seed_state
            .build_committee_cache(relative_epoch, &spec)
            .expect("committee cache");
    }
    let mut fcr = FastConfirmationRule::new(finalized_checkpoint, &seed_state, 25, 40)
        .expect("fcr initialization");
    fcr.previous_slot_head = head_root;
    fcr.current_slot_head = head_root;
    fcr.test_set_head_balance_source(balance_source.clone());
    fcr.current_epoch_observed_justified =
        CheckpointAndBalance::new(justified_checkpoint, balance_source.clone());
    fcr.previous_epoch_observed_justified =
        CheckpointAndBalance::new(justified_checkpoint, balance_source.clone());

    BenchData {
        proto_array,
        votes,
        balance_source,
        fcr,
        head_root,
        finalized_checkpoint,
        unrealized_justified_checkpoint,
        current_slot,
        equivocating_indices: BTreeSet::new(),
        block_roots,
    }
}

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// FFG scoring function: counts target checkpoint support.
fn bench_get_current_target_score(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_current_target_score");

    for &n in &[64, 16_000, 100_000, 500_000, 1_000_000] {
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

    for &n in &[64, 16_000, 100_000, 500_000, 1_000_000] {
        let data = build_chain(n);
        let genesis_root = data.block_roots[0];
        // `block_roots[1..]` is exactly `get_ancestor_roots(head, genesis)` for this linear chain.
        let terminal_slot = data
            .proto_array
            .block_slot(genesis_root)
            .expect("genesis in proto array");

        if n >= 100_000 {
            group.sample_size(10);
        }

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                fast_confirmation::optimizations::precompute_chain_attestation_scores(
                    &data.proto_array,
                    &data.block_roots[1..],
                    terminal_slot,
                    &data.balance_source,
                    &data.votes,
                    &data.equivocating_indices,
                )
            })
        });
    }
    group.finish();
}

/// Full confirmation algorithm: the complete production code path.
fn bench_get_latest_confirmed(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_latest_confirmed");

    for &n in &[64, 16_000, 100_000, 500_000, 1_000_000] {
        let data = build_chain(n);

        if n >= 100_000 {
            group.sample_size(10);
        }

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                data.fcr.get_latest_confirmed::<E>(
                    data.head_root,
                    &data.finalized_checkpoint,
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
    bench_get_current_target_score,
    bench_precompute_chain_scores,
    bench_get_latest_confirmed,
);
criterion_main!(benches);
