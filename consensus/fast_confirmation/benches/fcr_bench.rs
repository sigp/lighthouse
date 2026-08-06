//! Benchmarks for the Fast Confirmation Rule (FCR).
//!
//! Measures performance of the core FCR algorithms at various validator set sizes using a
//! synthetic linear chain built via `ProtoArrayForkChoice`.
//!
//! All benchmarks run on `MainnetEthSpec` (32 slots/epoch). The chain spans three epochs so the
//! FCR state machine has a real epoch boundary and a fully-populated previous epoch to act on.
//! `get_latest_confirmed` is measured across a table of realistic (chain position, FCR run slot)
//! scenarios — see `SCENARIOS`.

use std::collections::BTreeSet;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use ethereum_hashing::hash_fixed;
use fast_confirmation::{
    BalanceSourceData, BalanceSourceKey, CheckpointAndBalance, FastConfirmationRule,
};
use fixed_bytes::FixedBytesExtended;
use proto_array::core::{ProtoArray, VoteTracker};
use proto_array::{Block, ExecutionStatus, JustifiedBalances, ProtoArrayForkChoice};
use types::*;

type E = MainnetEthSpec;

const GWEI_PER_ETH: u64 = 1_000_000_000;
const BALANCE: u64 = 32 * GWEI_PER_ETH;

/// Linear chain spans slots 0..=CHAIN_TIP_SLOT, i.e. epochs 0, 1 and into epoch 2.
const CHAIN_TIP_SLOT: u64 = 69;
/// Epoch-1 boundary block; the FCR's current-epoch observed-justified checkpoint points here, so
/// every scenario below runs with `current_epoch == 2`.
const OBSERVED_JUSTIFIED_SLOT: u64 = 32;

/// A realistic FCR evaluation: where the chain head and last-confirmed block sit, and the
/// slot at which FCR runs. All scenarios sit in epoch 2 (current_epoch = 2).
struct Scenario {
    name: &'static str,
    head_slot: u64,
    current_slot: u64,
    confirmed_slot: u64,
}

/// Realistic spectrum, cheapest → most expensive. The FFG sweep (`get_current_target_score`) is
/// the dominant cost and only runs at a non-boundary slot while the confirmed block still lags in
/// the previous epoch.
const SCENARIOS: &[Scenario] = &[
    // Healthy steady state: head and confirmation both deep in the current epoch. Confirmed is in
    // the current epoch, so the FFG sweep is gated off and the precompute walk is short — the
    // common ~97% case.
    Scenario {
        name: "steady_mid_epoch",
        head_slot: 69,
        current_slot: 70,
        confirmed_slot: 66,
    },
    // First slot of the epoch: confirmation is still a full epoch behind, but the boundary slot
    // short-circuits the FFG sweep, so this runs the precompute + is_confirmed_chain_safe only.
    Scenario {
        name: "epoch_first_slot",
        head_slot: 63,
        current_slot: 64,
        confirmed_slot: 40,
    },
    // A couple slots into the epoch, confirmation catching up: the FFG sweep fires — the worst
    // case that occurs every epoch on a healthy network.
    Scenario {
        name: "epoch_catch_up",
        head_slot: 65,
        current_slot: 66,
        confirmed_slot: 40,
    },
    // First slots of the epoch missed (no current-epoch block yet, head still in the previous
    // epoch): the FFG-sweep window is extended several slots past the boundary.
    Scenario {
        name: "missed_epoch_start",
        head_slot: 63,
        current_slot: 68,
        confirmed_slot: 40,
    },
];

/// Deterministic, hash-like block root for a given slot.
///
/// Do not use `Hash256::from_low_u64_*` here: FCR's vote aggregation intentionally hashes on a
/// root-byte prefix, and low-u64 synthetic roots put all entropy at the end of the root.
fn block_root_at(slot: u64) -> Hash256 {
    let mut preimage = [0u8; 16];
    preimage[..8].copy_from_slice(b"fcr-root");
    preimage[8..].copy_from_slice(&(slot + 1).to_le_bytes());
    Hash256::from_slice(&hash_fixed(&preimage))
}

/// Shared chain + FCR state for a given validator-set size. The FCR's per-scenario fields
/// (confirmed root, slot heads) are set by `apply_scenario` before each measurement.
struct BenchData {
    proto_array: ProtoArray,
    votes: Vec<VoteTracker>,
    balance_source: BalanceSourceData,
    fcr: FastConfirmationRule,
    finalized_checkpoint: Checkpoint,
    unrealized_justified_checkpoint: Checkpoint,
    observed_justified_checkpoint: Checkpoint,
    genesis_checkpoint: Checkpoint,
    equivocating_indices: BTreeSet<u64>,
    block_roots: Vec<Hash256>,
}

impl BenchData {
    /// Point the FCR's confirmed root and head-tracking variables at a scenario's chain position.
    /// `get_latest_confirmed` is `&self`, so this is the only mutation and it happens between
    /// measurements.
    fn apply_scenario(&mut self, scenario: &Scenario) {
        let head_root = block_root_at(scenario.head_slot);
        self.fcr.previous_slot_head = head_root;
        self.fcr.current_slot_head = head_root;
        self.fcr.confirmed_root = block_root_at(scenario.confirmed_slot);
        self.fcr.current_epoch_observed_justified = CheckpointAndBalance::new(
            self.observed_justified_checkpoint,
            self.balance_source.clone(),
        );
        self.fcr.previous_epoch_observed_justified =
            CheckpointAndBalance::new(self.genesis_checkpoint, self.balance_source.clone());
    }
}

/// Build the synthetic chain (slots 0..=CHAIN_TIP_SLOT) with `num_validators` voting for scattered
/// recent blocks, plus an FCR seeded with the shared balances/checkpoints.
fn build_chain(num_validators: usize) -> BenchData {
    build_chain_inner(num_validators, E::slots_per_epoch() as usize, None)
}

/// `build_chain`, with `seed_validators` in the committee-cached seed state (so `is_in_range`
/// covers them) and an optional missed slot: block `gap_slot + 1` then parents to `gap_slot - 1`.
fn build_chain_inner(
    num_validators: usize,
    seed_validators: usize,
    gap_slot: Option<u64>,
) -> BenchData {
    let spec = E::default_spec();
    let genesis_root = block_root_at(0);

    let genesis_checkpoint = Checkpoint {
        epoch: Epoch::new(0),
        root: genesis_root,
    };
    let observed_justified_checkpoint = Checkpoint {
        epoch: Epoch::new(1),
        root: block_root_at(OBSERVED_JUSTIFIED_SLOT),
    };
    let finalized_checkpoint = genesis_checkpoint;
    let justified_checkpoint = genesis_checkpoint;

    let shuffling_id = AttestationShufflingId::from_components(Epoch::new(0), genesis_root);

    let mut fc = ProtoArrayForkChoice::new::<E>(
        Slot::new(0),    // current_slot
        Slot::new(0),    // finalized_block_slot
        Hash256::zero(), // finalized_block_state_root
        justified_checkpoint,
        finalized_checkpoint,
        shuffling_id.clone(),
        shuffling_id.clone(),
        ExecutionStatus::pre_merge(),
        None, // execution_payload_parent_hash
        None, // execution_payload_block_hash
        0,    // proposer_index
        &spec,
    )
    .expect("create fork choice");

    let mut block_roots = vec![genesis_root];

    for slot_u in 1..=CHAIN_TIP_SLOT {
        if Some(slot_u) == gap_slot {
            block_roots.push(block_roots[(slot_u - 1) as usize]);
            continue;
        }
        let slot = Slot::new(slot_u);
        let epoch = slot.epoch(E::slots_per_epoch());
        let root = block_root_at(slot_u);
        let parent_root = block_roots[(slot_u - 1) as usize];
        // Target is the block at the first slot of this block's epoch.
        let target_root = block_root_at(epoch.as_u64() * E::slots_per_epoch());
        // Epoch-0 blocks have nothing justified beyond genesis; later blocks see the epoch-1
        // boundary as unrealized-justified, matching the FCR's observed-justified checkpoint.
        let unrealized_justified_checkpoint = if epoch == Epoch::new(0) {
            genesis_checkpoint
        } else {
            observed_justified_checkpoint
        };

        let block = Block {
            slot,
            root,
            parent_root: Some(parent_root),
            state_root: Hash256::zero(),
            target_root,
            current_epoch_shuffling_id: shuffling_id.clone(),
            next_epoch_shuffling_id: shuffling_id.clone(),
            justified_checkpoint,
            finalized_checkpoint,
            execution_status: ExecutionStatus::pre_merge(),
            unrealized_justified_checkpoint: Some(unrealized_justified_checkpoint),
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

    // Model mainnet: each validator last attested in a different recent slot, so validators vote
    // for different recent block roots, scattered by validator index. This defeats a single-entry
    // vote-root cache (the realistic case), unlike an all-vote-for-head trivial best case.
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
        Slot::new(CHAIN_TIP_SLOT),
        &spec,
    )
    .expect("find head");

    let proto_array = fc.core_proto_array().clone();
    let votes = fc.votes().to_vec();

    let total_active_balance = BALANCE.saturating_mul(num_validators as u64);
    let balance_source = BalanceSourceData {
        key: BalanceSourceKey::NoSlashings {
            epoch_boundary_root: observed_justified_checkpoint.root,
            epoch: Slot::new(CHAIN_TIP_SLOT).epoch(E::slots_per_epoch()),
        },
        total_active_balance,
        effective_balances: vec![BALANCE; num_validators],
        slashed: vec![false; num_validators],
    };

    // `new` builds head assignments/balances from the state; the bench overwrites balances and
    // slot-tracking variables, so a small committee-cache-ready state suffices (its assignments
    // aren't on the O(V) cost path).
    let mut seed_state = BeaconState::<E>::new(0, Default::default(), &spec);
    for _ in 0..seed_validators {
        seed_state
            .validators_mut()
            .push(Validator {
                effective_balance: spec.max_effective_balance,
                activation_epoch: Epoch::new(0),
                exit_epoch: spec.far_future_epoch,
                withdrawable_epoch: spec.far_future_epoch,
                ..Default::default()
            })
            .expect("push validator");
        seed_state
            .balances_mut()
            .push(spec.max_effective_balance)
            .expect("push balance");
    }
    seed_state
        .build_all_committee_caches(&spec)
        .expect("committee caches");
    let seed_assignments =
        SlotAssignments::new(&seed_state, &spec, None).expect("slot assignments");
    let mut fcr = FastConfirmationRule::new(
        finalized_checkpoint.root,
        &seed_state,
        seed_assignments,
        finalized_checkpoint,
        &seed_state,
        25,
        40,
    )
    .expect("fcr initialization");
    fcr.test_set_head_balance_source(balance_source.clone());

    BenchData {
        proto_array,
        votes,
        balance_source,
        fcr,
        finalized_checkpoint,
        unrealized_justified_checkpoint: observed_justified_checkpoint,
        observed_justified_checkpoint,
        genesis_checkpoint,
        equivocating_indices: BTreeSet::new(),
        block_roots,
    }
}

/// Real networks start around 100k validators; 16k is kept only as a sub-floor scaling reference.
const VALIDATOR_SET_SIZES: [usize; 4] = [16_000, 100_000, 500_000, 1_000_000];

/// A representative chain head + slot for the slot-agnostic building-block benchmarks below
/// (the `epoch_catch_up` configuration, where the FFG sweep is live).
const REPRESENTATIVE_HEAD_SLOT: u64 = 65;
const REPRESENTATIVE_CURRENT_SLOT: u64 = 66;

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

/// FFG scoring function: counts target checkpoint support. This is the epoch-boundary FFG sweep
/// (`get_current_target_score`); its cost is O(V) regardless of the current slot.
fn bench_get_current_target_score(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_current_target_score");

    for &n in &VALIDATOR_SET_SIZES {
        let data = build_chain(n);

        if n >= 100_000 {
            group.sample_size(10);
        }

        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, _| {
            b.iter(|| {
                data.fcr.get_current_target_score::<E>(
                    block_root_at(REPRESENTATIVE_HEAD_SLOT),
                    Slot::new(REPRESENTATIVE_CURRENT_SLOT),
                    &data.proto_array,
                    &data.votes,
                    &data.equivocating_indices,
                )
            })
        });
    }
    group.finish();
}

/// Batch precomputation of attestation scores for the full chain. Runs on every FCR tick; its
/// cost is O(V × depth) regardless of the current slot.
fn bench_precompute_chain_scores(c: &mut Criterion) {
    let mut group = c.benchmark_group("precompute_chain_scores");

    for &n in &VALIDATOR_SET_SIZES {
        let data = build_chain(n);
        let genesis_root = data.block_roots[0];
        // `block_roots[1..]` is exactly `get_ancestor_roots(head, genesis)` for this linear chain.
        let terminal_slot = data
            .proto_array
            .get_block(genesis_root)
            .expect("genesis in proto array")
            .slot();

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

/// Full confirmation algorithm (the complete production code path), measured across the realistic
/// (chain position, FCR run slot) scenarios in `SCENARIOS`. Benchmark ids are
/// `get_latest_confirmed/{scenario}/{n}`.
fn bench_get_latest_confirmed(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_latest_confirmed");

    for &n in &VALIDATOR_SET_SIZES {
        let mut data = build_chain(n);

        if n >= 100_000 {
            group.sample_size(10);
        }

        for scenario in SCENARIOS {
            data.apply_scenario(scenario);
            let head_root = block_root_at(scenario.head_slot);
            let current_slot = Slot::new(scenario.current_slot);

            group.bench_with_input(BenchmarkId::new(scenario.name, n), &n, |b, _| {
                b.iter(|| {
                    data.fcr.get_latest_confirmed::<E>(
                        head_root,
                        &data.finalized_checkpoint,
                        &data.unrealized_justified_checkpoint,
                        current_slot,
                        &data.proto_array,
                        &data.votes,
                        &data.equivocating_indices,
                    )
                })
            });
        }
    }
    group.finish();
}

/// `get_latest_confirmed` with a missed slot at the confirmation frontier (block 68 parents to 66),
/// so `compute_empty_slot_support_discount` runs `get_block_support`'s O(V) `is_in_range` loop over
/// the full committee-cached validator set — the on-demand committee-cache lookup at scale.
fn bench_get_latest_confirmed_empty_slots(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_latest_confirmed_empty_slots");
    for &n in &VALIDATOR_SET_SIZES {
        let mut data = build_chain_inner(n, n, Some(67));
        if n >= 100_000 {
            group.sample_size(10);
        }
        data.apply_scenario(&Scenario {
            name: "missed_slot",
            head_slot: 69,
            current_slot: 70,
            confirmed_slot: 66,
        });
        let head_root = block_root_at(69);
        group.bench_with_input(BenchmarkId::new("missed_slot", n), &n, |b, _| {
            b.iter(|| {
                data.fcr.get_latest_confirmed::<E>(
                    head_root,
                    &data.finalized_checkpoint,
                    &data.unrealized_justified_checkpoint,
                    Slot::new(70),
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
    bench_get_latest_confirmed_empty_slots,
);
criterion_main!(benches);
