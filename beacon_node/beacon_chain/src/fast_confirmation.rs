//! Fast Confirmation Rule (FCR) for Ethereum consensus.
//!
//! Implements the algorithm from consensus-specs PR #4747. FCR is a pure read-only
//! observer of fork-choice state that computes a `confirmed_root` — a block guaranteed
//! to remain canonical under standard assumptions (synchrony + <25% Byzantine).
//!
//! This module has **zero dependency on fork-choice internals**. It reads proto_array,
//! votes, and checkpoints via shared references and writes only its own state.
//!
//! ## Spec divergences (performance optimizations)
//!
//! The spec's `is_one_confirmed` calls `get_attestation_score` per block, each of which
//! iterates all validators and walks ancestors — O(B × V × depth) total. This is too
//! expensive at mainnet scale (500k+ validators).
//!
//! We diverge in three ways, all behaviorally equivalent:
//!
//! 1. **Batch score precomputation** (`precompute_chain_attestation_scores`): iterates
//!    validators once, walks each vote to the deepest canonical chain block, then builds
//!    a suffix-sum score array. Reduces cost from O(B × V × depth) to O(V × depth + B).
//!    Used by `find_latest_confirmed_descendant` and `is_confirmed_chain_safe`.
//!
//! 2. **`is_one_confirmed_with_score`**: variant of `is_one_confirmed` that takes a
//!    precomputed attestation score instead of calling `get_attestation_score`. The rest
//!    of the logic (proposer score, support discount, adversarial weight) is identical.
//!
//! 3. **Vote-root and checkpoint caches**: inside `precompute_chain_attestation_scores`
//!    and `get_current_target_score`, we cache the result of the most recent vote root /
//!    checkpoint walk. Since most validators vote for the same root, this avoids
//!    redundant HashMap lookups and ancestor walks.
//!
//! The original spec functions (`is_one_confirmed`, `get_attestation_score`) are not
//! present — only the optimized equivalents are used.

use crate::metrics;
use proto_array::core::{ProtoArray, VoteTracker};
use std::collections::{BTreeSet, HashMap};
use tracing::{debug, debug_span, info};
use types::{BeaconState, Checkpoint, Epoch, EthSpec, Hash256, RelativeEpoch, Slot};

#[derive(Debug, strum::IntoStaticStr)]
pub enum Error {
    #[strum(serialize = "node_not_found")]
    NodeNotFound(Hash256),
    #[strum(serialize = "ancestor_lookup")]
    AncestorNotFound { block: Hash256, slot: Slot },
    #[strum(serialize = "checkpoint_lookup")]
    UnrealizedJustificationNotFound(Hash256),
    #[strum(serialize = "checkpoint_lookup")]
    CheckpointBlockNotFound { block: Hash256, epoch: types::Epoch },
    #[strum(serialize = "missing_score")]
    MissingPrecomputedScore(Hash256),
    #[strum(serialize = "block_epoch_none")]
    BlockEpochNone(Hash256),
    #[strum(serialize = "committee_cache")]
    CommitteeCache(String),
    #[strum(serialize = "unset_slot")]
    UnsetSlotAssignment(usize),
    /// The state's epoch window does not cover `current_slot`'s epoch.
    /// This means the state is too stale to provide committee assignments for the
    /// slots FCR needs to query.
    #[strum(serialize = "stale_state")]
    StaleStateForAssignments {
        current_slot_epoch: Epoch,
        state_epoch: Epoch,
    },
}

/// Per-mille adjustment factor for committee weight estimates that don't cover a full epoch.
const COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR: u64 = 5;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Format for `set_head_slot_assignments` input.
#[derive(Debug, Clone, Copy)]
pub enum AssignmentFormat {
    /// Production format: `validator_count * 3` slots (one per epoch offset).
    ThreeColumn,
    /// Benchmark format: `validator_count * 2` slots (auto-expanded to 3-column).
    TwoColumn,
}

/// Per-validator committee slot assignments across a 3-epoch window.
///
/// Each active validator is assigned to exactly one committee slot per epoch.
/// This structure tracks those assignments for epochs `[current-2, current-1, current]`,
/// stored as a flat `Vec<Slot>` with stride 3 for cache-friendly iteration over all
/// validators.
///
/// # Layout
///
/// ```text
///                    epoch-2    epoch-1    current
/// validator 0:       slot_a     slot_b     slot_c
/// validator 1:       slot_d     slot_e     slot_f
/// ...
/// ```
///
/// Stored flat: `[slot_a, slot_b, slot_c, slot_d, slot_e, slot_f, ...]`
///
/// Access: `slots[validator_index * 3 + column]` where column 0/1/2 maps to
/// the epoch at `epochs[column]`.
///
/// # Sentinel
///
/// `UNSET_SLOT` (`Slot(u64::MAX)`) marks uninitialized entries. Reading an unset
/// slot via `is_in_range` returns an error, catching rebuild bugs early.
#[derive(Clone, Debug)]
struct SlotAssignments {
    /// Flat array of slot assignments. Length = `validator_count * 3`.
    slots: Vec<Slot>,
    /// The 3 epochs covered by columns 0, 1, 2 (typically `[current-2, current-1, current]`).
    epochs: [types::Epoch; 3],
}

/// Number of epoch columns in the slot assignment table.
const NUM_EPOCH_COLUMNS: usize = 3;

/// Sentinel value for unset slot assignments. Using `u64::MAX` instead of `Slot(0)`
/// avoids ambiguity with genesis slot 0 and allows hard error detection on read.
const UNSET_SLOT: Slot = Slot::new(u64::MAX);

impl SlotAssignments {
    /// Create an empty assignment table.
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            epochs: [types::Epoch::new(0); NUM_EPOCH_COLUMNS],
        }
    }

    /// Get the assigned slot for a validator in a given column (0, 1, or 2).
    fn get(&self, val_idx: usize, col: usize) -> Option<Slot> {
        self.slots.get(val_idx * NUM_EPOCH_COLUMNS + col).copied()
    }

    /// Check if a validator is assigned to any committee in the slot range `[start, end]`.
    ///
    /// Iterates over all 3 epoch columns and returns `true` if any assigned slot
    /// falls within the range (inclusive). Returns an error if an `UNSET_SLOT`
    /// sentinel is encountered, indicating a rebuild bug.
    fn is_in_range(&self, val_idx: usize, start_slot: Slot, end_slot: Slot) -> Result<bool, Error> {
        for col in 0..NUM_EPOCH_COLUMNS {
            let Some(slot) = self.get(val_idx, col) else {
                continue;
            };
            // UNSET_SLOT means no assignment in this epoch column (inactive validator
            // or epoch not yet loaded). Treat as "not in range".
            if slot == UNSET_SLOT {
                continue;
            }
            if slot >= start_slot && slot <= end_slot {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Set assignments from external data (for benchmarks).
    ///
    /// - `ThreeColumn`: `assignments.len() == validator_count * 3` (direct use)
    /// - `TwoColumn`: `assignments.len() == validator_count * 2` (auto-expanded,
    ///   fills columns 1 and 2, leaving column 0 as `Slot(0)`)
    fn set_from(&mut self, assignments: Vec<Slot>, format: AssignmentFormat) {
        match format {
            AssignmentFormat::ThreeColumn => {
                self.slots = assignments;
            }
            AssignmentFormat::TwoColumn => {
                let validator_count = assignments.len() / 2;
                let mut expanded = vec![UNSET_SLOT; validator_count * NUM_EPOCH_COLUMNS];
                for val_idx in 0..validator_count {
                    expanded[val_idx * NUM_EPOCH_COLUMNS + 1] = assignments[val_idx * 2];
                    expanded[val_idx * NUM_EPOCH_COLUMNS + 2] = assignments[val_idx * 2 + 1];
                }
                self.slots = expanded;
            }
        }
    }

    /// Rebuild assignments from a beacon state for the given slot.
    ///
    /// Computes the 3-epoch window `[current-2, current-1, current]` and fills
    /// assignments from the state's committee caches. Preserves old assignments
    /// that still fall within the new window (epoch column remapping).
    ///
    /// Returns early (cache hit) if the epoch window and validator count haven't changed.
    ///
    /// # Performance
    ///
    /// Instead of calling `get_attestation_duties()` per validator (O(N × C) where C =
    /// committees per epoch), we iterate the committee cache's shuffled list directly and
    /// derive slot from shuffled position in O(1). Total cost: O(N) per epoch column.
    fn rebuild<E: EthSpec>(
        &mut self,
        state: &BeaconState<E>,
        current_slot: Slot,
    ) -> Result<(), Error> {
        let validator_count = state.validators().len();
        let current_slot_epoch = current_slot.epoch(E::slots_per_epoch());
        let state_current = state.current_epoch();

        // The state's committee caches cover [previous, current, next] epochs.
        // FCR queries assignments for slots up to current_slot, so the state must
        // cover current_slot's epoch. The state's next epoch is current + 1,
        // so we accept states where current_slot_epoch <= state_current + 1.
        let state_next = state
            .next_epoch()
            .unwrap_or(state_current.saturating_add(1u64));
        if current_slot_epoch > state_next {
            return Err(Error::StaleStateForAssignments {
                current_slot_epoch,
                state_epoch: state_current,
            });
        }

        // Use the state's available epochs to determine the window.
        let state_prev = state.previous_epoch();
        let desired_epochs = [state_prev, state_current, state_next];

        // Fast path: skip if epoch window and validator count are unchanged.
        if self.epochs == desired_epochs && self.slots.len() == validator_count * NUM_EPOCH_COLUMNS
        {
            return Ok(());
        }

        let mut new_slots = vec![UNSET_SLOT; validator_count * NUM_EPOCH_COLUMNS];

        // Preserve old assignments that overlap the new epoch window.
        if self.slots.len() == validator_count * NUM_EPOCH_COLUMNS {
            for val_idx in 0..validator_count {
                for (old_col, old_epoch) in self.epochs.iter().enumerate() {
                    if let Some(new_col) = desired_epochs.iter().position(|e| e == old_epoch) {
                        new_slots[val_idx * NUM_EPOCH_COLUMNS + new_col] =
                            self.slots[val_idx * NUM_EPOCH_COLUMNS + old_col];
                    }
                }
            }
        }

        // Fill from the committee caches by iterating the shuffled list directly.
        // This is O(active_validators) per epoch instead of O(validators × committees).
        let slots_per_epoch = E::slots_per_epoch();
        for relative_epoch in [
            RelativeEpoch::Previous,
            RelativeEpoch::Current,
            RelativeEpoch::Next,
        ] {
            let duty_epoch = match relative_epoch {
                RelativeEpoch::Previous => state.previous_epoch(),
                RelativeEpoch::Current => state.current_epoch(),
                RelativeEpoch::Next => state
                    .next_epoch()
                    .map_err(|e| Error::CommitteeCache(format!("{e:?}")))?,
            };
            let Some(col) = desired_epochs.iter().position(|e| *e == duty_epoch) else {
                continue;
            };

            let committee_cache = state
                .committee_cache(relative_epoch)
                .map_err(|e| Error::CommitteeCache(format!("{e:?}")))?;

            let shuffling = committee_cache.shuffling();
            if shuffling.is_empty() {
                continue;
            }

            let committees_per_slot = committee_cache.committees_per_slot() as usize;
            let epoch_start = duty_epoch.start_slot(slots_per_epoch);

            // Each position in the shuffled list maps to a committee, which maps to a slot.
            // committee_index_in_epoch = position * total_committees / shuffling_len
            // slot_offset = committee_index_in_epoch / committees_per_slot
            let total_committees = committees_per_slot * slots_per_epoch as usize;
            let shuffling_len = shuffling.len();

            for (position, &val_idx) in shuffling.iter().enumerate() {
                let committee_index = position * total_committees / shuffling_len;
                let slot_offset = committee_index / committees_per_slot;
                let slot = epoch_start + slot_offset as u64;
                if val_idx < validator_count {
                    new_slots[val_idx * NUM_EPOCH_COLUMNS + col] = slot;
                }
            }
        }

        self.slots = new_slots;
        self.epochs = desired_epochs;
        Ok(())
    }
}

/// Snapshot of a checkpoint state's balances and committee assignments.
///
/// FCR needs two of these simultaneously: one for new confirmations (current epoch
/// observed justified) and one for reconfirmation at epoch boundaries (previous).
#[derive(Clone, Debug, Default)]
pub struct BalanceSourceData {
    pub checkpoint: Checkpoint,
    pub total_active_balance: u64,
    /// Effective balance per validator index. 0 for inactive.
    pub effective_balances: Vec<u64>,
    /// True if the validator has been slashed. Used to filter support votes
    /// (spec: `get_block_support_between_slots` excludes slashed validators).
    pub slashed: Vec<bool>,
}

impl BalanceSourceData {
    /// Build a `BalanceSourceData` from a beacon state.
    ///
    /// Extracts effective balances and committee slot assignments for the given epoch.
    /// The committee cache for `relative_epoch` must already be built on `state`.
    pub fn from_state<E: EthSpec>(
        state: &BeaconState<E>,
        checkpoint: Checkpoint,
        relative_epoch: RelativeEpoch,
    ) -> Result<Self, Error> {
        let _span = debug_span!("fcr_build_balance_source", epoch = %checkpoint.epoch).entered();

        let validator_count = state.validators().len();
        let mut effective_balances = Vec::with_capacity(validator_count);
        let mut slashed = Vec::with_capacity(validator_count);
        let mut total_active_balance = 0u64;

        let epoch = match relative_epoch {
            RelativeEpoch::Current => state.current_epoch(),
            RelativeEpoch::Previous => state.previous_epoch(),
            RelativeEpoch::Next => state
                .next_epoch()
                .map_err(|e| Error::CommitteeCache(format!("{e:?}")))?,
        };

        // Build effective balances for all active validators regardless of slashed status.
        // The spec's get_total_active_balance uses is_active_at without checking slashed.
        // Slashed filtering is applied separately where needed (e.g. get_block_support_between_slots).
        for validator in state.validators().iter() {
            slashed.push(validator.slashed);
            if validator.is_active_at(epoch) {
                effective_balances.push(validator.effective_balance);
                total_active_balance =
                    total_active_balance.saturating_add(validator.effective_balance);
            } else {
                effective_balances.push(0);
            }
        }

        debug!(
            validators = validator_count,
            active_balance = total_active_balance,
            epoch = %checkpoint.epoch,
            "FCR balance source built"
        );

        Ok(Self {
            checkpoint,
            total_active_balance,
            effective_balances,
            slashed,
        })
    }

    fn balance(&self, val_idx: usize) -> u64 {
        self.effective_balances.get(val_idx).copied().unwrap_or(0)
    }

    /// Return balance only if the validator is not slashed.
    /// Spec: `get_block_support_between_slots` excludes slashed validators.
    fn unslashed_balance(&self, val_idx: usize) -> u64 {
        if self.slashed.get(val_idx).copied().unwrap_or(false) {
            0
        } else {
            self.balance(val_idx)
        }
    }
}

/// The Fast Confirmation Rule state machine.
///
/// Lives as an `Option<FastConfirmationRule>` on `BeaconChain`.
/// `None` = FCR disabled.
#[derive(Clone, Debug)]
pub struct FastConfirmationRule {
    // === Output ===
    /// The latest confirmed block root. Fed into `safe_block_hash` for the EL.
    pub confirmed_root: Hash256,

    // === Tracking state (spec's 6 new store fields) ===
    pub previous_epoch_observed_justified_checkpoint: Checkpoint,
    pub current_epoch_observed_justified_checkpoint: Checkpoint,
    pub previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    pub previous_slot_head: Hash256,
    pub current_slot_head: Hash256,

    // === Balance source snapshots ===
    pub previous_balance_source: BalanceSourceData,
    pub current_balance_source: BalanceSourceData,

    // === Config ===
    pub byzantine_threshold: u64,
    /// Proposer score boost percentage from ChainSpec (e.g. 40 for mainnet).
    proposer_score_boost: u64,

    // === Committee data from head state ===
    /// Per-validator committee slot assignments across the last 3 epochs.
    /// Used by `get_block_support_between_slots` and `compute_adversarial_weight`.
    head_assignments: SlotAssignments,

    // === FFG data from the head state ===
    /// Effective balances for the current store epoch as seen from the head state.
    ///
    /// This is the implementation's approximation of the spec's pulled-up head state
    /// balance source and is used only by the FFG helpers.
    head_balance_source: BalanceSourceData,

    // === Internal bookkeeping ===
    /// The last slot at which `update_fast_confirmation_variables` ran.
    /// Prevents double-rotation when `recompute_head` runs multiple times per slot.
    /// `None` means no update has occurred yet (avoids using Slot(0) as sentinel,
    /// since slot 0 is a real slot with real committee assignments).
    last_update_slot: Option<Slot>,

    /// When `true`, `on_fast_confirmation` updates tracking variables but skips
    /// the `get_latest_confirmed` call. Spec tests set this so FCR is only
    /// triggered at explicit orchestration points (the spec's `with_fast_confirmation`).
    /// Always `false` in production.
    spec_test_mode: bool,
}

impl FastConfirmationRule {
    /// Maximum valid value for `byzantine_threshold` (25%).
    const MAX_BYZANTINE_THRESHOLD: u64 = 25;

    /// Initialize FCR from an anchor (finalized) checkpoint.
    ///
    /// `byzantine_threshold` is clamped to [0, 25].
    pub fn new(
        finalized_checkpoint: Checkpoint,
        byzantine_threshold: u64,
        proposer_score_boost: u64,
    ) -> Self {
        let byzantine_threshold = byzantine_threshold.min(Self::MAX_BYZANTINE_THRESHOLD);
        Self {
            confirmed_root: finalized_checkpoint.root,
            previous_epoch_observed_justified_checkpoint: finalized_checkpoint,
            current_epoch_observed_justified_checkpoint: finalized_checkpoint,
            previous_epoch_greatest_unrealized_checkpoint: finalized_checkpoint,
            previous_slot_head: finalized_checkpoint.root,
            current_slot_head: finalized_checkpoint.root,
            previous_balance_source: BalanceSourceData::default(),
            current_balance_source: BalanceSourceData::default(),
            byzantine_threshold,
            proposer_score_boost,
            head_assignments: SlotAssignments::new(),
            head_balance_source: BalanceSourceData::default(),
            last_update_slot: None,
            spec_test_mode: false,
        }
    }

    /// Enable spec test mode: `on_fast_confirmation` still tracks variables but
    /// does not update `confirmed_root`. Call `run_confirmation` explicitly.
    pub fn set_spec_test_mode(&mut self, enabled: bool) {
        self.spec_test_mode = enabled;
    }

    /// Directly set committee slot assignments (for benchmarks that lack a real BeaconState).
    pub fn set_head_slot_assignments(&mut self, assignments: Vec<Slot>, format: AssignmentFormat) {
        self.head_assignments.set_from(assignments, format);
    }

    fn rebuild_head_balance_source<E: EthSpec>(
        &mut self,
        state: &BeaconState<E>,
        current_slot: Slot,
    ) -> Result<(), Error> {
        let current_epoch = current_slot.epoch(E::slots_per_epoch());

        // Skip rebuild if balance source is already for this epoch.
        if self.head_balance_source.checkpoint.epoch == current_epoch
            && !self.head_balance_source.effective_balances.is_empty()
        {
            return Ok(());
        }

        let relative_epoch = if state.current_epoch() < current_epoch {
            RelativeEpoch::Next
        } else {
            RelativeEpoch::Current
        };
        let checkpoint = Checkpoint {
            epoch: current_epoch,
            root: Hash256::ZERO,
        };

        self.head_balance_source =
            BalanceSourceData::from_state(state, checkpoint, relative_epoch)?;
        Ok(())
    }

    /// Update balance sources from a beacon state.
    ///
    /// Called at epoch boundaries when the observed justified checkpoints rotate.
    /// The state should have committee caches built for both current and previous epochs.
    pub fn update_balance_sources<E: EthSpec>(
        &mut self,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        let current_cp = self.current_epoch_observed_justified_checkpoint;
        let previous_cp = self.previous_epoch_observed_justified_checkpoint;

        // Only rebuild if the checkpoint changed.
        if self.current_balance_source.checkpoint != current_cp {
            self.current_balance_source =
                BalanceSourceData::from_state(state, current_cp, RelativeEpoch::Current)?;
        }

        if self.previous_balance_source.checkpoint != previous_cp {
            self.previous_balance_source =
                BalanceSourceData::from_state(state, previous_cp, RelativeEpoch::Previous)?;
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Top-level entry point: on_fast_confirmation
    // -----------------------------------------------------------------------

    /// Spec: `on_fast_confirmation(store)`.
    ///
    /// Called after head selection, while the fork-choice read lock is held.
    /// All parameters are borrowed from fork choice. The `state` is used to
    /// rebuild balance sources when observed justified checkpoints change.
    #[allow(clippy::too_many_arguments)]
    pub fn on_fast_confirmation<E: EthSpec>(
        &mut self,
        head_root: Hash256,
        finalized_checkpoint: &Checkpoint,
        justified_checkpoint: &Checkpoint,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        let _span = debug_span!("fcr_on_fast_confirmation", slot = %current_slot).entered();

        self.update_fast_confirmation_variables::<E>(
            head_root,
            unrealized_justified_checkpoint,
            current_slot,
        );

        let t0 = std::time::Instant::now();

        // Rebuild committee assignments from the head state.
        self.head_assignments.rebuild::<E>(state, current_slot)?;
        let t1 = t0.elapsed();

        self.rebuild_head_balance_source::<E>(state, current_slot)?;
        let t2 = t0.elapsed();

        // Rebuild balance sources if the observed justified checkpoints changed.
        self.update_balance_sources(state)?;
        let t3 = t0.elapsed();

        if !self.spec_test_mode {
            self.confirmed_root = self.get_latest_confirmed::<E>(
                head_root,
                finalized_checkpoint,
                justified_checkpoint,
                unrealized_justified_checkpoint,
                current_slot,
                proto_array,
                votes,
                equivocating_indices,
            )?;
        }
        let t4 = t0.elapsed();

        if t4.as_millis() > 5 {
            info!(
                slot = %current_slot,
                total_ms = t4.as_millis(),
                assignments_ms = t1.as_millis(),
                head_balance_ms = (t2 - t1).as_millis(),
                update_balance_ms = (t3 - t2).as_millis(),
                algorithm_ms = (t4 - t3).as_millis(),
                "FCR slow invocation"
            );
        }

        Ok(())
    }

    /// Explicitly trigger the confirmation finding step.
    ///
    /// In spec tests, `spec_test_mode` is `true` so this must be called manually
    /// at the orchestration points that correspond to the spec's `with_fast_confirmation`.
    #[allow(clippy::too_many_arguments)]
    pub fn run_confirmation<E: EthSpec>(
        &mut self,
        head_root: Hash256,
        finalized_checkpoint: &Checkpoint,
        justified_checkpoint: &Checkpoint,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
        state: &BeaconState<E>,
    ) -> Result<(), Error> {
        // Ensure variables and committee data are up to date.
        self.update_fast_confirmation_variables::<E>(
            head_root,
            unrealized_justified_checkpoint,
            current_slot,
        );
        self.head_assignments.rebuild::<E>(state, current_slot)?;
        self.rebuild_head_balance_source::<E>(state, current_slot)?;
        self.update_balance_sources(state)?;

        self.confirmed_root = self.get_latest_confirmed::<E>(
            head_root,
            finalized_checkpoint,
            justified_checkpoint,
            unrealized_justified_checkpoint,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        )?;

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Spec: update_fast_confirmation_variables
    // -----------------------------------------------------------------------

    /// Spec: `update_fast_confirmation_variables`.
    fn update_fast_confirmation_variables<E: EthSpec>(
        &mut self,
        head_root: Hash256,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
    ) {
        let _span = debug_span!("fcr_update_variables", slot = %current_slot).entered();

        // Spec: update_fast_confirmation_variables is called once per slot,
        // at the attestation deadline. Guard against duplicate calls within the same slot.
        if self.last_update_slot.is_none_or(|s| current_slot > s) {
            // Rotate slot heads.
            self.previous_slot_head = self.current_slot_head;
            self.current_slot_head = head_root;

            // At last slot of epoch: snapshot greatest unrealized justified.
            if is_start_slot_at_epoch::<E>(current_slot.saturating_add(1u64)) {
                self.previous_epoch_greatest_unrealized_checkpoint =
                    *unrealized_justified_checkpoint;
            }

            // At first slot of epoch: rotate observed justified checkpoints.
            if is_start_slot_at_epoch::<E>(current_slot) {
                self.previous_epoch_observed_justified_checkpoint =
                    self.current_epoch_observed_justified_checkpoint;
                self.current_epoch_observed_justified_checkpoint =
                    self.previous_epoch_greatest_unrealized_checkpoint;
            }

            self.last_update_slot = Some(current_slot);
        }
    }

    // -----------------------------------------------------------------------
    // Spec: get_latest_confirmed
    // -----------------------------------------------------------------------

    /// `_justified_checkpoint` is unused but kept to match the spec function signature.
    #[allow(clippy::too_many_arguments)]
    pub fn get_latest_confirmed<E: EthSpec>(
        &self,
        head_root: Hash256,
        finalized_checkpoint: &Checkpoint,
        _justified_checkpoint: &Checkpoint,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Hash256, Error> {
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let mut confirmed_root = self.confirmed_root;

        // Phase 1: Revert to finalized if needed.
        let confirmed_epoch = self.block_epoch::<E>(confirmed_root, proto_array);
        let is_epoch_start = is_start_slot_at_epoch::<E>(current_slot);

        if confirmed_epoch.is_none_or(|e| e.saturating_add(1u64) < current_epoch)
            || !self.is_ancestor(head_root, confirmed_root, proto_array)?
            || (is_epoch_start
                && !self.is_confirmed_chain_safe::<E>(
                    confirmed_root,
                    current_slot,
                    proto_array,
                    votes,
                    equivocating_indices,
                )?)
        {
            let reason = if confirmed_epoch.is_none_or(|e| e.saturating_add(1u64) < current_epoch) {
                "epoch_too_old"
            } else if !self
                .is_ancestor(head_root, confirmed_root, proto_array)
                .unwrap_or(false)
            {
                "not_ancestor"
            } else {
                "chain_unsafe"
            };
            debug!(
                prev_confirmed = %confirmed_root,
                finalized = %finalized_checkpoint.root,
                slot = %current_slot,
                reason = reason,
                "FCR reverted to finalized"
            );
            confirmed_root = finalized_checkpoint.root;
            metrics::inc_counter(&metrics::FCR_PHASE1_REVERT);
        }
        // Phase 2: Restart from justified if conditions met.
        let observed_jcp = &self.current_epoch_observed_justified_checkpoint;
        if is_epoch_start
            && observed_jcp.epoch.saturating_add(1u64) == current_epoch
            && *observed_jcp == self.unrealized_justification_of(head_root, proto_array)?
            && self.block_slot(confirmed_root, proto_array)?
                < self.block_slot(observed_jcp.root, proto_array)?
        {
            debug!(
                prev_confirmed = %confirmed_root,
                justified = %observed_jcp.root,
                justified_epoch = %observed_jcp.epoch,
                "FCR restarted from observed justified"
            );
            confirmed_root = observed_jcp.root;
            metrics::inc_counter(&metrics::FCR_PHASE2_RESTART);
        }
        let pre_advance_root = confirmed_root;

        // Phase 3: Advance via find_latest_confirmed_descendant.
        let confirmed_epoch = self.block_epoch::<E>(confirmed_root, proto_array);
        if confirmed_epoch.is_some_and(|e| e.saturating_add(1u64) >= current_epoch) {
            confirmed_root = self.find_latest_confirmed_descendant::<E>(
                confirmed_root,
                head_root,
                unrealized_justified_checkpoint,
                current_slot,
                proto_array,
                votes,
                equivocating_indices,
            )?;
        }
        if confirmed_root != pre_advance_root {
            metrics::inc_counter(&metrics::FCR_PHASE3_ADVANCE);
        }

        Ok(confirmed_root)
    }

    // -----------------------------------------------------------------------
    // Spec: find_latest_confirmed_descendant
    //
    // DIVERGENCE: The spec calls `is_one_confirmed` per block, which calls
    // `get_attestation_score` each time — O(B × V × depth). We precompute
    // all scores once via `precompute_chain_attestation_scores` and use
    // `is_one_confirmed_with_score` per block instead — O(V × depth + B).
    // -----------------------------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn find_latest_confirmed_descendant<E: EthSpec>(
        &self,
        latest_confirmed_root: Hash256,
        head_root: Hash256,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Hash256, Error> {
        let _span = debug_span!("fcr_find_confirmed_descendant").entered();

        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let mut confirmed_root = latest_confirmed_root;
        let is_epoch_start = is_start_slot_at_epoch::<E>(current_slot);

        // Precompute attestation scores for the full chain from confirmed → head in one
        // O(V × depth) pass. Both loops below use these scores instead of calling
        // get_attestation_score per block (which would be O(B × V × depth) total).
        let precomputed_scores = self.precompute_chain_attestation_scores(
            head_root,
            latest_confirmed_root,
            &self.current_balance_source,
            proto_array,
            votes,
            equivocating_indices,
        )?;
        // --- Loop 1: Previous epoch blocks ---
        let prev_head_voting_source_epoch =
            self.get_voting_source_epoch::<E>(self.previous_slot_head, current_slot, proto_array);

        let confirmed_epoch_check = self
            .block_epoch::<E>(confirmed_root, proto_array)
            .is_some_and(|e| e.saturating_add(1u64) == current_epoch);
        let voting_source_check =
            prev_head_voting_source_epoch.is_some_and(|e| e.saturating_add(2u64) >= current_epoch);
        let no_conflict = self.will_no_conflicting_checkpoint_be_justified::<E>(
            head_root,
            unrealized_justified_checkpoint,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        )?;
        let uj_prev_head =
            self.unrealized_justification_epoch_of(self.previous_slot_head, proto_array);
        let uj_head = self.unrealized_justification_epoch_of(head_root, proto_array);
        let loop1_guard = confirmed_epoch_check
            && voting_source_check
            && (is_epoch_start
                || (no_conflict
                    && (uj_prev_head.is_some_and(|e| e.saturating_add(1u64) >= current_epoch)
                        || uj_head.is_some_and(|e| e.saturating_add(1u64) >= current_epoch))));
        if loop1_guard {
            let canonical_roots =
                self.get_ancestor_roots(head_root, confirmed_root, proto_array)?;

            for block_root in &canonical_roots {
                let block_epoch = self.block_epoch::<E>(*block_root, proto_array);
                if block_epoch.is_none_or(|e| e >= current_epoch) {
                    break;
                }
                if !self.is_ancestor(self.previous_slot_head, *block_root, proto_array)? {
                    break;
                }
                let score = *precomputed_scores
                    .get(block_root)
                    .ok_or(Error::MissingPrecomputedScore(*block_root))?;
                if !self.is_one_confirmed_with_score::<E>(
                    &self.current_balance_source,
                    *block_root,
                    score,
                    current_slot,
                    proto_array,
                    votes,
                    equivocating_indices,
                )? {
                    break;
                }
                confirmed_root = *block_root;
            }
        }

        // --- Loop 2: Current epoch blocks ---
        let uj_epoch = self.unrealized_justification_epoch_of(head_root, proto_array);
        let loop2_guard =
            is_epoch_start || uj_epoch.is_some_and(|e| e.saturating_add(1u64) >= current_epoch);
        if loop2_guard {
            let canonical_roots =
                self.get_ancestor_roots(head_root, confirmed_root, proto_array)?;

            let mut tentative_confirmed_root = confirmed_root;

            for block_root in &canonical_roots {
                let block_epoch = self.block_epoch::<E>(*block_root, proto_array);
                let tentative_epoch = self.block_epoch::<E>(tentative_confirmed_root, proto_array);

                // When crossing into current epoch, check FFG.
                if block_epoch > tentative_epoch {
                    let ffg_ok = self.will_current_target_be_justified::<E>(
                        head_root,
                        unrealized_justified_checkpoint,
                        current_slot,
                        proto_array,
                        votes,
                        equivocating_indices,
                    )?;
                    if !ffg_ok {
                        break;
                    }
                }

                let score = *precomputed_scores
                    .get(block_root)
                    .ok_or(Error::MissingPrecomputedScore(*block_root))?;
                if !self.is_one_confirmed_with_score::<E>(
                    &self.current_balance_source,
                    *block_root,
                    score,
                    current_slot,
                    proto_array,
                    votes,
                    equivocating_indices,
                )? {
                    break;
                }
                tentative_confirmed_root = *block_root;
            }

            // Promote tentative if safe.
            let tentative_epoch = self.block_epoch::<E>(tentative_confirmed_root, proto_array);
            let tentative_voting_source_epoch = self.get_voting_source_epoch::<E>(
                tentative_confirmed_root,
                current_slot,
                proto_array,
            );

            let promote_check1 = tentative_epoch == Some(current_epoch);
            let promote_check2 = tentative_voting_source_epoch
                .is_some_and(|e| e.saturating_add(2u64) >= current_epoch)
                && (is_epoch_start
                    || self.will_no_conflicting_checkpoint_be_justified::<E>(
                        head_root,
                        unrealized_justified_checkpoint,
                        current_slot,
                        proto_array,
                        votes,
                        equivocating_indices,
                    )?);

            if promote_check1 || promote_check2 {
                confirmed_root = tentative_confirmed_root;
            }
        }

        if confirmed_root != latest_confirmed_root {
            debug!(
                confirmed = %confirmed_root,
                prev = %latest_confirmed_root,
                "FCR advanced"
            );
        }
        Ok(confirmed_root)
    }

    // -----------------------------------------------------------------------
    // Spec: is_one_confirmed
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Spec: is_confirmed_chain_safe
    //
    // DIVERGENCE: Same optimization as find_latest_confirmed_descendant —
    // precomputes scores once and uses `is_one_confirmed_with_score`.
    // -----------------------------------------------------------------------

    fn is_confirmed_chain_safe<E: EthSpec>(
        &self,
        confirmed_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<bool, Error> {
        let observed_jcp = &self.current_epoch_observed_justified_checkpoint;
        if !self.is_ancestor(confirmed_root, observed_jcp.root, proto_array)? {
            return Ok(false);
        }

        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let start_root = if observed_jcp.epoch.saturating_add(1u64) >= current_epoch {
            observed_jcp.root
        } else {
            // Limit reconfirmation to the first block of the previous epoch.
            // If successful, reconfirmation of ancestors is implied.
            let prev_epoch_start = current_epoch
                .saturating_sub(1u64)
                .start_slot(E::slots_per_epoch());
            let ancestor = self.get_ancestor(confirmed_root, prev_epoch_start, proto_array)?;
            let ancestor_epoch = self.block_epoch::<E>(ancestor, proto_array);
            if ancestor_epoch.is_some_and(|e| e.saturating_add(1u64) == current_epoch) {
                // The parent of the first block of the previous epoch.
                match self.parent_root(ancestor, proto_array) {
                    Some(r) => r,
                    None => return Ok(false),
                }
            } else {
                // The last block of the epoch before the previous one.
                ancestor
            }
        };

        // Precompute scores for the confirmed chain in one O(V × depth) pass.
        let precomputed_scores = self.precompute_chain_attestation_scores(
            confirmed_root,
            start_root,
            &self.previous_balance_source,
            proto_array,
            votes,
            equivocating_indices,
        )?;

        let chain_roots = self.get_ancestor_roots(confirmed_root, start_root, proto_array)?;
        for root in &chain_roots {
            let score = *precomputed_scores
                .get(root)
                .ok_or(Error::MissingPrecomputedScore(*root))?;
            if !self.is_one_confirmed_with_score::<E>(
                &self.previous_balance_source,
                *root,
                score,
                current_slot,
                proto_array,
                votes,
                equivocating_indices,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    // -----------------------------------------------------------------------
    // LMD-GHOST helpers
    // -----------------------------------------------------------------------

    /// Spec: `get_block_support_between_slots`.
    /// Counts weight of validators whose latest vote is for EXACTLY `block_root`
    /// (not descendants) and whose committee assignment is in [start_slot, end_slot].
    /// Committee assignments come from the HEAD state (stored in `head_assignments`).
    fn get_block_support_between_slots(
        &self,
        balance_source: &BalanceSourceData,
        block_root: Hash256,
        start_slot: Slot,
        end_slot: Slot,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        let mut score = 0u64;
        for (val_idx, vote) in votes.iter().enumerate() {
            if vote.current_root() != block_root {
                continue;
            }
            if equivocating_indices.contains(&(val_idx as u64)) {
                continue;
            }
            let balance = balance_source.unslashed_balance(val_idx);
            if balance == 0 {
                continue;
            }
            if self
                .head_assignments
                .is_in_range(val_idx, start_slot, end_slot)?
            {
                score = score.saturating_add(balance);
            }
        }
        Ok(score)
    }

    /// Spec: `compute_proposer_score(balance_source)`.
    /// Uses `(committee_weight * proposer_score_boost) // 100` (multiply-first) to match
    /// the spec and avoid precision loss from divide-first ordering.
    fn compute_proposer_score<E: EthSpec>(&self, balance_source: &BalanceSourceData) -> u64 {
        let committee_weight = balance_source.total_active_balance / E::slots_per_epoch();
        committee_weight.saturating_mul(self.proposer_score_boost) / 100
    }

    /// Spec: `get_support_discount`.
    fn get_support_discount<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        block_slot: Slot,
        parent_root: Hash256,
        parent_slot: Slot,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        // No empty slots before the block.
        if parent_slot.saturating_add(1u64) == block_slot {
            return Ok(0);
        }

        let empty_start = parent_slot.saturating_add(1u64);
        let empty_end = block_slot.saturating_sub(1u64);

        // Votes for the parent in the empty slot range.
        // Uses exact vote matching (spec's get_block_support_between_slots),
        // NOT ancestor matching (spec's get_attestation_score).
        let parent_support = self.get_block_support_between_slots(
            balance_source,
            parent_root,
            empty_start,
            empty_end,
            votes,
            equivocating_indices,
        )?;

        // Adversarial weight in empty slots is NOT discounted.
        let adversarial = self.compute_adversarial_weight::<E>(
            balance_source,
            empty_start,
            empty_end,
            equivocating_indices,
        )?;

        Ok(parent_support.saturating_sub(adversarial))
    }

    /// Spec: `get_adversarial_weight`.
    fn get_adversarial_weight<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        block_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        let block_slot = self.block_slot(block_root, proto_array)?;
        let Some(parent_root) = self.parent_root(block_root, proto_array) else {
            return Ok(0);
        };
        let parent_epoch = self.block_epoch::<E>(parent_root, proto_array);
        let block_epoch = self.block_epoch::<E>(block_root, proto_array);

        let start_slot = if block_epoch > parent_epoch {
            block_epoch
                .ok_or(Error::BlockEpochNone(block_root))?
                .start_slot(E::slots_per_epoch())
        } else {
            block_slot
        };

        self.compute_adversarial_weight::<E>(
            balance_source,
            start_slot,
            current_slot.saturating_sub(1u64),
            equivocating_indices,
        )
    }

    /// Spec: `compute_adversarial_weight`.
    ///
    fn compute_adversarial_weight<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        start_slot: Slot,
        end_slot: Slot,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        let maximum_weight = estimate_committee_weight_between_slots::<E>(
            balance_source.total_active_balance,
            start_slot,
            end_slot,
        );
        let max_adversarial = (maximum_weight / 100).saturating_mul(self.byzantine_threshold);

        let equivocation_score = self.get_equivocation_score(
            balance_source,
            start_slot,
            end_slot,
            equivocating_indices,
        )?;

        Ok(max_adversarial.saturating_sub(equivocation_score))
    }

    /// Spec: `get_equivocation_score`.
    /// Uses HEAD state committee assignments (via `head_assignments.is_in_range`).
    fn get_equivocation_score(
        &self,
        balance_source: &BalanceSourceData,
        start_slot: Slot,
        end_slot: Slot,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        let mut score = 0u64;
        for &val_idx in equivocating_indices {
            let idx = val_idx as usize;
            let balance = balance_source.balance(idx);
            if balance == 0 {
                continue;
            }
            if self
                .head_assignments
                .is_in_range(idx, start_slot, end_slot)?
            {
                score = score.saturating_add(balance);
            }
        }
        Ok(score)
    }

    // -----------------------------------------------------------------------
    // FFG helpers
    // -----------------------------------------------------------------------

    /// Spec: `will_no_conflicting_checkpoint_be_justified`.
    #[allow(clippy::too_many_arguments)]
    fn will_no_conflicting_checkpoint_be_justified<E: EthSpec>(
        &self,
        head_root: Hash256,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<bool, Error> {
        let current_target = self.get_current_target::<E>(head_root, current_slot, proto_array)?;
        if current_target == *unrealized_justified_checkpoint {
            return Ok(true);
        }

        let honest_ffg = self.compute_honest_ffg_support::<E>(
            head_root,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        )?;
        let total_active = self.head_balance_source.total_active_balance;

        // 3 * honest_ffg >= 1 * total_active (i.e. honest > 1/3)
        Ok(3u128 * honest_ffg as u128 >= total_active as u128)
    }

    /// Spec: `will_current_target_be_justified`.
    #[allow(clippy::too_many_arguments)]
    fn will_current_target_be_justified<E: EthSpec>(
        &self,
        head_root: Hash256,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<bool, Error> {
        let honest_ffg = self.compute_honest_ffg_support::<E>(
            head_root,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        )?;
        let total_active = self.head_balance_source.total_active_balance;

        // 3 * honest_ffg >= 2 * total_active (i.e. honest > 2/3)
        let _ = unrealized_justified_checkpoint; // used only in will_no_conflicting
        Ok(3u128 * honest_ffg as u128 >= 2u128 * total_active as u128)
    }

    /// Spec: `get_current_target_score` — estimates FFG support for current epoch target.
    ///
    /// For each validator with a latest message, computes the checkpoint at the
    /// **vote's own epoch** for the vote's root, and checks if it matches the
    /// current target. This ensures only votes from the current epoch count.
    pub fn get_current_target_score<E: EthSpec>(
        &self,
        head_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        let current_target = self.get_current_target::<E>(head_root, current_slot, proto_array)?;
        let bs = &self.head_balance_source;
        let mut score = 0u64;

        // Cache: most validators vote for the same root+epoch, so cache the last
        // checkpoint lookup result. Avoids redundant O(depth) walks AND HashMap hashing.
        let mut cached_root = Hash256::ZERO;
        let mut cached_epoch = types::Epoch::new(0);
        let mut cached_target = Checkpoint::default();
        let mut cached_valid = false;

        for (val_idx, vote) in votes.iter().enumerate() {
            // Skip validators without a vote (spec: `i in store.latest_messages`).
            if vote.current_root().is_zero() {
                continue;
            }
            if equivocating_indices.contains(&(val_idx as u64)) {
                continue;
            }
            let balance = bs.balance(val_idx);
            if balance == 0 {
                continue;
            }
            // Spec: get_checkpoint_for_block(store, latest_messages[i].root,
            //        get_latest_message_epoch(latest_messages[i]))
            // Use the VOTE's epoch, not the current epoch.
            let vote_root = vote.current_root();
            let vote_epoch = vote.latest_message_epoch();
            let vote_target =
                if cached_valid && vote_root == cached_root && vote_epoch == cached_epoch {
                    cached_target
                } else {
                    let cp =
                        self.get_checkpoint_for_block::<E>(vote_root, vote_epoch, proto_array)?;
                    cached_root = vote_root;
                    cached_epoch = vote_epoch;
                    cached_target = cp;
                    cached_valid = true;
                    cp
                };
            if vote_target == current_target {
                score = score.saturating_add(balance);
            }
        }
        Ok(score)
    }

    /// Spec: `compute_honest_ffg_support_for_current_target`.
    fn compute_honest_ffg_support<E: EthSpec>(
        &self,
        head_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let total_active = self.head_balance_source.total_active_balance;

        let ffg_support = self.get_current_target_score::<E>(
            head_root,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        )?;

        let epoch_start = current_epoch.start_slot(E::slots_per_epoch());
        let ffg_weight_till_now = estimate_committee_weight_between_slots::<E>(
            total_active,
            epoch_start,
            current_slot.saturating_sub(1u64),
        );

        let remaining_ffg_weight = total_active.saturating_sub(ffg_weight_till_now);
        let remaining_honest = (remaining_ffg_weight / 100)
            .saturating_mul(100u64.saturating_sub(self.byzantine_threshold));

        // Compute potential adversarial weight (accounts for slashed validators).
        let adversarial_weight = self.compute_adversarial_weight::<E>(
            &self.head_balance_source,
            epoch_start,
            current_slot.saturating_sub(1u64),
            equivocating_indices,
        )?;
        let min_honest_support = ffg_support.saturating_sub(adversarial_weight);

        Ok(min_honest_support.saturating_add(remaining_honest))
    }

    // -----------------------------------------------------------------------
    // Proto-array accessors (read-only)
    // -----------------------------------------------------------------------

    fn block_slot(&self, root: Hash256, proto_array: &ProtoArray) -> Result<Slot, Error> {
        proto_array
            .indices
            .get(&root)
            .and_then(|&idx| proto_array.nodes.get(idx))
            .map(|n| n.slot)
            .ok_or(Error::NodeNotFound(root))
    }

    fn block_epoch<E: EthSpec>(
        &self,
        root: Hash256,
        proto_array: &ProtoArray,
    ) -> Option<types::Epoch> {
        proto_array
            .indices
            .get(&root)
            .and_then(|&idx| proto_array.nodes.get(idx))
            .map(|n| n.slot.epoch(E::slots_per_epoch()))
    }

    fn parent_root(&self, root: Hash256, proto_array: &ProtoArray) -> Option<Hash256> {
        proto_array
            .indices
            .get(&root)
            .and_then(|&idx| proto_array.nodes.get(idx))
            .and_then(|n| n.parent)
            .and_then(|parent_idx| proto_array.nodes.get(parent_idx))
            .map(|n| n.root)
    }

    fn is_ancestor(
        &self,
        block_root: Hash256,
        ancestor_root: Hash256,
        proto_array: &ProtoArray,
    ) -> Result<bool, Error> {
        let ancestor_slot = self.block_slot(ancestor_root, proto_array)?;
        Ok(proto_array
            .iter_block_roots(&block_root)
            .any(|(root, slot)| slot <= ancestor_slot && root == ancestor_root))
    }

    /// Spec: `get_ancestor(store, block_root, slot)`.
    /// Returns the root of the latest block at or before `slot` on the chain of `block_root`.
    fn get_ancestor(
        &self,
        block_root: Hash256,
        slot: Slot,
        proto_array: &ProtoArray,
    ) -> Result<Hash256, Error> {
        proto_array
            .iter_block_roots(&block_root)
            .find(|(_, s)| *s <= slot)
            .map(|(root, _)| root)
            .ok_or(Error::AncestorNotFound {
                block: block_root,
                slot,
            })
    }

    /// Get ordered ancestor roots from `terminal_root` (exclusive) to `block_root` (inclusive).
    ///
    /// Returns an empty vector if `terminal_root` is not in the chain of `block_root`.
    fn get_ancestor_roots(
        &self,
        block_root: Hash256,
        terminal_root: Hash256,
        proto_array: &ProtoArray,
    ) -> Result<Vec<Hash256>, Error> {
        let terminal_slot = self.block_slot(terminal_root, proto_array)?;
        let mut roots = Vec::new();

        for (root, slot) in proto_array.iter_block_roots(&block_root) {
            if root == terminal_root {
                roots.reverse();
                return Ok(roots);
            }
            if slot <= terminal_slot {
                return Ok(Vec::new());
            }
            roots.push(root);
        }

        Ok(Vec::new())
    }

    /// Get the unrealized justified checkpoint for a block.
    fn unrealized_justification_of(
        &self,
        root: Hash256,
        proto_array: &ProtoArray,
    ) -> Result<Checkpoint, Error> {
        proto_array
            .indices
            .get(&root)
            .and_then(|&idx| proto_array.nodes.get(idx))
            .and_then(|n| n.unrealized_justified_checkpoint)
            .ok_or(Error::UnrealizedJustificationNotFound(root))
    }

    fn unrealized_justification_epoch_of(
        &self,
        root: Hash256,
        proto_array: &ProtoArray,
    ) -> Option<types::Epoch> {
        proto_array
            .indices
            .get(&root)
            .and_then(|&idx| proto_array.nodes.get(idx))
            .and_then(|n| n.unrealized_justified_checkpoint)
            .map(|cp| cp.epoch)
    }

    /// Implements `get_voting_source` — returns the checkpoint used for fork choice voting.
    /// When `current_epoch > block_epoch`, returns unrealized justified checkpoint (pulled-up).
    /// Otherwise, returns the block's own justified checkpoint.
    fn get_voting_source_epoch<E: EthSpec>(
        &self,
        root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
    ) -> Option<types::Epoch> {
        let node = proto_array
            .indices
            .get(&root)
            .and_then(|&idx| proto_array.nodes.get(idx))?;
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let block_epoch = node.slot.epoch(E::slots_per_epoch());
        if current_epoch > block_epoch {
            node.unrealized_justified_checkpoint.map(|cp| cp.epoch)
        } else {
            Some(node.justified_checkpoint.epoch)
        }
    }

    /// Get current epoch target checkpoint.
    fn get_current_target<E: EthSpec>(
        &self,
        head_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
    ) -> Result<Checkpoint, Error> {
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        self.get_checkpoint_for_block::<E>(head_root, current_epoch, proto_array)
    }

    /// Get checkpoint block root at the given epoch for the chain ending at `block_root`.
    fn get_checkpoint_for_block<E: EthSpec>(
        &self,
        block_root: Hash256,
        epoch: types::Epoch,
        proto_array: &ProtoArray,
    ) -> Result<Checkpoint, Error> {
        let cp_root = self.get_checkpoint_block_root::<E>(block_root, epoch, proto_array)?;
        Ok(Checkpoint {
            epoch,
            root: cp_root,
        })
    }

    /// Find the block root at the epoch boundary for the given chain.
    fn get_checkpoint_block_root<E: EthSpec>(
        &self,
        block_root: Hash256,
        epoch: types::Epoch,
        proto_array: &ProtoArray,
    ) -> Result<Hash256, Error> {
        let epoch_start_slot = epoch.start_slot(E::slots_per_epoch());
        proto_array
            .iter_block_roots(&block_root)
            .find(|(_, slot)| *slot <= epoch_start_slot)
            .map(|(root, _)| root)
            .ok_or(Error::CheckpointBlockNotFound {
                block: block_root,
                epoch,
            })
    }

    // -----------------------------------------------------------------------
    // Batch score precomputation
    // -----------------------------------------------------------------------

    /// Precompute attestation scores for all blocks along the canonical chain from
    /// `terminal_root` (exclusive) to `chain_tip` (inclusive) in a single O(V × depth) pass.
    ///
    /// This replaces B separate O(V × depth) calls to `get_attestation_score` with one
    /// pass over all validators, reducing total cost from O(B × V × depth) to O(V × depth + B).
    pub fn precompute_chain_attestation_scores(
        &self,
        chain_tip: Hash256,
        terminal_root: Hash256,
        balance_source: &BalanceSourceData,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<HashMap<Hash256, u64>, Error> {
        let chain = self.get_ancestor_roots(chain_tip, terminal_root, proto_array)?;
        if chain.is_empty() {
            return Ok(HashMap::new());
        }

        // Build node_index → chain_position map for O(1) membership checks during walks.
        let mut index_to_position: HashMap<usize, usize> = HashMap::with_capacity(chain.len());
        for (pos, root) in chain.iter().enumerate() {
            if let Some(&node_idx) = proto_array.indices.get(root) {
                index_to_position.insert(node_idx, pos);
            }
        }

        let terminal_slot = self.block_slot(terminal_root, proto_array)?;

        // For each validator, walk from vote_root toward genesis. The first canonical chain
        // node hit is the deepest block the vote covers. Accumulate balances by position.
        let chain_len = chain.len();
        let mut score_at_position = vec![0u64; chain_len];

        // Cache: most validators vote for the same root, so cache the last walk result
        // to avoid redundant HashMap<Hash256, usize> lookups (hashing 32 bytes is expensive).
        let mut cached_vote_root = Hash256::ZERO;
        let mut cached_position: Option<usize> = None;

        for (val_idx, vote) in votes.iter().enumerate() {
            let vote_root = vote.current_root();
            if vote_root.is_zero() {
                continue;
            }
            if equivocating_indices.contains(&(val_idx as u64)) {
                continue;
            }
            let balance = balance_source.unslashed_balance(val_idx);
            if balance == 0 {
                continue;
            }

            // Fast path: reuse cached walk result for repeated vote roots.
            if vote_root == cached_vote_root {
                if let Some(pos) = cached_position {
                    score_at_position[pos] = score_at_position[pos].saturating_add(balance);
                }
                continue;
            }

            // Slow path: resolve vote root and walk ancestors.
            let Some(&start_idx) = proto_array.indices.get(&vote_root) else {
                cached_vote_root = vote_root;
                cached_position = None;
                continue;
            };

            let mut deepest_pos = None;
            let mut current_idx = start_idx;
            loop {
                if let Some(&pos) = index_to_position.get(&current_idx) {
                    deepest_pos = Some(pos);
                    break;
                }
                let Some(node) = proto_array.nodes.get(current_idx) else {
                    break;
                };
                if node.slot <= terminal_slot {
                    break;
                }
                match node.parent {
                    Some(parent_idx) => current_idx = parent_idx,
                    None => break,
                }
            }

            cached_vote_root = vote_root;
            cached_position = deepest_pos;

            if let Some(pos) = deepest_pos {
                score_at_position[pos] = score_at_position[pos].saturating_add(balance);
            }
        }

        // Suffix sum: a vote covering position j also covers all ancestors at positions 0..j.
        // score[k] = Σ score_at_position[j] for j ∈ [k, chain_len)
        let mut scores = HashMap::with_capacity(chain_len);
        let mut running = 0u64;
        for i in (0..chain_len).rev() {
            running = running.saturating_add(score_at_position[i]);
            scores.insert(chain[i], running);
        }

        Ok(scores)
    }

    /// Spec: `is_one_confirmed` — uses a precomputed attestation score from
    /// `precompute_chain_attestation_scores` instead of iterating all validators.
    #[allow(clippy::too_many_arguments)]
    fn is_one_confirmed_with_score<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        block_root: Hash256,
        attestation_score: u64,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<bool, Error> {
        let block_slot = self.block_slot(block_root, proto_array)?;
        let Some(parent_root) = self.parent_root(block_root, proto_array) else {
            return Ok(false);
        };
        let parent_slot = self.block_slot(parent_root, proto_array)?;

        let support = attestation_score;
        let proposer_score = self.compute_proposer_score::<E>(balance_source);
        let maximum_support = estimate_committee_weight_between_slots::<E>(
            balance_source.total_active_balance,
            parent_slot.saturating_add(1u64),
            current_slot.saturating_sub(1u64),
        );
        let support_discount = self.get_support_discount::<E>(
            balance_source,
            block_slot,
            parent_root,
            parent_slot,
            votes,
            equivocating_indices,
        )?;
        let adversarial_weight = self.get_adversarial_weight::<E>(
            balance_source,
            block_root,
            current_slot,
            proto_array,
            equivocating_indices,
        )?;

        // Spec: compute_safety_threshold
        // safety_threshold = (maximum_support + proposer_score - support_discount) / 2 + adversarial_weight
        let safety_threshold =
            (maximum_support as u128 + proposer_score as u128 - support_discount as u128) / 2
                + adversarial_weight as u128;

        Ok(support as u128 > safety_threshold)
    }
}

// ---------------------------------------------------------------------------
// Free functions: arithmetic helpers
// ---------------------------------------------------------------------------

/// Spec: `is_start_slot_at_epoch`.
pub fn is_start_slot_at_epoch<E: EthSpec>(slot: Slot) -> bool {
    slot.as_u64().is_multiple_of(E::slots_per_epoch())
}

/// Spec: `is_full_validator_set_covered`.
pub fn is_full_validator_set_covered<E: EthSpec>(start_slot: Slot, end_slot: Slot) -> bool {
    let spe = E::slots_per_epoch();
    let start_full_epoch = start_slot.as_u64().div_ceil(spe);
    let end_full_epoch = end_slot.as_u64().saturating_add(1) / spe;
    start_full_epoch < end_full_epoch
}

/// Spec: `adjust_committee_weight_estimate_to_ensure_safety`.
pub fn adjust_committee_weight_estimate_to_ensure_safety(estimate: u64) -> u64 {
    (estimate / 1000)
        .saturating_mul(1000u64.saturating_add(COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR))
}

/// Spec: `estimate_committee_weight_between_slots`.
pub fn estimate_committee_weight_between_slots<E: EthSpec>(
    total_active_balance: u64,
    start_slot: Slot,
    end_slot: Slot,
) -> u64 {
    let spe = E::slots_per_epoch();

    if start_slot > end_slot {
        return 0;
    }

    if is_full_validator_set_covered::<E>(start_slot, end_slot) {
        return total_active_balance;
    }

    let start_epoch = start_slot.as_u64() / spe;
    let end_epoch = end_slot.as_u64() / spe;

    if start_epoch == end_epoch {
        let num_slots = end_slot.as_u64() - start_slot.as_u64() + 1;
        return (total_active_balance / spe).saturating_mul(num_slots);
    }

    // Cross-epoch boundary but not covering a full epoch.
    let slots_since_start_epoch = start_slot.as_u64() % spe;
    let num_slots_in_start_epoch = spe - slots_since_start_epoch;

    let slots_since_end_epoch = end_slot.as_u64() % spe;
    let num_slots_in_end_epoch = slots_since_end_epoch + 1;
    let remaining_slots_in_end_epoch = spe - num_slots_in_end_epoch;

    let start_epoch_weight = (total_active_balance / spe).saturating_mul(num_slots_in_start_epoch);
    let end_epoch_weight = (total_active_balance / spe).saturating_mul(num_slots_in_end_epoch);

    let start_epoch_weight_pro_rated =
        (start_epoch_weight / spe).saturating_mul(remaining_slots_in_end_epoch);

    adjust_committee_weight_estimate_to_ensure_safety(
        start_epoch_weight_pro_rated.saturating_add(end_epoch_weight),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::MainnetEthSpec;

    type E = MainnetEthSpec;

    #[test]
    fn test_is_start_slot_at_epoch() {
        assert!(is_start_slot_at_epoch::<E>(Slot::new(0)));
        assert!(is_start_slot_at_epoch::<E>(Slot::new(32)));
        assert!(!is_start_slot_at_epoch::<E>(Slot::new(1)));
        assert!(!is_start_slot_at_epoch::<E>(Slot::new(31)));
    }

    #[test]
    fn test_is_full_validator_set_covered() {
        // 32 slots = full epoch
        assert!(is_full_validator_set_covered::<E>(
            Slot::new(0),
            Slot::new(31)
        ));
        // 33 slots crossing boundary
        assert!(is_full_validator_set_covered::<E>(
            Slot::new(0),
            Slot::new(32)
        ));
        // Single slot — not full
        assert!(!is_full_validator_set_covered::<E>(
            Slot::new(0),
            Slot::new(0)
        ));
        // 31 slots — not full
        assert!(!is_full_validator_set_covered::<E>(
            Slot::new(1),
            Slot::new(31)
        ));
    }

    #[test]
    fn test_estimate_committee_weight_same_epoch() {
        let total = 32_000_000_000u64; // 32B gwei
        // 1 slot out of 32 => total/32 = 1B
        let w = estimate_committee_weight_between_slots::<E>(total, Slot::new(0), Slot::new(0));
        assert_eq!(w, 1_000_000_000);

        // Full epoch => total
        let w = estimate_committee_weight_between_slots::<E>(total, Slot::new(0), Slot::new(31));
        assert_eq!(w, total);
    }

    #[test]
    fn test_estimate_committee_weight_empty_range() {
        let w = estimate_committee_weight_between_slots::<E>(
            32_000_000_000,
            Slot::new(10),
            Slot::new(5),
        );
        assert_eq!(w, 0);
    }

    #[test]
    fn test_adjustment_factor() {
        // 1000 -> 1000/1000 * 1005 = 1005
        assert_eq!(
            adjust_committee_weight_estimate_to_ensure_safety(1000),
            1005
        );
        // 999 -> 0 * 1005 = 0 (integer division)
        assert_eq!(adjust_committee_weight_estimate_to_ensure_safety(999), 0);
    }

    mod slot_assignments {
        use super::*;
        use state_processing::per_slot_processing;
        use types::MinimalEthSpec;

        type E = MinimalEthSpec;

        /// Build a minimal genesis state with `n` validators and committee caches.
        /// Uses BeaconState::new directly with manually-added validators to avoid
        /// needing deposit proofs.
        fn genesis_state(n: usize) -> (BeaconState<E>, types::ChainSpec) {
            let spec = E::default_spec();
            let mut state = BeaconState::new(0, Default::default(), &spec);

            // Manually populate validators and balances.
            for _ in 0..n {
                let validator = types::Validator {
                    effective_balance: spec.max_effective_balance,
                    activation_epoch: Epoch::new(0),
                    exit_epoch: spec.far_future_epoch,
                    withdrawable_epoch: spec.far_future_epoch,
                    ..Default::default()
                };
                state
                    .validators_mut()
                    .push(validator)
                    .expect("push validator");
                state
                    .balances_mut()
                    .push(spec.max_effective_balance)
                    .expect("push balance");
            }

            state
                .build_committee_cache(RelativeEpoch::Previous, &spec)
                .expect("prev cache");
            state
                .build_committee_cache(RelativeEpoch::Current, &spec)
                .expect("current cache");
            state
                .build_committee_cache(RelativeEpoch::Next, &spec)
                .expect("next cache");

            (state, spec)
        }

        /// Advance a state to a given slot, rebuilding committee caches.
        fn advance_state(state: &mut BeaconState<E>, target_slot: Slot, spec: &types::ChainSpec) {
            while state.slot() < target_slot {
                per_slot_processing(state, None, spec).expect("should advance slot");
            }
            state
                .build_committee_cache(RelativeEpoch::Previous, spec)
                .expect("prev cache");
            state
                .build_committee_cache(RelativeEpoch::Current, spec)
                .expect("current cache");
            state
                .build_committee_cache(RelativeEpoch::Next, spec)
                .expect("next cache");
        }

        #[test]
        fn rebuild_with_genesis_state_at_genesis_slot() {
            let (state, _spec) = genesis_state(64);
            let mut sa = SlotAssignments::new();

            // State at epoch 0, current_slot in epoch 0 — should work.
            sa.rebuild::<E>(&state, Slot::new(1))
                .expect("genesis state covers epoch 0");

            // Verify epoch window: [prev=0, current=0, next=1].
            assert_eq!(sa.epochs[0], Epoch::new(0));
            assert_eq!(sa.epochs[1], Epoch::new(0));
            assert_eq!(sa.epochs[2], Epoch::new(1));
        }

        #[test]
        fn rebuild_with_genesis_state_at_next_epoch_slot() {
            let (state, _spec) = genesis_state(64);
            let mut sa = SlotAssignments::new();

            // State at epoch 0, current_slot in epoch 1 — should work
            // because state's next epoch (1) covers current_slot's epoch.
            let epoch_1_slot = E::slots_per_epoch(); // slot 8 for minimal
            sa.rebuild::<E>(&state, Slot::new(epoch_1_slot))
                .expect("genesis state's next epoch covers epoch 1");
        }

        #[test]
        fn rebuild_rejects_stale_state() {
            let (state, _spec) = genesis_state(64);
            let mut sa = SlotAssignments::new();

            // State at epoch 0 (covers [0, 0, 1]), current_slot in epoch 2.
            // Epoch 2 > state's next epoch (1) — should fail.
            let epoch_2_slot = E::slots_per_epoch() * 2; // slot 16 for minimal
            let result = sa.rebuild::<E>(&state, Slot::new(epoch_2_slot));
            assert!(
                matches!(
                    result,
                    Err(Error::StaleStateForAssignments {
                        current_slot_epoch,
                        state_epoch,
                    }) if current_slot_epoch == Epoch::new(2) && state_epoch == Epoch::new(0)
                ),
                "expected StaleStateForAssignments, got {:?}",
                result
            );
        }

        #[test]
        fn rebuild_rejects_state_3_epochs_behind() {
            let (state, _spec) = genesis_state(64);
            let mut sa = SlotAssignments::new();

            // State at epoch 0, current_slot in epoch 5 — clearly stale.
            let epoch_5_slot = E::slots_per_epoch() * 5;
            let result = sa.rebuild::<E>(&state, Slot::new(epoch_5_slot));
            assert!(
                matches!(result, Err(Error::StaleStateForAssignments { .. })),
                "expected StaleStateForAssignments for 5-epoch gap, got {:?}",
                result
            );
        }

        #[test]
        fn rebuild_advanced_state_covers_later_epochs() {
            let (mut state, spec) = genesis_state(64);
            let mut sa = SlotAssignments::new();

            // Advance state to epoch 2 (slot 16 for minimal).
            let epoch_2_start = E::slots_per_epoch() * 2;
            advance_state(&mut state, Slot::new(epoch_2_start), &spec);

            assert_eq!(state.current_epoch(), Epoch::new(2));

            // current_slot in epoch 2 — should work (state covers [1, 2, 3]).
            sa.rebuild::<E>(&state, Slot::new(epoch_2_start + 1))
                .expect("state at epoch 2 covers epoch 2");

            // current_slot in epoch 3 — should also work (state's next = 3).
            let epoch_3_start = E::slots_per_epoch() * 3;
            sa.rebuild::<E>(&state, Slot::new(epoch_3_start))
                .expect("state at epoch 2 covers epoch 3 via next");

            // current_slot in epoch 4 — should fail.
            let epoch_4_start = E::slots_per_epoch() * 4;
            let result = sa.rebuild::<E>(&state, Slot::new(epoch_4_start));
            assert!(
                matches!(result, Err(Error::StaleStateForAssignments { .. })),
                "state at epoch 2 can't cover epoch 4, got {:?}",
                result
            );
        }

        #[test]
        fn rebuild_populates_assignments_for_correct_epochs() {
            let (mut state, spec) = genesis_state(64);
            let mut sa = SlotAssignments::new();

            // Advance state to epoch 2.
            let epoch_2_start = E::slots_per_epoch() * 2;
            advance_state(&mut state, Slot::new(epoch_2_start), &spec);

            // Rebuild with current_slot in epoch 2.
            sa.rebuild::<E>(&state, Slot::new(epoch_2_start + 1))
                .expect("rebuild should succeed");

            // Epoch window should be [1, 2, 3].
            assert_eq!(sa.epochs[0], Epoch::new(1));
            assert_eq!(sa.epochs[1], Epoch::new(2));
            assert_eq!(sa.epochs[2], Epoch::new(3));

            // Every validator should have an assignment in at least the current epoch.
            let validator_count = state.validators().len();
            let spe = E::slots_per_epoch();
            for val_idx in 0..validator_count {
                // Check current epoch column (col 1 = epoch 2).
                let slot = sa.get(val_idx, 1).expect("valid index");
                assert_ne!(
                    slot, UNSET_SLOT,
                    "validator {val_idx} missing epoch 2 assignment"
                );
                // Assignment slot must be within epoch 2.
                let epoch_2_end = epoch_2_start + spe - 1;
                assert!(
                    slot.as_u64() >= epoch_2_start && slot.as_u64() <= epoch_2_end,
                    "validator {val_idx} assigned to slot {} which is not in epoch 2 [{epoch_2_start}, {epoch_2_end}]",
                    slot
                );
            }

            // Slots in epoch 2 should be findable via is_in_range.
            let mid_epoch_2 = Slot::new(epoch_2_start + spe / 2);
            let mut found_any = false;
            for val_idx in 0..validator_count {
                if sa
                    .is_in_range(val_idx, Slot::new(epoch_2_start), mid_epoch_2)
                    .unwrap()
                {
                    found_any = true;
                    break;
                }
            }
            assert!(
                found_any,
                "at least one validator should be assigned in first half of epoch 2"
            );
        }

        #[test]
        fn is_in_range_returns_false_for_uncovered_epochs() {
            let (state, _spec) = genesis_state(64);
            let mut sa = SlotAssignments::new();

            // State at epoch 0, covers epochs [0, 0, 1].
            sa.rebuild::<E>(&state, Slot::new(1)).expect("should build");

            // Query for a slot in epoch 5 — no validator should match.
            let far_slot = Slot::new(E::slots_per_epoch() * 5);
            for val_idx in 0..state.validators().len() {
                assert!(
                    !sa.is_in_range(val_idx, far_slot, far_slot).unwrap(),
                    "validator {val_idx} should NOT be in range for epoch 5"
                );
            }
        }
    }
}
