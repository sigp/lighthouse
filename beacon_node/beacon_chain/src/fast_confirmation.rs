//! Fast Confirmation Rule (FCR) for Ethereum consensus.
//!
//! Implements the algorithm from consensus-specs PR #4747. FCR is a pure read-only
//! observer of fork-choice state that computes a `confirmed_root` — a block guaranteed
//! to remain canonical under standard assumptions (synchrony + <25% Byzantine).
//!
//! This module has **zero dependency on fork-choice internals**. It reads proto_array,
//! votes, and checkpoints via shared references and writes only its own state.

use proto_array::core::{ProtoArray, VoteTracker};
use std::collections::{BTreeSet, HashMap};
use tracing::{debug, debug_span, warn};
use types::{BeaconState, Checkpoint, EthSpec, Hash256, RelativeEpoch, Slot};

/// Per-mille adjustment factor for committee weight estimates that don't cover a full epoch.
const COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR: u64 = 5;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

/// Snapshot of a checkpoint state's balances and committee assignments.
///
/// FCR needs two of these simultaneously: one for new confirmations (current epoch
/// observed justified) and one for reconfirmation at epoch boundaries (previous).
#[derive(Clone, Debug, Default)]
pub struct BalanceSourceData {
    pub checkpoint: Checkpoint,
    pub total_active_balance: u64,
    /// Effective balance per validator index. 0 for inactive/slashed.
    pub effective_balances: Vec<u64>,
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
    ) -> Result<Self, String> {
        let _span = debug_span!("fcr_build_balance_source", epoch = %checkpoint.epoch).entered();

        let validator_count = state.validators().len();
        let mut effective_balances = Vec::with_capacity(validator_count);
        let mut total_active_balance = 0u64;

        let epoch = match relative_epoch {
            RelativeEpoch::Current => state.current_epoch(),
            RelativeEpoch::Previous => state.previous_epoch(),
            RelativeEpoch::Next => state.next_epoch().map_err(|e| format!("{e:?}"))?,
        };

        // Build effective balances (same pattern as JustifiedBalances).
        for validator in state.validators().iter() {
            if !validator.slashed && validator.is_active_at(epoch) {
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
        })
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

    // === Committee data from head state ===
    /// Per-validator slot assignment, covering current and previous epochs.
    /// Built from the HEAD state each time `on_fast_confirmation` runs.
    /// Used by `get_block_support_between_slots` and `get_equivocation_score`.
    head_slot_assignments: Vec<Slot>,

    // === Internal bookkeeping ===
    /// The last slot at which `update_fast_confirmation_variables` ran.
    /// Prevents double-rotation when `recompute_head` runs multiple times per slot.
    last_update_slot: Slot,

    /// When `false`, `on_fast_confirmation` updates tracking variables but skips
    /// the `get_latest_confirmed` call. Used in spec tests where FCR is only
    /// triggered at explicit orchestration points (the spec's `with_fast_confirmation`
    /// flag). In production this should always be `true`.
    auto_confirm: bool,
}

impl FastConfirmationRule {
    /// Maximum valid value for `byzantine_threshold` (25%).
    const MAX_BYZANTINE_THRESHOLD: u64 = 25;

    /// Initialize FCR from an anchor (finalized) checkpoint.
    ///
    /// `byzantine_threshold` is clamped to [0, 25].
    pub fn new(finalized_checkpoint: Checkpoint, byzantine_threshold: u64) -> Self {
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
            head_slot_assignments: Vec::new(),
            last_update_slot: Slot::new(0),
            auto_confirm: true,
        }
    }

    /// Disable automatic confirmation finding (for spec tests).
    /// When disabled, `on_fast_confirmation` still tracks variables but does not
    /// update `confirmed_root`. Call `run_confirmation` explicitly to trigger it.
    pub fn set_auto_confirm(&mut self, enabled: bool) {
        self.auto_confirm = enabled;
    }

    /// Directly set committee slot assignments (for benchmarks that lack a real BeaconState).
    pub fn set_head_slot_assignments(&mut self, assignments: Vec<Slot>) {
        self.head_slot_assignments = assignments;
    }

    /// Rebuild committee slot assignments from the head state.
    ///
    /// The spec's `get_slot_committee` uses `store.block_states[head]` for shuffling,
    /// which is separate from the balance source. We store two slot assignments per
    /// validator (previous epoch and current epoch) so we can check committee membership
    /// across epoch boundaries.
    fn rebuild_head_slot_assignments<E: EthSpec>(&mut self, state: &BeaconState<E>) {
        let validator_count = state.validators().len();
        // Store pairs: (prev_epoch_slot, curr_epoch_slot). Slot(0) means no assignment.
        let mut assignments = vec![Slot::new(0); validator_count * 2];

        for val_idx in 0..validator_count {
            if let Ok(Some(duty)) = state.get_attestation_duties(val_idx, RelativeEpoch::Previous) {
                assignments[val_idx * 2] = duty.slot;
            }
            if let Ok(Some(duty)) = state.get_attestation_duties(val_idx, RelativeEpoch::Current) {
                assignments[val_idx * 2 + 1] = duty.slot;
            }
        }

        self.head_slot_assignments = assignments;
    }

    /// Check if a validator is assigned to any committee in the slot range [start, end].
    fn is_in_committee_range(&self, val_idx: usize, start_slot: Slot, end_slot: Slot) -> bool {
        let prev_slot = self
            .head_slot_assignments
            .get(val_idx * 2)
            .copied()
            .unwrap_or_else(|| Slot::new(0));
        let curr_slot = self
            .head_slot_assignments
            .get(val_idx * 2 + 1)
            .copied()
            .unwrap_or_else(|| Slot::new(0));
        (prev_slot >= start_slot && prev_slot <= end_slot)
            || (curr_slot >= start_slot && curr_slot <= end_slot)
    }

    /// Update balance sources from a beacon state.
    ///
    /// Called at epoch boundaries when the observed justified checkpoints rotate.
    /// The state should have committee caches built for both current and previous epochs.
    pub fn update_balance_sources<E: EthSpec>(&mut self, state: &BeaconState<E>) {
        let current_cp = self.current_epoch_observed_justified_checkpoint;
        let previous_cp = self.previous_epoch_observed_justified_checkpoint;

        // Only rebuild if the checkpoint changed.
        if self.current_balance_source.checkpoint != current_cp {
            match BalanceSourceData::from_state(state, current_cp, RelativeEpoch::Current) {
                Ok(bs) => self.current_balance_source = bs,
                Err(e) => warn!(error = %e, "FCR: failed to build current balance source"),
            }
        }

        if self.previous_balance_source.checkpoint != previous_cp {
            match BalanceSourceData::from_state(state, previous_cp, RelativeEpoch::Previous) {
                Ok(bs) => self.previous_balance_source = bs,
                Err(e) => warn!(error = %e, "FCR: failed to build previous balance source"),
            }
        }
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
    ) -> Result<(), String> {
        let _span = debug_span!("fcr_on_fast_confirmation", slot = %current_slot).entered();

        self.update_fast_confirmation_variables::<E>(
            head_root,
            unrealized_justified_checkpoint,
            current_slot,
            proto_array,
        );

        // Rebuild committee assignments from the head state.
        self.rebuild_head_slot_assignments::<E>(state);

        // Rebuild balance sources if the observed justified checkpoints changed.
        self.update_balance_sources(state);

        if self.auto_confirm {
            self.confirmed_root = self.get_latest_confirmed::<E>(
                head_root,
                finalized_checkpoint,
                justified_checkpoint,
                unrealized_justified_checkpoint,
                current_slot,
                proto_array,
                votes,
                equivocating_indices,
            );
        }

        Ok(())
    }

    /// Explicitly trigger the confirmation finding step.
    ///
    /// In spec tests, `auto_confirm` is `false` so this must be called manually
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
    ) -> Result<(), String> {
        // Ensure variables and committee data are up to date.
        self.update_fast_confirmation_variables::<E>(
            head_root,
            unrealized_justified_checkpoint,
            current_slot,
            proto_array,
        );
        self.rebuild_head_slot_assignments::<E>(state);
        self.update_balance_sources(state);

        self.confirmed_root = self.get_latest_confirmed::<E>(
            head_root,
            finalized_checkpoint,
            justified_checkpoint,
            unrealized_justified_checkpoint,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Spec: update_fast_confirmation_variables
    // -----------------------------------------------------------------------

    fn update_fast_confirmation_variables<E: EthSpec>(
        &mut self,
        head_root: Hash256,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        _proto_array: &ProtoArray,
    ) {
        let _span = debug_span!("fcr_update_variables", slot = %current_slot).entered();

        // The spec's slot-head tracking (previous_slot_head / current_slot_head) records
        // the head at the *start* of each slot. Mid-slot block processing should NOT update
        // these values. Only rotate at slot boundaries.
        if current_slot > self.last_update_slot {
            // Rotate slot heads: previous captures old current, then current = new head.
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

            self.last_update_slot = current_slot;
        }
    }

    // -----------------------------------------------------------------------
    // Spec: get_latest_confirmed
    // -----------------------------------------------------------------------

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
    ) -> Hash256 {
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let mut confirmed_root = self.confirmed_root;

        // Phase 1: Revert to finalized if needed.
        let confirmed_epoch = self.block_epoch::<E>(confirmed_root, proto_array);
        let is_epoch_start = is_start_slot_at_epoch::<E>(current_slot);

        if confirmed_epoch.is_none_or(|e| e.saturating_add(1u64) < current_epoch)
            || !self.is_ancestor(head_root, confirmed_root, proto_array)
            || (is_epoch_start
                && !self.is_confirmed_chain_safe::<E>(
                    confirmed_root,
                    current_slot,
                    proto_array,
                    votes,
                    equivocating_indices,
                ))
        {
            debug!(
                prev_confirmed = %confirmed_root,
                finalized = %finalized_checkpoint.root,
                slot = %current_slot,
                "FCR reverted to finalized"
            );
            confirmed_root = finalized_checkpoint.root;
        }

        // Phase 2: Restart from justified if conditions met.
        let observed_jcp = &self.current_epoch_observed_justified_checkpoint;
        if is_epoch_start
            && observed_jcp.epoch.saturating_add(1u64) == current_epoch
            && *observed_jcp == self.unrealized_justification_of(head_root, proto_array)
            && self.block_slot(confirmed_root, proto_array)
                < self.block_slot(observed_jcp.root, proto_array)
        {
            debug!(
                prev_confirmed = %confirmed_root,
                justified = %observed_jcp.root,
                justified_epoch = %observed_jcp.epoch,
                "FCR restarted from observed justified"
            );
            confirmed_root = observed_jcp.root;
        }

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
            );
        }

        confirmed_root
    }

    // -----------------------------------------------------------------------
    // Spec: find_latest_confirmed_descendant
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
    ) -> Hash256 {
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
        );

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
        );
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
            let canonical_roots = self.get_ancestor_roots(head_root, confirmed_root, proto_array);

            for block_root in &canonical_roots {
                let block_epoch = self.block_epoch::<E>(*block_root, proto_array);
                if block_epoch.is_none_or(|e| e >= current_epoch) {
                    break;
                }
                if !self.is_ancestor(self.previous_slot_head, *block_root, proto_array) {
                    break;
                }
                let score = precomputed_scores.get(block_root).copied().unwrap_or(0);
                if !self.is_one_confirmed_with_score::<E>(
                    &self.current_balance_source,
                    *block_root,
                    score,
                    current_slot,
                    proto_array,
                    votes,
                    equivocating_indices,
                ) {
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
            let canonical_roots = self.get_ancestor_roots(head_root, confirmed_root, proto_array);

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
                    );
                    if !ffg_ok {
                        break;
                    }
                }

                let score = precomputed_scores.get(block_root).copied().unwrap_or(0);
                if !self.is_one_confirmed_with_score::<E>(
                    &self.current_balance_source,
                    *block_root,
                    score,
                    current_slot,
                    proto_array,
                    votes,
                    equivocating_indices,
                ) {
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
                    ));

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
        confirmed_root
    }

    // -----------------------------------------------------------------------
    // Spec: is_one_confirmed
    // -----------------------------------------------------------------------

    /// The core LMD-GHOST safety predicate.
    ///
    /// Returns `true` iff:
    /// `2 * support + support_discount > maximum_support + proposer_score + 2 * adversarial_weight`
    ///
    /// Computes the attestation score from scratch by iterating all validators.
    /// When checking multiple blocks on the same chain, prefer
    /// `precompute_chain_attestation_scores` + `is_one_confirmed_with_score` instead.
    #[allow(clippy::too_many_arguments)]
    pub fn is_one_confirmed<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        block_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> bool {
        let score = self.get_attestation_score(
            balance_source,
            block_root,
            proto_array,
            votes,
            equivocating_indices,
        );
        self.is_one_confirmed_with_score::<E>(
            balance_source,
            block_root,
            score,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        )
    }

    // -----------------------------------------------------------------------
    // Spec: is_confirmed_chain_safe
    // -----------------------------------------------------------------------

    fn is_confirmed_chain_safe<E: EthSpec>(
        &self,
        confirmed_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> bool {
        let observed_jcp = &self.current_epoch_observed_justified_checkpoint;
        if !self.is_ancestor(confirmed_root, observed_jcp.root, proto_array) {
            return false;
        }

        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let start_root = if observed_jcp.epoch.saturating_add(1u64) >= current_epoch {
            observed_jcp.root
        } else {
            // Limit reconfirmation to the checkpoint block at current_epoch - 1.
            let cp_root = self.get_checkpoint_block_root::<E>(
                confirmed_root,
                current_epoch.saturating_sub(1u64),
                proto_array,
            );
            match self.parent_root(cp_root, proto_array) {
                Some(r) => r,
                None => return false,
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
        );

        let chain_roots = self.get_ancestor_roots(confirmed_root, start_root, proto_array);
        chain_roots.iter().all(|root| {
            let score = precomputed_scores.get(root).copied().unwrap_or(0);
            self.is_one_confirmed_with_score::<E>(
                &self.previous_balance_source,
                *root,
                score,
                current_slot,
                proto_array,
                votes,
                equivocating_indices,
            )
        })
    }

    // -----------------------------------------------------------------------
    // LMD-GHOST helpers
    // -----------------------------------------------------------------------

    /// Spec: `get_block_support_between_slots`.
    /// Counts weight of validators whose latest vote is for EXACTLY `block_root`
    /// (not descendants) and whose committee assignment is in [start_slot, end_slot].
    /// Committee assignments come from the HEAD state (stored in `head_slot_assignments`).
    fn get_block_support_between_slots(
        &self,
        balance_source: &BalanceSourceData,
        block_root: Hash256,
        start_slot: Slot,
        end_slot: Slot,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> u64 {
        let mut score = 0u64;
        for (val_idx, vote) in votes.iter().enumerate() {
            if vote.current_root() != block_root {
                continue;
            }
            if equivocating_indices.contains(&(val_idx as u64)) {
                continue;
            }
            let balance = balance_source
                .effective_balances
                .get(val_idx)
                .copied()
                .unwrap_or(0);
            if balance == 0 {
                continue;
            }
            if self.is_in_committee_range(val_idx, start_slot, end_slot) {
                score = score.saturating_add(balance);
            }
        }
        score
    }

    /// Spec: `get_attestation_score` (from PR #4746).
    ///
    /// Counts the total effective balance of active, unslashed, non-equivocating
    /// validators whose latest message root has `block_root` as an ancestor.
    /// Uses ancestor matching:
    /// `get_ancestor(store, latest_messages[i].root, blocks[root].slot) == root`
    /// No slot-range filtering — all voters are counted.
    pub fn get_attestation_score(
        &self,
        balance_source: &BalanceSourceData,
        block_root: Hash256,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> u64 {
        let mut score = 0u64;
        for (val_idx, vote) in votes.iter().enumerate() {
            // Ancestor matching per spec:
            // get_ancestor(store, latest_messages[i].root, blocks[root].slot) == root
            if !self.is_ancestor(vote.current_root(), block_root, proto_array) {
                continue;
            }
            if equivocating_indices.contains(&(val_idx as u64)) {
                continue;
            }
            let balance = balance_source
                .effective_balances
                .get(val_idx)
                .copied()
                .unwrap_or(0);
            if balance == 0 {
                continue;
            }
            score = score.saturating_add(balance);
        }
        score
    }

    /// Spec: `compute_proposer_score(balance_source)`.
    fn compute_proposer_score<E: EthSpec>(&self, balance_source: &BalanceSourceData) -> u64 {
        let committee_weight = balance_source
            .total_active_balance
            .checked_div(E::slots_per_epoch())
            .unwrap_or(0);
        // Proposer boost is 40% of committee weight (matching Lighthouse's default).
        (committee_weight / 100).saturating_mul(40)
    }

    /// Spec: `get_support_discount`.
    #[allow(clippy::too_many_arguments)]
    fn get_support_discount<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        _block_root: Hash256,
        block_slot: Slot,
        parent_root: Hash256,
        parent_slot: Slot,
        current_slot: Slot,
        _proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> u64 {
        // No empty slots before the block.
        if parent_slot.saturating_add(1u64) == block_slot {
            return 0;
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
        );

        // Adversarial weight in empty slots is NOT discounted.
        let adversarial = self.compute_adversarial_weight::<E>(
            balance_source,
            empty_start,
            empty_end,
            current_slot,
            equivocating_indices,
        );

        parent_support.saturating_sub(adversarial)
    }

    /// Spec: `get_adversarial_weight`.
    fn get_adversarial_weight<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        block_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        equivocating_indices: &BTreeSet<u64>,
    ) -> u64 {
        let block_slot = self.block_slot(block_root, proto_array);
        let Some(parent_root) = self.parent_root(block_root, proto_array) else {
            return 0;
        };
        let parent_epoch = self.block_epoch::<E>(parent_root, proto_array);
        let block_epoch = self.block_epoch::<E>(block_root, proto_array);

        let start_slot = if block_epoch > parent_epoch {
            block_epoch
                .unwrap_or_default()
                .start_slot(E::slots_per_epoch())
        } else {
            block_slot
        };

        self.compute_adversarial_weight::<E>(
            balance_source,
            start_slot,
            current_slot.saturating_sub(1u64),
            current_slot,
            equivocating_indices,
        )
    }

    /// Spec: `compute_adversarial_weight`.
    fn compute_adversarial_weight<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        start_slot: Slot,
        end_slot: Slot,
        _current_slot: Slot,
        equivocating_indices: &BTreeSet<u64>,
    ) -> u64 {
        let maximum_weight = estimate_committee_weight_between_slots::<E>(
            balance_source.total_active_balance,
            start_slot,
            end_slot,
        );
        let max_adversarial = (maximum_weight / 100).saturating_mul(self.byzantine_threshold);

        let equivocation_score =
            self.get_equivocation_score(balance_source, start_slot, end_slot, equivocating_indices);

        max_adversarial.saturating_sub(equivocation_score)
    }

    /// Spec: `get_equivocation_score`.
    /// Uses HEAD state committee assignments (via `is_in_committee_range`).
    fn get_equivocation_score(
        &self,
        balance_source: &BalanceSourceData,
        start_slot: Slot,
        end_slot: Slot,
        equivocating_indices: &BTreeSet<u64>,
    ) -> u64 {
        let mut score = 0u64;
        for &val_idx in equivocating_indices {
            let idx = val_idx as usize;
            let balance = balance_source
                .effective_balances
                .get(idx)
                .copied()
                .unwrap_or(0);
            if balance == 0 {
                continue;
            }
            if self.is_in_committee_range(idx, start_slot, end_slot) {
                score = score.saturating_add(balance);
            }
        }
        score
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
    ) -> bool {
        let current_target = self.get_current_target::<E>(head_root, current_slot, proto_array);
        if current_target == *unrealized_justified_checkpoint {
            return true;
        }

        let honest_ffg = self.compute_honest_ffg_support::<E>(
            head_root,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        );
        let total_active = self.current_balance_source.total_active_balance;

        // 3 * honest_ffg >= 1 * total_active (i.e. honest > 1/3)
        3u128 * honest_ffg as u128 >= total_active as u128
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
    ) -> bool {
        let honest_ffg = self.compute_honest_ffg_support::<E>(
            head_root,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        );
        let total_active = self.current_balance_source.total_active_balance;

        // 3 * honest_ffg >= 2 * total_active (i.e. honest > 2/3)
        let _ = unrealized_justified_checkpoint; // used only in will_no_conflicting
        3u128 * honest_ffg as u128 >= 2u128 * total_active as u128
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
    ) -> u64 {
        let current_target = self.get_current_target::<E>(head_root, current_slot, proto_array);
        let bs = &self.current_balance_source;
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
            let balance = bs.effective_balances.get(val_idx).copied().unwrap_or(0);
            if balance == 0 {
                continue;
            }
            // Spec: get_checkpoint_for_block(store, latest_messages[i].root,
            //        get_latest_message_epoch(latest_messages[i]))
            // Use the VOTE's epoch, not the current epoch.
            let vote_root = vote.current_root();
            let vote_epoch = vote.current_epoch();
            let vote_target =
                if cached_valid && vote_root == cached_root && vote_epoch == cached_epoch {
                    cached_target
                } else {
                    let cp = self.get_checkpoint_for_block::<E>(vote_root, vote_epoch, proto_array);
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
        score
    }

    /// Spec: `compute_honest_ffg_support_for_current_target`.
    fn compute_honest_ffg_support<E: EthSpec>(
        &self,
        head_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> u64 {
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let total_active = self.current_balance_source.total_active_balance;

        let ffg_support = self.get_current_target_score::<E>(
            head_root,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        );

        let epoch_start = current_epoch.start_slot(E::slots_per_epoch());
        let ffg_weight_till_now = estimate_committee_weight_between_slots::<E>(
            total_active,
            epoch_start,
            current_slot.saturating_sub(1u64),
        );

        let remaining_ffg_weight = total_active.saturating_sub(ffg_weight_till_now);
        let remaining_honest = (remaining_ffg_weight / 100)
            .saturating_mul(100u64.saturating_sub(self.byzantine_threshold));

        let max_adversarial_till_now =
            (ffg_weight_till_now / 100).saturating_mul(self.byzantine_threshold);
        let min_honest_support = ffg_support.saturating_sub(max_adversarial_till_now);

        min_honest_support.saturating_add(remaining_honest)
    }

    // -----------------------------------------------------------------------
    // Proto-array accessors (read-only)
    // -----------------------------------------------------------------------

    fn block_slot(&self, root: Hash256, proto_array: &ProtoArray) -> Slot {
        proto_array
            .indices
            .get(&root)
            .and_then(|&idx| proto_array.nodes.get(idx))
            .map(|n| n.slot)
            .unwrap_or_else(|| Slot::new(0))
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
    ) -> bool {
        let ancestor_slot = self.block_slot(ancestor_root, proto_array);
        proto_array
            .iter_block_roots(&block_root)
            .any(|(root, slot)| slot <= ancestor_slot && root == ancestor_root)
    }

    /// Get ordered ancestor roots from `terminal_root` (exclusive) to `block_root` (inclusive).
    fn get_ancestor_roots(
        &self,
        block_root: Hash256,
        terminal_root: Hash256,
        proto_array: &ProtoArray,
    ) -> Vec<Hash256> {
        let terminal_slot = self.block_slot(terminal_root, proto_array);
        let mut roots: Vec<Hash256> = proto_array
            .iter_block_roots(&block_root)
            .take_while(|(root, _)| *root != terminal_root)
            .filter(|(_, slot)| *slot > terminal_slot)
            .map(|(root, _)| root)
            .collect();
        roots.reverse();
        roots
    }

    /// Get the unrealized justified checkpoint for a block.
    fn unrealized_justification_of(&self, root: Hash256, proto_array: &ProtoArray) -> Checkpoint {
        proto_array
            .indices
            .get(&root)
            .and_then(|&idx| proto_array.nodes.get(idx))
            .and_then(|n| n.unrealized_justified_checkpoint)
            .unwrap_or_default()
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
    ) -> Checkpoint {
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        self.get_checkpoint_for_block::<E>(head_root, current_epoch, proto_array)
    }

    /// Get checkpoint block root at the given epoch for the chain ending at `block_root`.
    fn get_checkpoint_for_block<E: EthSpec>(
        &self,
        block_root: Hash256,
        epoch: types::Epoch,
        proto_array: &ProtoArray,
    ) -> Checkpoint {
        let cp_root = self.get_checkpoint_block_root::<E>(block_root, epoch, proto_array);
        Checkpoint {
            epoch,
            root: cp_root,
        }
    }

    /// Find the block root at the epoch boundary for the given chain.
    fn get_checkpoint_block_root<E: EthSpec>(
        &self,
        block_root: Hash256,
        epoch: types::Epoch,
        proto_array: &ProtoArray,
    ) -> Hash256 {
        let epoch_start_slot = epoch.start_slot(E::slots_per_epoch());
        proto_array
            .iter_block_roots(&block_root)
            .find(|(_, slot)| *slot <= epoch_start_slot)
            .map(|(root, _)| root)
            .unwrap_or(block_root)
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
    ) -> HashMap<Hash256, u64> {
        let chain = self.get_ancestor_roots(chain_tip, terminal_root, proto_array);
        if chain.is_empty() {
            return HashMap::new();
        }

        // Build node_index → chain_position map for O(1) membership checks during walks.
        let mut index_to_position: HashMap<usize, usize> = HashMap::with_capacity(chain.len());
        for (pos, root) in chain.iter().enumerate() {
            if let Some(&node_idx) = proto_array.indices.get(root) {
                index_to_position.insert(node_idx, pos);
            }
        }

        let terminal_slot = self.block_slot(terminal_root, proto_array);

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
            let balance = balance_source
                .effective_balances
                .get(val_idx)
                .copied()
                .unwrap_or(0);
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

        scores
    }

    /// Like `is_one_confirmed` but uses a precomputed attestation score instead of
    /// iterating all validators.
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
    ) -> bool {
        let block_slot = self.block_slot(block_root, proto_array);
        let Some(parent_root) = self.parent_root(block_root, proto_array) else {
            return false;
        };
        let parent_slot = self.block_slot(parent_root, proto_array);

        let support = attestation_score;
        let proposer_score = self.compute_proposer_score::<E>(balance_source);
        let maximum_support = estimate_committee_weight_between_slots::<E>(
            balance_source.total_active_balance,
            parent_slot.saturating_add(1u64),
            current_slot.saturating_sub(1u64),
        );
        let support_discount = self.get_support_discount::<E>(
            balance_source,
            block_root,
            block_slot,
            parent_root,
            parent_slot,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        );
        let adversarial_weight = self.get_adversarial_weight::<E>(
            balance_source,
            block_root,
            current_slot,
            proto_array,
            equivocating_indices,
        );

        let lhs = 2u128 * support as u128 + support_discount as u128;
        let rhs =
            maximum_support as u128 + proposer_score as u128 + 2u128 * adversarial_weight as u128;

        lhs > rhs
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
}
