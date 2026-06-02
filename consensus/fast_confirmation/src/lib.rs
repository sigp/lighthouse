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
//! We diverge in several ways, all behaviorally equivalent:
//!
//! 1. **Batch score precomputation** (`precompute_chain_attestation_scores`): iterates
//!    validators once, walks each vote to the deepest canonical chain block, then builds
//!    a suffix-sum score array. Reduces cost from O(B × V × depth) to O(V × depth + B).
//!    Used by `find_latest_confirmed_descendant` and `is_confirmed_chain_safe`.
//!
//! 2. **`is_one_confirmed_with_score`**: variant of `is_one_confirmed` that takes a
//!    precomputed attestation score instead of calling `get_attestation_score`. The rest
//!    of the logic (proposer score, support discount, adversarial weight) is identical.
//!    Likewise the FFG support (`compute_honest_ffg_support`) is computed once per run and
//!    threaded into `will_no_conflicting_checkpoint_be_justified` /
//!    `will_current_target_be_justified` rather than recomputed per call.
//!
//! 3. **Multi-entry vote-root / checkpoint memos**: inside
//!    `precompute_chain_attestation_scores` and `get_current_target_score`, each distinct
//!    vote root (or root+epoch) is resolved (HashMap lookup + ancestor walk) at most once
//!    across the whole validator set and memoized. Real mainnet votes are scattered by
//!    validator index, so a single-element cache thrashes; the memos turn ~1M ancestor
//!    walks into ~tens. Keyed on the root prefix via [`IdentityU64Hasher`] to avoid
//!    SipHashing 32-byte roots per validator (full key stored for collision safety).
//!
//! 4. **Single-pass balance rebuild** (`BalanceSourceData::build_for_epochs`): the
//!    head/current/previous balance sources are rebuilt from one validator-set iteration
//!    over the (usually two) distinct epochs rather than one iteration each.
//!
//! The original spec functions (`is_one_confirmed`, `get_attestation_score`) are not
//! present — only the optimized equivalents are used.

mod balance_source;
pub mod metrics;
mod slot_assignments;

pub use balance_source::BalanceSourceData;
use slot_assignments::SlotAssignments;
pub use slot_assignments::UNSET_SLOT;

use proto_array::core::{ProtoArray, VoteTracker};
use std::collections::{BTreeSet, HashMap};
use tracing::{debug, debug_span};
use types::{BeaconState, Checkpoint, Epoch, EthSpec, Hash256, Slot};

#[derive(Debug, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Error {
    NodeNotFound(Hash256),
    AncestorNotFound {
        block: Hash256,
        slot: Slot,
    },
    UnrealizedJustificationNotFound(Hash256),
    CheckpointBlockNotFound {
        block: Hash256,
        epoch: types::Epoch,
    },
    MissingPrecomputedScore(Hash256),
    BlockEpochNone(Hash256),
    CommitteeCache(String),
    UnsetSlotAssignment(usize),
    /// The state's epoch window does not cover `current_slot`'s epoch.
    /// This means the state is too stale to provide committee assignments for the
    /// slots FCR needs to query.
    StaleStateForAssignments {
        current_slot_epoch: Epoch,
        state_epoch: Epoch,
    },
}

/// Per-mille adjustment factor for committee weight estimates that don't cover a full epoch.
const COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR: u64 = 5;

/// Identity hasher for `u64` keys that are already well-distributed (block-root byte
/// prefixes). The per-vote memoization loops resolve each vote's root/checkpoint at most
/// once across the whole validator set; keying those memos on a root prefix with this
/// no-op hasher avoids SipHashing a 32-byte `Hash256` per validator (~1M times). Hash
/// quality is irrelevant to correctness — the memos store and compare the full key.
#[derive(Default)]
struct IdentityU64Hasher(u64);
impl std::hash::Hasher for IdentityU64Hasher {
    fn finish(&self) -> u64 {
        self.0
    }
    fn write(&mut self, _: &[u8]) {}
    fn write_u64(&mut self, n: u64) {
        self.0 = n;
    }
}
type FastMap<V> = HashMap<u64, V, std::hash::BuildHasherDefault<IdentityU64Hasher>>;

/// First 8 bytes of a block root as a `u64` (roots are uniformly distributed, so this is a
/// good hash). Used as the memo key; the stored full root disambiguates the rare collision.
fn root_prefix(root: &Hash256) -> u64 {
    u64::from_le_bytes(
        root.as_slice()[..8]
            .try_into()
            .expect("Hash256 is 32 bytes"),
    )
}

/// Index of `e` in `epochs`, appending it if absent. Used to dedup the (few) epochs needed by
/// a fused balance-source rebuild so coinciding sources share one validator pass.
fn dedup_epoch_index(epochs: &mut Vec<Epoch>, e: Epoch) -> usize {
    match epochs.iter().position(|x| *x == e) {
        Some(i) => i,
        None => {
            epochs.push(e);
            epochs.len() - 1
        }
    }
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

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

    // === Balance source snapshots (paired with the observed-justified checkpoints) ===
    /// Snapshot at `previous_epoch_observed_justified_checkpoint`; used to re-confirm.
    pub previous_balance_source: BalanceSourceData,
    /// Snapshot at `current_epoch_observed_justified_checkpoint`; used to advance.
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
    /// Approximates the spec's `get_pulled_up_head_state` (FCR spec, "State helpers").
    /// The spec advances the head state via `process_slots` to the current epoch's
    /// start; this implementation reads from the head state directly and skips
    /// `process_slots`, accepting that validator activations/exits/slashings due
    /// to be realized at an unprocessed epoch boundary are missing.
    ///
    /// `checkpoint.root` is repurposed here to carry the **dependent root** of
    /// the cached epoch (the block at the previous epoch's last slot), used as
    /// the chain-identity component of the cache key — *not* a justified-block
    /// root like the anchored snapshots' `checkpoint.root`.
    head_balance_source: BalanceSourceData,

    // === Internal bookkeeping ===
    /// The last slot at which `update_fast_confirmation_variables` ran.
    /// Prevents double-rotation when `recompute_head` runs multiple times per slot.
    /// `None` means no update has occurred yet (avoids using Slot(0) as sentinel,
    /// since slot 0 is a real slot with real committee assignments).
    last_update_slot: Option<Slot>,

    /// When `true`, `on_fast_confirmation` updates tracking variables but skips
    /// the `get_latest_confirmed` call. The spec test runner runs FCR implicitly
    /// at the start of each slot; the Lighthouse test harness mirrors that by
    /// calling `get_latest_confirmed` explicitly per check, so the auto-run is
    /// disabled here. Always `false` in production.
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
    /// does not update `confirmed_root`. Call `get_latest_confirmed` explicitly
    /// when the test needs the confirmation result.
    pub fn set_spec_test_mode(&mut self, enabled: bool) {
        self.spec_test_mode = enabled;
    }

    /// Directly set committee slot assignments. Intended for synthetic-data benchmarks
    /// that lack a real `BeaconState`; not used in production.
    ///
    /// `assignments` must be in the canonical 3-column layout
    /// (`validator_count * 3`). Use `UNSET_SLOT` for columns with no assignment.
    pub fn test_set_head_slot_assignments(&mut self, assignments: Vec<Slot>) {
        self.head_assignments.test_set_from(assignments);
    }

    /// Rebuild the head / current / previous balance sources from `state`.
    ///
    /// Each source keeps its own cache key and is rebuilt only when stale (the previous
    /// `rebuild_head_balance_source` + `update_balance_sources`). When more than one is stale —
    /// e.g. at an epoch boundary — they are built from a **single** validator-set pass
    /// (`build_for_epochs`) instead of one O(V) iteration per source. The head and current
    /// sources usually resolve to the same epoch, so their per-validator data is computed once
    /// and shared. Per-source semantics are unchanged.
    fn rebuild_balance_sources<E: EthSpec>(
        &mut self,
        state: &BeaconState<E>,
        current_slot: Slot,
    ) -> Result<(), Error> {
        let current_epoch = current_slot.epoch(E::slots_per_epoch());

        // Head source: keyed on the dependent root (block at the last slot of the previous
        // epoch). Two chains share the same validator-set view at `current_epoch` iff they
        // share this root, so it is the right chain-identity cache key. A re-org that pivots
        // before the previous-epoch boundary changes it, forcing a rebuild.
        let head_checkpoint = Checkpoint {
            epoch: current_epoch,
            root: *state
                .get_block_root(
                    current_epoch
                        .start_slot(E::slots_per_epoch())
                        .saturating_sub(1u64),
                )
                .map_err(|e| Error::CommitteeCache(format!("dep_root lookup: {e:?}")))?,
        };
        let head_epoch = if state.current_epoch() < current_epoch {
            state
                .next_epoch()
                .map_err(|e| Error::CommitteeCache(format!("{e:?}")))?
        } else {
            state.current_epoch()
        };
        let head_stale = self.head_balance_source.checkpoint != head_checkpoint
            || self.head_balance_source.effective_balances.is_empty();

        // Current/previous sources: keyed on the observed-justified checkpoints; rebuilt when
        // those rotate (epoch boundary).
        let current_cp = self.current_epoch_observed_justified_checkpoint;
        let previous_cp = self.previous_epoch_observed_justified_checkpoint;
        let current_stale = self.current_balance_source.checkpoint != current_cp;
        let previous_stale = self.previous_balance_source.checkpoint != previous_cp;

        if !head_stale && !current_stale && !previous_stale {
            return Ok(());
        }

        // Collect the distinct epochs needed by the stale sources (head & current coincide in
        // the common case), then resolve all balances in one pass.
        let mut epochs: Vec<Epoch> = Vec::with_capacity(3);
        let head_i = head_stale.then(|| dedup_epoch_index(&mut epochs, head_epoch));
        let current_i =
            current_stale.then(|| dedup_epoch_index(&mut epochs, state.current_epoch()));
        let previous_i =
            previous_stale.then(|| dedup_epoch_index(&mut epochs, state.previous_epoch()));

        let (slashed, per_epoch) = BalanceSourceData::build_for_epochs(state, &epochs);

        if let Some(i) = head_i {
            let eb = &per_epoch[i];
            self.head_balance_source = BalanceSourceData::from_parts(
                head_checkpoint,
                eb.effective_balances.clone(),
                eb.total_active_balance,
                slashed.clone(),
            );
        }
        if let Some(i) = current_i {
            let eb = &per_epoch[i];
            self.current_balance_source = BalanceSourceData::from_parts(
                current_cp,
                eb.effective_balances.clone(),
                eb.total_active_balance,
                slashed.clone(),
            );
        }
        if let Some(i) = previous_i {
            let eb = &per_epoch[i];
            self.previous_balance_source = BalanceSourceData::from_parts(
                previous_cp,
                eb.effective_balances.clone(),
                eb.total_active_balance,
                slashed,
            );
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Top-level entry point: on_fast_confirmation
    // -----------------------------------------------------------------------

    /// Spec: `on_fast_confirmation(fcr_store)`.
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

        // Rebuild committee assignments from the head state.
        {
            let _span = debug_span!("fcr_rebuild_assignments").entered();
            self.head_assignments.rebuild::<E>(state, current_slot)?;
        }

        // Rebuild the head/current/previous balance sources (whichever are stale) in one
        // shared validator-set pass.
        {
            let _span = debug_span!("fcr_rebuild_balances").entered();
            self.rebuild_balance_sources::<E>(state, current_slot)?;
        }

        if !self.spec_test_mode {
            let _span = debug_span!("fcr_get_latest_confirmed").entered();
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
            && self
                .block_epoch::<E>(observed_jcp.root, proto_array)
                .is_some_and(|e| e.saturating_add(1u64) == current_epoch)
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
        let precomputed_scores = {
            let _s = debug_span!("fcr_precompute").entered();
            self.precompute_chain_attestation_scores(
                head_root,
                latest_confirmed_root,
                &self.current_balance_source,
                proto_array,
                votes,
                equivocating_indices,
            )?
        };
        // FFG support is identical for every FFG check in this run (constant head, slot and
        // vote set), so compute it once and thread it into the `will_*` checks below — the
        // same precompute-and-pass-in pattern as the attestation scores above. This avoids
        // recomputing the O(V) FFG vote pass up to three times per run.
        let honest_ffg = {
            let _s = debug_span!("fcr_honest_ffg").entered();
            self.compute_honest_ffg_support::<E>(
                head_root,
                current_slot,
                proto_array,
                votes,
                equivocating_indices,
            )?
        };

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
            honest_ffg,
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
            let _s = debug_span!("fcr_loop1").entered();
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
            let _s = debug_span!("fcr_loop2").entered();
            let canonical_roots =
                self.get_ancestor_roots(head_root, confirmed_root, proto_array)?;

            let mut tentative_confirmed_root = confirmed_root;

            for block_root in &canonical_roots {
                let block_epoch = self.block_epoch::<E>(*block_root, proto_array);
                let tentative_epoch = self.block_epoch::<E>(tentative_confirmed_root, proto_array);

                // When crossing into current epoch, check FFG.
                if block_epoch > tentative_epoch {
                    let ffg_ok = self.will_current_target_be_justified(honest_ffg)?;
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
            // Reuse `no_conflict` from above: `will_no_conflicting_checkpoint_be_justified` here
            // takes identical arguments and is deterministic, so its result is unchanged.
            let promote_check2 = tentative_voting_source_epoch
                .is_some_and(|e| e.saturating_add(2u64) >= current_epoch)
                && (is_epoch_start || no_conflict);

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
    ///
    /// `honest_ffg` is the precomputed `compute_honest_ffg_support` result (identical for
    /// every FFG check in a single `find_latest_confirmed_descendant` run, so it is computed
    /// once and threaded in — same pattern as `is_one_confirmed_with_score`'s precomputed
    /// attestation score). This avoids recomputing the O(V) FFG vote pass per call.
    fn will_no_conflicting_checkpoint_be_justified<E: EthSpec>(
        &self,
        head_root: Hash256,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        proto_array: &ProtoArray,
        honest_ffg: u64,
    ) -> Result<bool, Error> {
        let current_target = self.get_current_target::<E>(head_root, current_slot, proto_array)?;
        if current_target == *unrealized_justified_checkpoint {
            return Ok(true);
        }

        let total_active = self.head_balance_source.total_active_balance;

        // 3 * honest_ffg > 1 * total_active (i.e. honest strictly > 1/3)
        Ok(3u128 * honest_ffg as u128 > total_active as u128)
    }

    /// Spec: `will_current_target_be_justified`.
    ///
    /// `honest_ffg` is the precomputed `compute_honest_ffg_support` result (see
    /// `will_no_conflicting_checkpoint_be_justified`).
    fn will_current_target_be_justified(&self, honest_ffg: u64) -> Result<bool, Error> {
        let total_active = self.head_balance_source.total_active_balance;

        // 3 * honest_ffg >= 2 * total_active (i.e. honest > 2/3)
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

        // Memoize get_checkpoint_for_block by (vote root, vote epoch). Most validators share
        // a small set of (root, epoch) pairs, so each is resolved (an O(depth) ancestor walk)
        // at most once across the whole validator set instead of once per validator. Keyed on
        // the root prefix for cheap hashing; the stored (root, epoch) disambiguates collisions.
        let mut memo: FastMap<(Hash256, Epoch, Option<Checkpoint>)> = FastMap::default();

        for (val_idx, vote) in votes.iter().enumerate() {
            // Skip validators without a vote (spec: `i in store.latest_messages`).
            let vote_root = vote.current_root();
            if vote_root.is_zero() {
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
            let vote_epoch = vote.latest_message_slot().epoch(E::slots_per_epoch());
            let key =
                root_prefix(&vote_root) ^ vote_epoch.as_u64().wrapping_mul(0x9E37_79B9_7F4A_7C15);
            let cached = memo
                .get(&key)
                .and_then(|(r, e, t)| (*r == vote_root && *e == vote_epoch).then_some(*t));
            let vote_target = match cached {
                Some(t) => t,
                None => {
                    let t = match self.get_checkpoint_for_block::<E>(
                        vote_root,
                        vote_epoch,
                        proto_array,
                    ) {
                        Ok(cp) => Some(cp),
                        // Vote references a block pruned from proto_array — skip it.
                        Err(Error::CheckpointBlockNotFound { .. }) => None,
                        Err(e) => return Err(e),
                    };
                    memo.insert(key, (vote_root, vote_epoch, t));
                    t
                }
            };
            if vote_target.is_some_and(|t| t == current_target) {
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
            .map(|n| n.slot())
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
            .map(|n| n.slot().epoch(E::slots_per_epoch()))
    }

    fn parent_root(&self, root: Hash256, proto_array: &ProtoArray) -> Option<Hash256> {
        proto_array
            .indices
            .get(&root)
            .and_then(|&idx| proto_array.nodes.get(idx))
            .and_then(|n| n.parent())
            .and_then(|parent_idx| proto_array.nodes.get(parent_idx))
            .map(|n| n.root())
    }

    /// Return `true` if the block's execution payload is `Optimistic` or `Invalid`.
    /// Pre-bellatrix `Irrelevant` payloads and missing nodes are treated as not
    /// optimistic (the spec MUST applies post-merge). A missing node will be
    /// rejected later by `block_slot`, so this returning `false` here is safe.
    fn is_optimistic_or_invalid(&self, root: Hash256, proto_array: &ProtoArray) -> bool {
        proto_array
            .indices
            .get(&root)
            .and_then(|&idx| proto_array.nodes.get(idx))
            .and_then(|n| n.execution_status().ok())
            .is_some_and(|s| s.is_optimistic_or_invalid())
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
            .and_then(|n| n.unrealized_justified_checkpoint())
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
            .and_then(|n| n.unrealized_justified_checkpoint())
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
        let block_epoch = node.slot().epoch(E::slots_per_epoch());
        if current_epoch > block_epoch {
            node.unrealized_justified_checkpoint().map(|cp| cp.epoch)
        } else {
            Some(node.justified_checkpoint().epoch)
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

        // Memoize vote-root -> deepest canonical position. Most validators vote for a small
        // set of recent roots, so each root is resolved (proto-array lookup + ancestor walk)
        // at most once across the validator set instead of once per validator. Keyed on the
        // root prefix for cheap hashing; the stored full root disambiguates collisions.
        let mut memo: FastMap<(Hash256, Option<usize>)> = FastMap::default();

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

            let key = root_prefix(&vote_root);
            let cached = memo
                .get(&key)
                .and_then(|(r, p)| (*r == vote_root).then_some(*p));
            let pos = match cached {
                Some(p) => p,
                None => {
                    // Resolve the vote root and walk ancestors to the deepest canonical block.
                    let p = proto_array.indices.get(&vote_root).and_then(|&start_idx| {
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
                            if node.slot() <= terminal_slot {
                                break;
                            }
                            match node.parent() {
                                Some(parent_idx) => current_idx = parent_idx,
                                None => break,
                            }
                        }
                        deepest_pos
                    });
                    memo.insert(key, (vote_root, p));
                    p
                }
            };

            if let Some(pos) = pos {
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
    ///
    /// Spec MUST: returns `false` if the block's execution status is optimistic
    /// or invalid (i.e. not VALID per Optimistic-sync), so an unvalidated payload
    /// can never be fed to the EL as `safe_block_hash`.
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
        if self.is_optimistic_or_invalid(block_root, proto_array) {
            return Ok(false);
        }

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
        // safety_threshold = (maximum_support + proposer_score + 2 * adversarial_weight - support_discount) / 2
        // with an underflow guard
        let numerator_without_discount = maximum_support + proposer_score + 2 * adversarial_weight;
        let safety_threshold = if support_discount < numerator_without_discount {
            (numerator_without_discount - support_discount) / 2
        } else {
            0
        };

        Ok(support > safety_threshold)
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
///
/// Spec uses ceiling division: `(estimate + 999) // 1000`. The function exists to
/// conservatively over-estimate committee weight; flooring would under-estimate and
/// weaken the safety threshold.
pub fn adjust_committee_weight_estimate_to_ensure_safety(estimate: u64) -> u64 {
    let ceil = estimate.saturating_add(999) / 1000;
    ceil.saturating_mul(1000u64.saturating_add(COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR))
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
        // Ceiling division: ceil(1000/1000) * 1005 = 1 * 1005 = 1005
        assert_eq!(
            adjust_committee_weight_estimate_to_ensure_safety(1000),
            1005
        );
        // Ceiling division: ceil(999/1000) * 1005 = 1 * 1005 = 1005 (NOT 0)
        assert_eq!(adjust_committee_weight_estimate_to_ensure_safety(999), 1005);
        // Ceiling division: ceil(1500/1000) * 1005 = 2 * 1005 = 2010
        assert_eq!(
            adjust_committee_weight_estimate_to_ensure_safety(1500),
            2010
        );
        // Edge case: 0 -> ceil(0/1000) = 0
        assert_eq!(adjust_committee_weight_estimate_to_ensure_safety(0), 0);
    }
}
