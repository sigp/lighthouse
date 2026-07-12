//! Fast Confirmation Rule (FCR) for Ethereum consensus.
//!
//! Implements the Fast Confirmation Rule from the latest merged consensus-specs. FCR is a pure read-only
//! observer of fork-choice state that computes a `confirmed_root` — a block guaranteed
//! to remain canonical under standard assumptions (synchrony + <25% Byzantine).
//!
//! This module just reads proto_array, votes, and checkpoints via shared references and writes
//! only its own state.
//!
//! ## Spec divergences (performance optimizations)
//!
//! We diverge in several ways, all behaviorally equivalent:
//!
//! 1. **Batch score precomputation** (`precompute_chain_attestation_scores`): iterates
//!    validators once, walks each vote to the deepest canonical chain block, then builds
//!    a suffix-sum score array.
//!
//! 2. **Cached spec helpers**: `is_one_confirmed` still reads as
//!    `support > compute_safety_threshold`, but `get_attestation_score` is backed by a
//!    precomputed chain score cache. The FFG predicates compute `compute_honest_ffg_support`
//!    internally; their call sites are short-circuited, so the O(V) FFG sweep only runs near
//!    epoch boundaries (and at most a couple of times) rather than every slot.
//!
//! 3. **Vote-root balance aggregation** (`optimizations::RootBalanceMap`): before ancestor
//!    lookups, validators with the same vote root (or root+epoch) are collapsed into one
//!    balance. Real mainnet votes are scattered by validator index, so caching only the previous
//!    root thrashes; aggregation turns ~1M per-validator ancestor/checkpoint lookups into one
//!    lookup per distinct vote. This is a readability deviation from the spec loop, but is kept
//!    because the 1M-validator `get_latest_confirmed` benches improve by ~28-82%.
//!
//! 4. **Snapshot balance sources** (`BalanceSourceData`): the current/previous observed-justified
//!    sources are rebuilt only at the epoch-boundary rotation (bundled with their checkpoint in
//!    `CheckpointAndBalance`), and the head source only when its `BalanceSourceKey` changes
//!    (the epoch boundary root normally, per head block once the epoch contains a slashing) — instead
//!    of re-scanning the validator set every slot.
//!
//! The visible algorithm deliberately keeps the spec function names and control-flow shape;
//! the caches are implementation details behind those helpers.

mod balance_source;
pub mod metrics;
pub mod optimizations;
mod slot_assignments;

pub use balance_source::{BalanceSourceData, BalanceSourceKey};
pub use optimizations::CheckpointAndBalance;
use optimizations::{AttestationScoreCache, HonestFfgSupportCache};
use slot_assignments::{SlotAssignments, WindowEpoch, attestation_shuffling_id};

use proto_array::core::{ProtoArray, ProtoNode, VoteTracker};
use safe_arith::{ArithError, SafeArith};
use std::collections::BTreeSet;
use tracing::{debug, debug_span};
use types::{BeaconState, BeaconStateError, ChainSpec, Checkpoint, Epoch, EthSpec, Hash256, Slot};

#[derive(Debug, strum::IntoStaticStr)]
#[strum(serialize_all = "snake_case")]
pub enum Error {
    NodeNotFound(Hash256),
    NodeHasNoBlockHash(Hash256),
    ParentRootNotFound(Hash256),
    UnableToObtainHeadState(String),
    UnableToObtainCheckpointState(String),
    MissingCheckpointState(Checkpoint),
    AncestorNotFound { block: Hash256, slot: Slot },
    UnrealizedJustificationNotFound(Hash256),
    CheckpointBlockNotFound { block: Hash256, epoch: types::Epoch },
    HeadCheckpointNotFound(Hash256),
    MissingPrecomputedScore(Hash256),
    BlockEpochNone(Hash256),
    CommitteeCacheUninitialized(String),
    BlockRootsOutOfBounds(String),
    SlashingsOutOfBounds(String),
    IndexOutOfBounds(usize),
    AttestationShufflingIdError(BeaconStateError),
    CommitteeCacheError(BeaconStateError),
    ArithError(ArithError),
}

impl From<ArithError> for Error {
    fn from(e: ArithError) -> Self {
        Error::ArithError(e)
    }
}

/// Rich outcome of `is_one_confirmed` to track metrics in case of `BelowThreshold`..
enum Confirmation {
    Confirmed,
    NotConfirmed(Unconfirmed),
}

/// Why a block failed `is_one_confirmed`.
enum Unconfirmed {
    /// The block's execution status is optimistic or invalid.
    Optimistic,
    /// Attestation support did not exceed the safety threshold.
    BelowThreshold { support: u64, safety_threshold: u64 },
}

impl Confirmation {
    fn is_confirmed(&self) -> bool {
        match self {
            Confirmation::Confirmed => true,
            Confirmation::NotConfirmed(_) => false,
        }
    }
}

const COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR: u64 = 5;

/// The Fast Confirmation Rule state
#[derive(Debug)]
pub struct FastConfirmationRule {
    // === Output ===
    /// Fed into `safe_block_hash` for the EL.
    pub confirmed_root: Hash256,

    // === Tracking state (spec's 6 new store fields) ===
    /// Spec `previous_epoch_observed_justified_checkpoint` with its `get_previous_balance_source`
    /// snapshot; used to re-confirm.
    pub previous_epoch_observed_justified: CheckpointAndBalance,
    /// Spec `current_epoch_observed_justified_checkpoint` with its `get_current_balance_source`
    /// snapshot; used to advance.
    pub current_epoch_observed_justified: CheckpointAndBalance,
    pub previous_epoch_greatest_unrealized_checkpoint: Checkpoint,
    pub previous_slot_head: Hash256,
    pub current_slot_head: Hash256,

    // === Config ===
    pub byzantine_threshold: u64,
    /// Proposer score boost percentage from ChainSpec (e.g. 40 for mainnet).
    proposer_score_boost: u64,

    // === Committee data from head state ===
    /// Per-validator committee slot assignments across the last 3 epochs.
    /// Used by `get_block_support_between_slots` and `compute_adversarial_weight`.
    slot_assignments: SlotAssignments,

    // === FFG data from the head state ===
    /// Built from the spec's `get_pulled_up_head_state`. Keyed (via `BalanceSourceData.key`)
    /// on the head's epoch boundary root — or the head block root itself once the epoch contains a
    /// slashing — so a reorg past the previous-epoch boundary or an intra-epoch slashing
    /// rebuilds it.
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

    /// Initialize FCR from the finalized checkpoint, its checkpoint state and the head state,
    /// building the balance sources and committee assignments up front (each tagged with its own
    /// `BalanceSourceKey` derived from the state). The spec seeds both observed-justified
    /// checkpoints with the finalized checkpoint, so both balance sources come from
    /// `checkpoint_state` (spec: `store.checkpoint_states[finalized_checkpoint]`); the
    /// head-derived caches come from `head_state`, whose block root is `head_root`.
    /// `byzantine_threshold` is clamped to [0, 25].
    pub fn new<E: EthSpec>(
        head_root: Hash256,
        head_state: &BeaconState<E>,
        finalized_checkpoint: Checkpoint,
        checkpoint_state: &BeaconState<E>,
        byzantine_threshold: u64,
        proposer_score_boost: u64,
        spec: &ChainSpec,
    ) -> Result<Self, Error> {
        let byzantine_threshold = byzantine_threshold.min(Self::MAX_BYZANTINE_THRESHOLD);
        // Sanity: the supplied state must be the checkpoint's state, advanced to the
        // checkpoint's epoch.
        if checkpoint_state.current_epoch() != finalized_checkpoint.epoch {
            return Err(Error::MissingCheckpointState(finalized_checkpoint));
        }
        let checkpoint_balance =
            BalanceSourceData::new(checkpoint_state, finalized_checkpoint.root)?;
        Ok(Self {
            confirmed_root: finalized_checkpoint.root,
            previous_epoch_observed_justified: CheckpointAndBalance::new(
                finalized_checkpoint,
                checkpoint_balance.clone(),
            ),
            current_epoch_observed_justified: CheckpointAndBalance::new(
                finalized_checkpoint,
                checkpoint_balance,
            ),
            previous_epoch_greatest_unrealized_checkpoint: finalized_checkpoint,
            previous_slot_head: finalized_checkpoint.root,
            current_slot_head: finalized_checkpoint.root,
            byzantine_threshold,
            proposer_score_boost,
            slot_assignments: SlotAssignments::new(head_state, spec, None)?,
            head_balance_source: BalanceSourceData::new(head_state, head_root)?,
            last_update_slot: None,
            spec_test_mode: false,
        })
    }

    /// Enable spec test mode: `on_fast_confirmation` still tracks variables but
    /// does not update `confirmed_root`. Call `get_latest_confirmed` explicitly
    /// when the test needs the confirmation result.
    pub fn set_spec_test_mode(&mut self, enabled: bool) {
        self.spec_test_mode = enabled;
    }

    /// Directly set head balances for synthetic-data benchmarks; not used in production.
    pub fn test_set_head_balance_source(&mut self, balance_source: BalanceSourceData) {
        self.head_balance_source = balance_source;
    }

    /// Top-level entry point. Spec: `on_fast_confirmation(fcr_store)`.
    ///
    /// Called after head selection, while the fork-choice read lock is held.
    /// All parameters are borrowed from fork choice. The `head_state` is used to
    /// rebuild the head balance source and committee assignments; `checkpoint_state`
    /// backs the observed-justified balance source at the epoch-boundary rotation
    /// (spec: `store.checkpoint_states[checkpoint]`). Callers should obtain the
    /// required checkpoint via `checkpoint_state_needed` and may pass `None` when
    /// it returns `None`.
    #[allow(clippy::too_many_arguments)]
    pub fn on_fast_confirmation<E: EthSpec>(
        &mut self,
        head_root: Hash256,
        finalized_checkpoint: &Checkpoint,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
        head_state: &BeaconState<E>,
        checkpoint_state: Option<&BeaconState<E>>,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let _span = debug_span!("fcr_on_fast_confirmation", slot = %current_slot).entered();

        self.update_fast_confirmation_variables::<E>(
            head_root,
            unrealized_justified_checkpoint,
            current_slot,
            head_state,
            checkpoint_state,
            spec,
        )?;

        if !self.spec_test_mode {
            let _span = debug_span!("fcr_get_latest_confirmed").entered();
            self.confirmed_root = self.get_latest_confirmed::<E>(
                head_root,
                finalized_checkpoint,
                unrealized_justified_checkpoint,
                current_slot,
                proto_array,
                votes,
                equivocating_indices,
            )?;
        }

        Ok(())
    }

    /// Slot of the most recent per-slot FCR update (`update_fast_confirmation_variables`), used to
    /// sample per-slot metrics exactly once per slot.
    pub fn last_update_slot(&self) -> Option<Slot> {
        self.last_update_slot
    }

    /// True iff `update_fast_confirmation_variables` will rotate the observed-justified
    /// checkpoint pairs when run at `current_slot` (once per slot, at the first slot of an
    /// epoch).
    fn will_rotate<E: EthSpec>(&self, current_slot: Slot) -> bool {
        self.last_update_slot.is_none_or(|s| current_slot > s)
            && is_start_slot_at_epoch::<E>(current_slot)
    }

    /// The checkpoint whose state (spec: `store.checkpoint_states[checkpoint]`) must be
    /// supplied to `on_fast_confirmation` at `current_slot`, or `None` if no state is
    /// required — either no rotation happens this slot, or the rotating checkpoint is
    /// unchanged so its existing balance snapshot is reused.
    pub fn checkpoint_state_needed<E: EthSpec>(&self, current_slot: Slot) -> Option<Checkpoint> {
        (self.will_rotate::<E>(current_slot)
            && self.previous_epoch_greatest_unrealized_checkpoint
                != self.current_epoch_observed_justified.checkpoint())
        .then_some(self.previous_epoch_greatest_unrealized_checkpoint)
    }

    /// Spec: `get_previous_balance_source`.
    fn get_previous_balance_source(&self) -> &BalanceSourceData {
        self.previous_epoch_observed_justified.balances()
    }

    /// Spec: `get_current_balance_source`.
    fn get_current_balance_source(&self) -> &BalanceSourceData {
        self.current_epoch_observed_justified.balances()
    }

    /// Spec: `update_fast_confirmation_variables`.
    fn update_fast_confirmation_variables<E: EthSpec>(
        &mut self,
        head_root: Hash256,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        head_state: &BeaconState<E>,
        checkpoint_state: Option<&BeaconState<E>>,
        spec: &ChainSpec,
    ) -> Result<(), Error> {
        let _span = debug_span!("fcr_update_variables", slot = %current_slot).entered();

        // Rebuild the head-derived caches when the head changes (including within a slot, e.g. a
        // late block or reorg). Each cache is rebuilt from scratch, independently, when its own
        // key is stale.
        let head_current_epoch_shuffling_id =
            attestation_shuffling_id(head_state, WindowEpoch::Current)?;

        if *self.slot_assignments.key() != head_current_epoch_shuffling_id {
            let _span = debug_span!("fcr_rebuild_assignments").entered();
            self.slot_assignments =
                SlotAssignments::new(head_state, spec, Some(&self.slot_assignments))?;
        }

        let head_balance_key = BalanceSourceKey::compute(head_state, head_root)?;
        if self.head_balance_source.key != head_balance_key {
            let _span = debug_span!("fcr_rebuild_head_balance").entered();
            self.head_balance_source = BalanceSourceData::new(head_state, head_root)?;
        }

        // Spec: update_fast_confirmation_variables must be called at most once per slot.
        if self.last_update_slot.is_none_or(|s| current_slot > s) {
            // Rotate the slot heads unconditionally, once per slot (spec).
            self.previous_slot_head = self.current_slot_head;
            self.current_slot_head = head_root;

            // At last slot of epoch: snapshot greatest unrealized justified.
            if is_start_slot_at_epoch::<E>(current_slot.safe_add(1)?) {
                self.previous_epoch_greatest_unrealized_checkpoint =
                    *unrealized_justified_checkpoint;
            }

            // At first slot of epoch: rotate the (checkpoint, balances) pairs. `previous` takes
            // `current`'s snapshot (spec-equal, no O(V) re-derive); `current` is rebuilt in one
            // step so the pair stays coherent, with balances from the new checkpoint's state
            // (spec: `store.checkpoint_states[checkpoint]`) evaluated at the checkpoint's epoch.
            // The first conjunct of `will_rotate` is always true inside the once-per-slot guard.
            if self.will_rotate::<E>(current_slot) {
                let new_current_cp = self.previous_epoch_greatest_unrealized_checkpoint;
                let new_current =
                    if new_current_cp == self.current_epoch_observed_justified.checkpoint() {
                        // Same checkpoint keys the same `checkpoint_states` entry — reuse the snapshot.
                        self.current_epoch_observed_justified.clone()
                    } else {
                        let checkpoint_state = checkpoint_state
                            .ok_or(Error::MissingCheckpointState(new_current_cp))?;
                        // Sanity: the supplied state must be the checkpoint's state, advanced to the
                        // checkpoint's epoch.
                        if checkpoint_state.current_epoch() != new_current_cp.epoch {
                            return Err(Error::MissingCheckpointState(new_current_cp));
                        }
                        CheckpointAndBalance::new(new_current_cp, {
                            let _span = debug_span!("fcr_rebuild_current_balance").entered();
                            BalanceSourceData::new(checkpoint_state, new_current_cp.root)?
                        })
                    };
                self.previous_epoch_observed_justified =
                    std::mem::replace(&mut self.current_epoch_observed_justified, new_current);
            }

            self.last_update_slot = Some(current_slot);
        }

        Ok(())
    }

    /// Spec: get_latest_confirmed
    #[allow(clippy::too_many_arguments)]
    pub fn get_latest_confirmed<E: EthSpec>(
        &self,
        head_root: Hash256,
        finalized_checkpoint: &Checkpoint,
        unrealized_justified_checkpoint: &Checkpoint,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Hash256, Error> {
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let is_epoch_start = is_start_slot_at_epoch::<E>(current_slot);
        let mut confirmed_root = self.confirmed_root;

        // Revert to finalized block if either of the following is true:
        let should_revert_to_finalized_reason =
            if get_block_epoch::<E>(confirmed_root, proto_array)?.safe_add(1)? < current_epoch {
                // 1) the latest confirmed block's epoch is older than the previous epoch,
                Some("epoch_too_old")
            } else if !is_ancestor(head_root, confirmed_root, proto_array)? {
                // 2) the latest confirmed block does not belong to the canonical chain,
                Some("not_ancestor")
            } else if is_epoch_start
                && let Some(chain_unsafe_reason) = self.is_confirmed_chain_safe::<E>(
                    // 3) the confirmed chain starting from the current epoch observed justified
                    //    checkpoint cannot be re-confirmed at the start of the current epoch.
                    confirmed_root,
                    current_slot,
                    proto_array,
                    votes,
                    equivocating_indices,
                )?
            {
                Some(chain_unsafe_reason)
            } else {
                None
            };
        if let Some(reason) = should_revert_to_finalized_reason {
            debug!(
                prev_confirmed = %confirmed_root,
                finalized = %finalized_checkpoint.root,
                slot = %current_slot,
                reason = reason,
                "FCR reverted to finalized"
            );
            confirmed_root = finalized_checkpoint.root;
            metrics::inc_counter_vec(&metrics::FCR_REVERT_TO_FINALIZED, &[reason]);
        }

        // Restart the confirmation chain if each of the following conditions are true:
        // 1) it is the start of the current epoch,
        let observed_justified_block_slot = get_block_slot(
            self.current_epoch_observed_justified.checkpoint().root,
            proto_array,
        )?;
        // 2) epoch of fcr_store.current_epoch_observed_justified_checkpoint.root equals to the previous epoch,
        let is_observed_justified_block_epoch_ok = observed_justified_block_slot
            .epoch(E::slots_per_epoch())
            .safe_add(1)?
            == current_epoch;
        // 3) fcr_store.current_epoch_observed_justified_checkpoint equals to unrealized justification of the head,
        let is_head_unrealized_justified_ok = self.current_epoch_observed_justified.checkpoint()
            == unrealized_justification_of(head_root, proto_array)?;
        // 4) confirmed block is older than the block of fcr_store.current_epoch_observed_justified_checkpoint.
        let is_confirmed_block_stale =
            get_block_slot(confirmed_root, proto_array)? < observed_justified_block_slot;
        if is_epoch_start
            && is_observed_justified_block_epoch_ok
            && is_head_unrealized_justified_ok
            && is_confirmed_block_stale
        {
            debug!(
                prev_confirmed = %confirmed_root,
                justified = %self.current_epoch_observed_justified.checkpoint().root,
                justified_epoch = %self.current_epoch_observed_justified.checkpoint().epoch,
                "FCR restarted from observed justified"
            );
            confirmed_root = self.current_epoch_observed_justified.checkpoint().root;
            metrics::inc_counter(&metrics::FCR_RESTART_FROM_JUSTIFIED);
        }

        // Attempt to further advance the latest confirmed block
        if get_block_epoch::<E>(confirmed_root, proto_array)?.safe_add(1)? >= current_epoch {
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

        Ok(confirmed_root)
    }

    /// Spec: find_latest_confirmed_descendant
    ///
    /// DIVERGENCE: `is_one_confirmed` below is backed by an attestation-score cache instead of
    /// recomputing `get_attestation_score` per block. The control-flow shape follows the spec.
    #[allow(clippy::too_many_arguments)]
    fn find_latest_confirmed_descendant<E: EthSpec>(
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

        // Precompute attestation scores for the whole chain (confirmed → head) in one O(V × depth)
        // pass; both loops below read per-block scores from it instead of recomputing per block.
        let attestation_scores = {
            let _s = debug_span!("fcr_precompute").entered();
            let chain = get_ancestor_roots(head_root, latest_confirmed_root, proto_array)?;
            let terminal_slot = get_block_slot(latest_confirmed_root, proto_array)?;
            AttestationScoreCache::for_chain(
                proto_array,
                &chain,
                terminal_slot,
                self.get_current_balance_source(),
                votes,
                equivocating_indices,
            )?
        };

        // Shared across both FFG predicates so the O(V) honest-support sweep runs at most once.
        let honest_ffg_support = HonestFfgSupportCache::new();

        if get_block_epoch::<E>(confirmed_root, proto_array)?.safe_add(1)? == current_epoch
            && get_voting_source_epoch::<E>(self.previous_slot_head, current_slot, proto_array)?
                .safe_add(2)?
                >= current_epoch
            && (is_start_slot_at_epoch::<E>(current_slot)
                || (self.will_no_conflicting_checkpoint_be_justified::<E>(
                    head_root,
                    unrealized_justified_checkpoint,
                    current_slot,
                    proto_array,
                    votes,
                    equivocating_indices,
                    &honest_ffg_support,
                )? && (unrealized_justification_of(self.previous_slot_head, proto_array)?
                    .epoch
                    .safe_add(1)?
                    >= current_epoch
                    || unrealized_justification_of(head_root, proto_array)?
                        .epoch
                        .safe_add(1)?
                        >= current_epoch)))
        {
            let _s = debug_span!("fcr_loop1").entered();
            let canonical_roots = get_ancestor_roots(head_root, confirmed_root, proto_array)?;

            for block_root in &canonical_roots {
                let block_epoch = get_block_epoch::<E>(*block_root, proto_array)?;

                if block_epoch == current_epoch {
                    break;
                }

                if !is_ancestor(self.previous_slot_head, *block_root, proto_array)? {
                    break;
                }

                if !self
                    .is_one_confirmed::<E>(
                        self.get_current_balance_source(),
                        *block_root,
                        &attestation_scores,
                        current_slot,
                        proto_array,
                        votes,
                        equivocating_indices,
                    )?
                    .is_confirmed()
                {
                    break;
                }
                confirmed_root = *block_root;
            }
        }

        if is_start_slot_at_epoch::<E>(current_slot)
            || unrealized_justification_of(head_root, proto_array)?
                .epoch
                .safe_add(1)?
                >= current_epoch
        {
            let _s = debug_span!("fcr_loop2").entered();
            let canonical_roots = get_ancestor_roots(head_root, confirmed_root, proto_array)?;

            let mut tentative_confirmed_root = confirmed_root;

            for block_root in &canonical_roots {
                let block_epoch = get_block_epoch::<E>(*block_root, proto_array)?;
                let tentative_epoch = get_block_epoch::<E>(tentative_confirmed_root, proto_array)?;

                if block_epoch > tentative_epoch
                    && !self.will_current_target_be_justified::<E>(
                        head_root,
                        current_slot,
                        proto_array,
                        votes,
                        equivocating_indices,
                        &honest_ffg_support,
                    )?
                {
                    break;
                }

                if !self
                    .is_one_confirmed::<E>(
                        self.get_current_balance_source(),
                        *block_root,
                        &attestation_scores,
                        current_slot,
                        proto_array,
                        votes,
                        equivocating_indices,
                    )?
                    .is_confirmed()
                {
                    break;
                }
                tentative_confirmed_root = *block_root;
            }

            if get_block_epoch::<E>(tentative_confirmed_root, proto_array)? == current_epoch
                || (get_voting_source_epoch::<E>(
                    tentative_confirmed_root,
                    current_slot,
                    proto_array,
                )?
                .safe_add(2)?
                    >= current_epoch
                    && (is_start_slot_at_epoch::<E>(current_slot)
                        || self.will_no_conflicting_checkpoint_be_justified::<E>(
                            head_root,
                            unrealized_justified_checkpoint,
                            current_slot,
                            proto_array,
                            votes,
                            equivocating_indices,
                            &honest_ffg_support,
                        )?))
            {
                confirmed_root = tentative_confirmed_root;
            }
        }

        if confirmed_root != latest_confirmed_root {
            debug!(
                confirmed = %confirmed_root,
                prev = %latest_confirmed_root,
                "FCR advanced"
            );
            metrics::inc_counter(&metrics::FCR_ADVANCE);
        }
        Ok(confirmed_root)
    }

    /// Spec: is_confirmed_chain_safe
    ///
    /// DIVERGENCE: Same optimization as find_latest_confirmed_descendant —
    /// precomputes scores once and uses `is_one_confirmed_with_score`.
    ///
    /// `Ok(None)` = the confirmed chain is safe (re-confirmable). `Ok(Some(reason))` = it
    /// isn't, with `reason` naming which check failed (surfaced as the revert metric label).
    fn is_confirmed_chain_safe<E: EthSpec>(
        &self,
        confirmed_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Option<&'static str>, Error> {
        if get_checkpoint_for_block::<E>(
            confirmed_root,
            self.current_epoch_observed_justified.checkpoint().epoch,
            proto_array,
        )
        .is_none_or(|checkpoint| checkpoint != self.current_epoch_observed_justified.checkpoint())
        {
            return Ok(Some("off_justified_chain"));
        }

        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let start_root_exclusive = if self
            .current_epoch_observed_justified
            .checkpoint()
            .epoch
            .safe_add(1)?
            >= current_epoch
        {
            self.current_epoch_observed_justified.checkpoint().root
        } else {
            // Limit reconfirmation to the first block of the previous epoch.
            // If successful, reconfirmation of ancestors is implied.
            let ancestor_at_previous_epoch_start = get_ancestor(
                confirmed_root,
                compute_start_slot_at_epoch::<E>(current_epoch.safe_sub(1)?),
                proto_array,
            )?;
            if get_block_epoch::<E>(ancestor_at_previous_epoch_start, proto_array)?.safe_add(1)?
                == current_epoch
            {
                // The parent of the first block of the previous epoch.
                parent_root(ancestor_at_previous_epoch_start, proto_array)?
            } else {
                // The last block of the epoch before the previous one.
                ancestor_at_previous_epoch_start
            }
        };

        let chain_roots = get_ancestor_roots(confirmed_root, start_root_exclusive, proto_array)?;
        let terminal_slot = get_block_slot(start_root_exclusive, proto_array)?;
        let attestation_scores = AttestationScoreCache::for_chain(
            proto_array,
            &chain_roots,
            terminal_slot,
            self.get_previous_balance_source(),
            votes,
            equivocating_indices,
        )?;

        for root in &chain_roots {
            if let Confirmation::NotConfirmed(unconfirmed) = self.is_one_confirmed::<E>(
                self.get_previous_balance_source(),
                *root,
                &attestation_scores,
                current_slot,
                proto_array,
                votes,
                equivocating_indices,
            )? {
                // `root` is not confirmed; surface why for the revert metric.
                match unconfirmed {
                    Unconfirmed::BelowThreshold {
                        support,
                        safety_threshold,
                    } => {
                        if safety_threshold > 0 {
                            metrics::observe(
                                &metrics::FCR_UNCONFIRMED_SUPPORT_RATIO,
                                support as f64 / safety_threshold as f64,
                            );
                        }
                        return Ok(Some("unconfirmed_optimistic"));
                    }
                    Unconfirmed::Optimistic => {
                        return Ok(Some("unconfirmed_below_threshold"));
                    }
                }
            }
        }
        Ok(None)
    }

    // -----------------------------------------------------------------------
    // LMD-GHOST helpers
    // -----------------------------------------------------------------------

    /// Spec: `get_block_support_between_slots`.
    fn get_block_support_between_slots(
        &self,
        balance_source: &BalanceSourceData,
        block_root: Hash256,
        start_slot: Slot,
        end_slot: Slot,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        // Spec: sum effective balance of validators that:
        // - Are assigned to attest in a committee in the `range(start_slot, end_slot + 1)`
        // - Are active in `balance_source` tracked here as `balance > 0`
        // - Are not slashed in `balance_source` tracked here as `slashed == false`
        // - Do not belong to the `store.equivocating_indices` set
        // - Their vote is for exactly `block_root`
        let mut score = 0u64;
        for (val_idx, balance) in balance_source.unslashed_and_active_indices() {
            let Some(vote) = votes.get(val_idx) else {
                continue;
            };
            if balance > 0
                && self
                    .slot_assignments
                    .is_in_range(val_idx, start_slot, end_slot)?
                && vote.current_root() == block_root
                && !equivocating_indices.contains(&(val_idx as u64))
            {
                score = score.safe_add(balance)?;
            }
        }
        Ok(score)
    }

    /// Spec: `compute_proposer_score(balance_source)`.
    /// Uses `(committee_weight * proposer_score_boost) // 100` (multiply-first) to match
    /// the spec and avoid precision loss from divide-first ordering.
    fn compute_proposer_score<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
    ) -> Result<u64, Error> {
        let committee_weight = balance_source
            .total_active_balance
            .safe_div(E::slots_per_epoch())?;
        Ok(committee_weight
            .safe_mul(self.proposer_score_boost)?
            .safe_div(100)?)
    }

    /// Spec: `compute_empty_slot_support_discount`.
    fn compute_empty_slot_support_discount<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        block_root: Hash256,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        let block = get_block(block_root, proto_array)?;
        let parent_block = parent_node_of(block, proto_array)?;

        if parent_block.slot().safe_add(1)? == block.slot() {
            return Ok(0);
        }

        let parent_support_in_empty_slots = self.get_block_support_between_slots(
            balance_source,
            parent_block.root(),
            parent_block.slot().safe_add(1)?,
            block.slot().safe_sub(1)?,
            votes,
            equivocating_indices,
        )?;

        let adversarial_weight = self.compute_adversarial_weight::<E>(
            balance_source,
            parent_block.slot().safe_add(1)?,
            block.slot().safe_sub(1)?,
            equivocating_indices,
        )?;

        if parent_support_in_empty_slots > adversarial_weight {
            Ok(parent_support_in_empty_slots.safe_sub(adversarial_weight)?)
        } else {
            Ok(0)
        }
    }

    /// Spec: `get_support_discount`.
    fn get_support_discount<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        block_root: Hash256,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        self.compute_empty_slot_support_discount::<E>(
            balance_source,
            block_root,
            proto_array,
            votes,
            equivocating_indices,
        )
    }

    /// Spec: `compute_safety_threshold`.
    fn compute_safety_threshold<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        block_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        let parent_root = parent_root(block_root, proto_array)?;
        let parent_slot = get_block_slot(parent_root, proto_array)?;

        let total_active_balance = balance_source.total_active_balance;
        let proposer_score = self.compute_proposer_score::<E>(balance_source)?;
        let maximum_support = estimate_committee_weight_between_slots::<E>(
            total_active_balance,
            parent_slot.safe_add(1)?,
            current_slot.safe_sub(1)?,
        )?;
        let support_discount = self.get_support_discount::<E>(
            balance_source,
            block_root,
            proto_array,
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

        let threshold_numerator = maximum_support
            .safe_add(proposer_score)?
            .safe_add(adversarial_weight.safe_mul(2)?)?;
        if support_discount < threshold_numerator {
            Ok(threshold_numerator
                .safe_sub(support_discount)?
                .safe_div(2)?)
        } else {
            Ok(0)
        }
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
        let block_slot = get_block_slot(block_root, proto_array)?;
        let parent_root = parent_root(block_root, proto_array)?;
        let block_epoch = get_block_epoch::<E>(block_root, proto_array)?;

        if block_epoch > get_block_epoch::<E>(parent_root, proto_array)? {
            self.compute_adversarial_weight::<E>(
                balance_source,
                compute_start_slot_at_epoch::<E>(block_epoch),
                current_slot.safe_sub(1)?,
                equivocating_indices,
            )
        } else {
            self.compute_adversarial_weight::<E>(
                balance_source,
                block_slot,
                current_slot.safe_sub(1)?,
                equivocating_indices,
            )
        }
    }

    /// Spec: `compute_adversarial_weight`.
    fn compute_adversarial_weight<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        start_slot: Slot,
        end_slot: Slot,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        let total_active_balance = balance_source.total_active_balance;
        let maximum_weight = estimate_committee_weight_between_slots::<E>(
            total_active_balance,
            start_slot,
            end_slot,
        )?;
        let max_adversarial_weight = maximum_weight
            .safe_div(100)?
            .safe_mul(self.byzantine_threshold)?;

        let equivocation_score = self.get_equivocation_score(
            balance_source,
            start_slot,
            end_slot,
            equivocating_indices,
        )?;

        if max_adversarial_weight > equivocation_score {
            Ok(max_adversarial_weight.safe_sub(equivocation_score)?)
        } else {
            Ok(0)
        }
    }

    /// Spec: `get_equivocation_score`.
    /// Equivalent to the spec's `active_equivocating_indices`, but tests committee membership
    /// with precomputed head assignments instead of materializing all committee participants.
    fn get_equivocation_score(
        &self,
        balance_source: &BalanceSourceData,
        start_slot: Slot,
        end_slot: Slot,
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        let mut score = 0u64;
        // Spec: Sum the effective balance of validators that:
        // - Belong to the `store.equivocating_indices` set
        // - Are assigned to attest in a committee in the `range(start_slot, end_slot + 1)`
        // - Are active in `balance_source` tracked here as `balance > 0`
        for &idx in equivocating_indices {
            let idx = idx as usize;
            if self
                .slot_assignments
                .is_in_range(idx, start_slot, end_slot)?
            {
                score = score.safe_add(balance_source.balance(idx))?;
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
        honest_ffg_support: &HonestFfgSupportCache,
    ) -> Result<bool, Error> {
        if get_current_target::<E>(head_root, current_slot, proto_array)?
            == *unrealized_justified_checkpoint
        {
            return Ok(true);
        }

        let total_active_balance = self.head_balance_source.total_active_balance;
        let honest_ffg = honest_ffg_support.get_or_compute(|| {
            self.compute_honest_ffg_support::<E>(
                head_root,
                current_slot,
                proto_array,
                votes,
                equivocating_indices,
            )
        })?;
        Ok(honest_ffg.safe_mul(3)? > total_active_balance)
    }

    /// Spec: `will_current_target_be_justified`.
    fn will_current_target_be_justified<E: EthSpec>(
        &self,
        head_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
        honest_ffg_support: &HonestFfgSupportCache,
    ) -> Result<bool, Error> {
        let total_active_balance = self.head_balance_source.total_active_balance;
        let honest_ffg = honest_ffg_support.get_or_compute(|| {
            self.compute_honest_ffg_support::<E>(
                head_root,
                current_slot,
                proto_array,
                votes,
                equivocating_indices,
            )
        })?;
        Ok(honest_ffg.safe_mul(3)? >= total_active_balance.safe_mul(2)?)
    }

    /// Spec: `get_current_target_score` — estimates FFG support for the current-epoch target.
    ///
    /// Sums the balance of validators whose latest-message checkpoint (resolved from the vote
    /// root at the vote's epoch) matches the current target. Votes are epoch-filtered and
    /// aggregated by `(root, epoch)`, so each checkpoint lookup runs once per distinct vote
    /// rather than once per validator.
    pub fn get_current_target_score<E: EthSpec>(
        &self,
        head_root: Hash256,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<u64, Error> {
        let target = get_current_target::<E>(head_root, current_slot, proto_array)?;

        // Aggregate balances by (vote root, vote epoch): most validators share a small set of
        // latest-message checkpoints, so each O(depth) checkpoint lookup runs once per distinct
        // key rather than once per validator.
        let mut balance_by_vote_checkpoint =
            optimizations::RootBalanceMap::<(Hash256, Epoch)>::new();

        // Spec: sum the effective balance of validators that:
        // - Are active the current epoch
        // - Are not slashed in the current epoch
        // - Don't belong in the equivocating_indices set
        // - Have a vote for the current target
        let mut score = 0u64;

        for (val_idx, balance) in self.head_balance_source.unslashed_and_active_indices() {
            let Some(vote) = votes.get(val_idx) else {
                continue;
            };
            let vote_root = vote.current_root();
            // Spec: get_latest_message_epoch(latest_messages[i]).
            let vote_epoch = vote.current_slot().epoch(E::slots_per_epoch());
            // vote_root.is_zero() == true means no latest message
            if !vote_root.is_zero()
                && vote_epoch == target.epoch
                && !equivocating_indices.contains(&(val_idx as u64))
            {
                balance_by_vote_checkpoint.add((vote_root, vote_epoch), balance)?;
            }
        }

        for ((vote_root, vote_epoch), balance) in balance_by_vote_checkpoint.iter() {
            // Spec: get_checkpoint_for_block(store, latest_messages[i].root,
            //        get_latest_message_epoch(latest_messages[i])).
            if get_checkpoint_for_block::<E>(vote_root, vote_epoch, proto_array) == Some(target) {
                score.safe_add_assign(balance)?;
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
        let _s = debug_span!("fcr_honest_ffg").entered();
        let current_epoch = current_slot.epoch(E::slots_per_epoch());
        let balance_source = &self.head_balance_source;
        let total_active_balance = balance_source.total_active_balance;

        let ffg_support_for_checkpoint = self.get_current_target_score::<E>(
            head_root,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        )?;

        let ffg_weight_till_now = estimate_committee_weight_between_slots::<E>(
            total_active_balance,
            compute_start_slot_at_epoch::<E>(current_epoch),
            current_slot.safe_sub(1)?,
        )?;

        let remaining_ffg_weight = total_active_balance.safe_sub(ffg_weight_till_now)?;
        let remaining_honest_ffg_weight = remaining_ffg_weight
            .safe_div(100)?
            .safe_mul(100u64.safe_sub(self.byzantine_threshold)?)?;

        // Compute potential adversarial weight (accounts for slashed validators).
        let adversarial_weight = self.compute_adversarial_weight::<E>(
            balance_source,
            compute_start_slot_at_epoch::<E>(current_epoch),
            current_slot.safe_sub(1)?,
            equivocating_indices,
        )?;
        let min_honest_ffg_support = ffg_support_for_checkpoint.safe_sub(std::cmp::min(
            adversarial_weight,
            ffg_support_for_checkpoint,
        ))?;

        Ok(min_honest_ffg_support.safe_add(remaining_honest_ffg_weight)?)
    }

    /// Spec: `is_one_confirmed`.
    #[allow(clippy::too_many_arguments)]
    fn is_one_confirmed<E: EthSpec>(
        &self,
        balance_source: &BalanceSourceData,
        block_root: Hash256,
        attestation_scores: &AttestationScoreCache,
        current_slot: Slot,
        proto_array: &ProtoArray,
        votes: &[VoteTracker],
        equivocating_indices: &BTreeSet<u64>,
    ) -> Result<Confirmation, Error> {
        // Spec MUST: not confirmed if the block's execution status is not VALID.
        if is_optimistic_or_invalid(block_root, proto_array)? {
            return Ok(Confirmation::NotConfirmed(Unconfirmed::Optimistic));
        }
        let support = get_attestation_score(block_root, attestation_scores)?;
        let safety_threshold = self.compute_safety_threshold::<E>(
            balance_source,
            block_root,
            current_slot,
            proto_array,
            votes,
            equivocating_indices,
        )?;
        if support > safety_threshold {
            Ok(Confirmation::Confirmed)
        } else {
            Ok(Confirmation::NotConfirmed(Unconfirmed::BelowThreshold {
                support,
                safety_threshold,
            }))
        }
    }
}

// ---------------------------------------------------------------------------
// Free functions: proto-array/store helpers
// ---------------------------------------------------------------------------

fn get_block(root: Hash256, proto_array: &ProtoArray) -> Result<&ProtoNode, Error> {
    proto_array.get_block(root).ok_or(Error::NodeNotFound(root))
}

/// Spec: `get_block_slot`.
fn get_block_slot(root: Hash256, proto_array: &ProtoArray) -> Result<Slot, Error> {
    Ok(get_block(root, proto_array)?.slot())
}

/// Spec: `get_block_epoch`.
fn get_block_epoch<E: EthSpec>(
    root: Hash256,
    proto_array: &ProtoArray,
) -> Result<types::Epoch, Error> {
    Ok(get_block_slot(root, proto_array)?.epoch(E::slots_per_epoch()))
}

fn parent_root(root: Hash256, proto_array: &ProtoArray) -> Result<Hash256, Error> {
    let node = get_block(root, proto_array)?;
    Ok(parent_node_of(node, proto_array)?.root())
}

fn parent_node_of<'a>(
    node: &'a ProtoNode,
    proto_array: &'a ProtoArray,
) -> Result<&'a ProtoNode, Error> {
    proto_array
        .get_parent(node)
        .ok_or(Error::ParentRootNotFound(node.root()))
}

/// Return `true` if the block's execution payload is `Optimistic` or `Invalid`.
/// Pre-bellatrix `Irrelevant` payloads and missing nodes are treated as not
/// optimistic (the spec MUST applies post-merge). A missing node will be
/// rejected later by `get_block_slot`, so this returning `false` here is safe.
fn is_optimistic_or_invalid(root: Hash256, proto_array: &ProtoArray) -> Result<bool, Error> {
    Ok(get_block(root, proto_array)?
        .execution_status()
        .ok()
        .is_some_and(|s| s.is_optimistic_or_invalid()))
}

/// Spec: `is_ancestor`.
fn is_ancestor(
    block_root: Hash256,
    ancestor_root: Hash256,
    proto_array: &ProtoArray,
) -> Result<bool, Error> {
    let ancestor_slot = get_block_slot(ancestor_root, proto_array)?;
    Ok(proto_array
        .iter_block_roots(&block_root)
        .take_while(|(_, slot)| *slot >= ancestor_slot)
        .any(|(root, _)| root == ancestor_root))
}

/// Spec: `get_ancestor`.
fn get_ancestor(
    block_root: Hash256,
    slot: Slot,
    proto_array: &ProtoArray,
) -> Result<Hash256, Error> {
    proto_array
        .iter_block_roots(&block_root)
        .find(|(_, s)| *s <= slot)
        .map(|(r, _)| r)
        .ok_or(Error::AncestorNotFound {
            block: block_root,
            slot,
        })
}

/// Spec: `get_ancestor_roots`.
fn get_ancestor_roots(
    block_root: Hash256,
    terminal_root: Hash256,
    proto_array: &ProtoArray,
) -> Result<Vec<Hash256>, Error> {
    let terminal_slot = get_block_slot(terminal_root, proto_array)?;
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

fn unrealized_justification_of(
    root: Hash256,
    proto_array: &ProtoArray,
) -> Result<Checkpoint, Error> {
    get_block(root, proto_array)?
        .unrealized_justified_checkpoint()
        .ok_or(Error::UnrealizedJustificationNotFound(root))
}

/// Spec: `get_voting_source`.
fn get_voting_source_epoch<E: EthSpec>(
    root: Hash256,
    current_slot: Slot,
    proto_array: &ProtoArray,
) -> Result<types::Epoch, Error> {
    let node = get_block(root, proto_array)?;
    let current_epoch = current_slot.epoch(E::slots_per_epoch());
    let block_epoch = node.slot().epoch(E::slots_per_epoch());
    if current_epoch > block_epoch {
        node.unrealized_justified_checkpoint()
            .map(|cp| cp.epoch)
            .ok_or(Error::UnrealizedJustificationNotFound(root))
    } else {
        Ok(node.justified_checkpoint().epoch)
    }
}

/// Spec: `get_current_target`.
fn get_current_target<E: EthSpec>(
    head_root: Hash256,
    current_slot: Slot,
    proto_array: &ProtoArray,
) -> Result<Checkpoint, Error> {
    let current_epoch = current_slot.epoch(E::slots_per_epoch());
    get_checkpoint_for_block::<E>(head_root, current_epoch, proto_array)
        .ok_or(Error::HeadCheckpointNotFound(head_root))
}

/// Spec: `get_checkpoint_for_block`.
/// Returns None, if `block_root` or its checkpoint block is not known to fork-choice
fn get_checkpoint_for_block<E: EthSpec>(
    block_root: Hash256,
    epoch: types::Epoch,
    proto_array: &ProtoArray,
) -> Option<Checkpoint> {
    Some(Checkpoint {
        epoch,
        root: get_checkpoint_block_root::<E>(block_root, epoch, proto_array)?,
    })
}

/// Spec: `get_checkpoint_block`.
/// Returns None, if `block_root` or its checkpoint block is not known to fork-choice
fn get_checkpoint_block_root<E: EthSpec>(
    block_root: Hash256,
    epoch: types::Epoch,
    proto_array: &ProtoArray,
) -> Option<Hash256> {
    proto_array
        .iter_block_roots(&block_root)
        .find(|(_, slot)| *slot <= compute_start_slot_at_epoch::<E>(epoch))
        .map(|(root, _)| root)
}

/// Spec: `get_attestation_score`.
///
/// Served from a chain score cache to avoid one validator pass per candidate block.
fn get_attestation_score(
    block_root: Hash256,
    attestation_scores: &AttestationScoreCache,
) -> Result<u64, Error> {
    attestation_scores
        .get_attestation_score(block_root)
        .ok_or(Error::MissingPrecomputedScore(block_root))
}

// ---------------------------------------------------------------------------
// Free functions: arithmetic helpers
// ---------------------------------------------------------------------------

/// Spec: `is_start_slot_at_epoch`.
fn is_start_slot_at_epoch<E: EthSpec>(slot: Slot) -> bool {
    slot.as_u64().is_multiple_of(E::slots_per_epoch())
}

/// Spec: `compute_start_slot_at_epoch`.
fn compute_start_slot_at_epoch<E: EthSpec>(epoch: Epoch) -> Slot {
    epoch.start_slot(E::slots_per_epoch())
}

/// Spec: `is_full_validator_set_covered`.
fn is_full_validator_set_covered<E: EthSpec>(
    start_slot: Slot,
    end_slot: Slot,
) -> Result<bool, Error> {
    let spe = E::slots_per_epoch();
    let start_full_epoch = start_slot.safe_add(spe.safe_sub(1)?)?.epoch(spe);
    let end_full_epoch = end_slot.safe_add(1)?.epoch(spe);
    Ok(start_full_epoch < end_full_epoch)
}

/// Spec: `adjust_committee_weight_estimate_to_ensure_safety`.
///
/// Spec uses ceiling division: `(estimate + 999) // 1000`. The function exists to
/// conservatively over-estimate committee weight; flooring would under-estimate and
/// weaken the safety threshold.
fn adjust_committee_weight_estimate_to_ensure_safety(estimate: u64) -> Result<u64, Error> {
    let ceil = estimate.safe_add(999)?.safe_div(1000)?;
    Ok(ceil.safe_mul(1000u64.safe_add(COMMITTEE_WEIGHT_ESTIMATION_ADJUSTMENT_FACTOR)?)?)
}

/// Spec: `estimate_committee_weight_between_slots`.
fn estimate_committee_weight_between_slots<E: EthSpec>(
    total_active_balance: u64,
    start_slot: Slot,
    end_slot: Slot,
) -> Result<u64, Error> {
    let spe = E::slots_per_epoch();

    if start_slot > end_slot {
        return Ok(0);
    }

    if is_full_validator_set_covered::<E>(start_slot, end_slot)? {
        return Ok(total_active_balance);
    }

    let start_epoch = start_slot.as_u64().safe_div(spe)?;
    let end_epoch = end_slot.as_u64().safe_div(spe)?;
    let committee_weight = total_active_balance.safe_div(spe)?;

    if start_epoch == end_epoch {
        let num_slots = end_slot
            .as_u64()
            .safe_sub(start_slot.as_u64())?
            .safe_add(1)?;
        Ok(committee_weight.safe_mul(num_slots)?)
    } else {
        // A range that spans an epoch boundary, but does not span any full epoch
        // needs pro-rata calculation

        // See https://gist.github.com/saltiniroberto/9ee53d29c33878d79417abb2b4468c20
        // for an explanation of the formula used below.

        // First, calculate the number of committees in the end epoch
        let slots_since_end_epoch = end_slot.as_u64().safe_rem(spe)?;
        let num_slots_in_end_epoch = slots_since_end_epoch.safe_add(1)?;
        // Next, calculate the number of slots remaining in the end epoch
        let remaining_slots_in_end_epoch = spe.safe_sub(num_slots_in_end_epoch)?;

        // Then, calculate the number of slots in the start epoch
        let slots_since_start_epoch = start_slot.as_u64().safe_rem(spe)?;
        let num_slots_in_start_epoch = spe.safe_sub(slots_since_start_epoch)?;

        let start_epoch_weight = committee_weight.safe_mul(num_slots_in_start_epoch)?;
        let end_epoch_weight = committee_weight.safe_mul(num_slots_in_end_epoch)?;

        let start_epoch_weight_pro_rated = start_epoch_weight
            .safe_div(spe)?
            .safe_mul(remaining_slots_in_end_epoch)?;

        // Each committee from the end epoch only contributes a pro-rated weight
        adjust_committee_weight_estimate_to_ensure_safety(
            start_epoch_weight_pro_rated.safe_add(end_epoch_weight)?,
        )
    }
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
        assert!(is_full_validator_set_covered::<E>(Slot::new(0), Slot::new(31)).unwrap());
        // 33 slots crossing boundary
        assert!(is_full_validator_set_covered::<E>(Slot::new(0), Slot::new(32)).unwrap());
        // Single slot — not full
        assert!(!is_full_validator_set_covered::<E>(Slot::new(0), Slot::new(0)).unwrap());
        // 31 slots — not full
        assert!(!is_full_validator_set_covered::<E>(Slot::new(1), Slot::new(31)).unwrap());
    }

    #[test]
    fn test_estimate_committee_weight_same_epoch() {
        let total = 32_000_000_000u64; // 32B gwei
        // 1 slot out of 32 => total/32 = 1B
        let w = estimate_committee_weight_between_slots::<E>(total, Slot::new(0), Slot::new(0))
            .unwrap();
        assert_eq!(w, 1_000_000_000);

        // Full epoch => total
        let w = estimate_committee_weight_between_slots::<E>(total, Slot::new(0), Slot::new(31))
            .unwrap();
        assert_eq!(w, total);
    }

    #[test]
    fn test_estimate_committee_weight_empty_range() {
        let w = estimate_committee_weight_between_slots::<E>(
            32_000_000_000,
            Slot::new(10),
            Slot::new(5),
        )
        .unwrap();
        assert_eq!(w, 0);
    }

    #[test]
    fn test_adjustment_factor() {
        // Ceiling division: ceil(1000/1000) * 1005 = 1 * 1005 = 1005
        assert_eq!(
            adjust_committee_weight_estimate_to_ensure_safety(1000).unwrap(),
            1005
        );
        // Ceiling division: ceil(999/1000) * 1005 = 1 * 1005 = 1005 (NOT 0)
        assert_eq!(
            adjust_committee_weight_estimate_to_ensure_safety(999).unwrap(),
            1005
        );
        // Ceiling division: ceil(1500/1000) * 1005 = 2 * 1005 = 2010
        assert_eq!(
            adjust_committee_weight_estimate_to_ensure_safety(1500).unwrap(),
            2010
        );
        // Edge case: 0 -> ceil(0/1000) = 0
        assert_eq!(
            adjust_committee_weight_estimate_to_ensure_safety(0).unwrap(),
            0
        );
    }

    /// Regression test: a slashing processed mid-epoch must rebuild the head balance source
    /// even though the epoch boundary root is unchanged for the rest of the epoch (the FCR analogue
    /// of the unrealized-checkpoints bug fixed in sigp/lighthouse#9471).
    #[test]
    fn head_balance_source_rebuilt_after_intra_epoch_slashing() {
        use state_processing::per_slot_processing;
        use types::MinimalEthSpec;
        type E = MinimalEthSpec;

        let spec = E::default_spec();
        let mut state: BeaconState<E> = BeaconState::new(0, Default::default(), &spec);
        for _ in 0..32 {
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
            .build_all_committee_caches(&spec)
            .expect("committee caches");

        // Advance to a mid-epoch slot: at an epoch start the dependent root changes and would
        // rebuild the source regardless, masking the bug.
        let mid_epoch_slot = Slot::new(E::slots_per_epoch() + 4);
        while state.slot() < mid_epoch_slot {
            per_slot_processing(&mut state, None, &spec).expect("should advance slot");
        }
        state
            .build_all_committee_caches(&spec)
            .expect("committee caches");

        let checkpoint = Checkpoint {
            epoch: state.current_epoch(),
            root: Hash256::repeat_byte(1),
        };
        let head_root_a = Hash256::repeat_byte(2);
        let mut fcr =
            FastConfirmationRule::new::<E>(head_root_a, &state, checkpoint, &state, 25, 40, &spec)
                .expect("fcr initialization");

        assert!(matches!(
            fcr.head_balance_source.key,
            BalanceSourceKey::NoSlashings { .. }
        ));
        assert!(!fcr.head_balance_source.slashed[0]);
        let pre_slashing_key = fcr.head_balance_source.key;

        // Simulate a slashing landing in a new head block within the same epoch (mirroring what
        // `slash_validator` does to the state).
        let effective_balance = spec.max_effective_balance;
        state.get_validator_mut(0).expect("validator 0").slashed = true;
        state
            .set_slashings(state.current_epoch(), effective_balance)
            .expect("set slashings");

        let head_root_b = Hash256::repeat_byte(3);
        fcr.update_fast_confirmation_variables::<E>(
            head_root_b,
            &checkpoint,
            state.slot(),
            &state,
            None,
            &spec,
        )
        .expect("update variables");

        // The regression assertion: the balance source must have been rebuilt.
        assert!(fcr.head_balance_source.slashed[0]);
        assert_eq!(
            fcr.head_balance_source.key,
            BalanceSourceKey::SlashingsPresent {
                head_block_root: head_root_b
            }
        );
        assert_ne!(fcr.head_balance_source.key, pre_slashing_key);

        // While the epoch contains a slashing, every head change rebuilds the source.
        let head_root_c = Hash256::repeat_byte(4);
        fcr.update_fast_confirmation_variables::<E>(
            head_root_c,
            &checkpoint,
            state.slot(),
            &state,
            None,
            &spec,
        )
        .expect("update variables");
        assert_eq!(
            fcr.head_balance_source.key,
            BalanceSourceKey::SlashingsPresent {
                head_block_root: head_root_c
            }
        );
    }
}
