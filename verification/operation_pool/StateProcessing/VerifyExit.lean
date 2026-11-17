import StateProcessing.Funs

/-!
# The `verify_exit` cores

`verify_exit` in `consensus/state_processing/src/per_block_processing/verify_exit.rs` delegates
its checks to two functions that are free of `EthSpec`. This file states what each one computes.

* `verify_exit_validator_checks` returns `Ok` exactly when the validator exists and its record
  passes `ExitChecks`.
* `verify_exit_pending_balance` returns `Ok` exactly when the pending balance, if one was
  computed, is zero.

Neither function can panic: both theorems give the returned value.
-/

open Aeneas Aeneas.Std Result

namespace state_processing

open types.core.slot_epoch (Epoch)
open types.validator.validator (Validator)
open types.exit.voluntary_exit (VoluntaryExit)
open per_block_processing.verify_exit
open per_block_processing.errors

/-! ## Comparisons and checked addition on `Epoch`

`Epoch` is a `u64`. Its derived comparisons and its `safe_add` are extracted from Rust; these
lemmas read them as statements about natural numbers. -/

theorem epoch_partial_cmp (a b : Epoch) :
    types.core.slot_epoch.Epoch.Insts.CoreCmpPartialOrdEpoch.partial_cmp a b =
      ok (some (compare a.val b.val)) := by
  simp [types.core.slot_epoch.Epoch.Insts.CoreCmpPartialOrdEpoch.partial_cmp,
    types.core.slot_epoch.Epoch.Insts.CoreCmpOrd.cmp]

/-- `a <= b` on epochs. -/
theorem epoch_le (a b : Epoch) :
    core.cmp.PartialOrd.le.trait_default
      types.core.slot_epoch.Epoch.Insts.CoreCmpPartialOrdEpoch a b = ok (decide (a.val ≤ b.val)) := by
  simp only [core.cmp.PartialOrd.le.trait_default, core.cmp.PartialOrd.le.default,
    core.cmp.PartialOrd.le_body, epoch_partial_cmp, bind_tc_ok, ok.injEq]
  rw [Bool.eq_iff_iff]
  simp [Nat.compare_eq_lt]
  omega

/-- `a < b` on epochs. -/
theorem epoch_lt (a b : Epoch) :
    core.cmp.PartialOrd.lt.trait_default
      types.core.slot_epoch.Epoch.Insts.CoreCmpPartialOrdEpoch a b = ok (decide (a.val < b.val)) := by
  simp only [core.cmp.PartialOrd.lt.trait_default, core.cmp.PartialOrd.lt.default,
    core.cmp.PartialOrd.lt_body, epoch_partial_cmp, bind_tc_ok, ok.injEq]
  rw [Bool.eq_iff_iff]
  simp [Nat.compare_eq_lt]

/-- `a >= b` on epochs. -/
theorem epoch_ge (a b : Epoch) :
    core.cmp.PartialOrd.ge.trait_default
      types.core.slot_epoch.Epoch.Insts.CoreCmpPartialOrdEpoch a b = ok (decide (b.val ≤ a.val)) := by
  simp only [core.cmp.PartialOrd.ge.trait_default, core.cmp.PartialOrd.ge.default,
    core.cmp.PartialOrd.ge_body, epoch_partial_cmp, bind_tc_ok, ok.injEq]
  rw [Bool.eq_iff_iff]
  simp [Nat.compare_eq_gt]
  omega

/-- `a == b` on epochs. -/
theorem epoch_eq (a b : Epoch) :
    types.core.slot_epoch.Epoch.Insts.CoreCmpPartialEqEpoch.eq a b = ok (decide (a = b)) := by
  simp [types.core.slot_epoch.Epoch.Insts.CoreCmpPartialEqEpoch.eq]

/-- `Validator::is_active_at`: `activation_epoch <= epoch < exit_epoch`. -/
theorem is_active_at_eq (v : Validator) (epoch : Epoch) :
    types.validator.validator.Validator.is_active_at v epoch =
      ok (decide (v.activation_epoch.val ≤ epoch.val ∧ epoch.val < v.exit_epoch.val)) := by
  simp only [types.validator.validator.Validator.is_active_at, epoch_le, epoch_lt]
  by_cases h : v.activation_epoch.val ≤ epoch.val <;> simp [h]

/-- `Epoch::safe_add` returns the sum when it fits in a `u64`, and `ArithError::Overflow`
otherwise. -/
theorem safe_add_eq (a : Epoch) (b : U64) :
    (a.val + b.val ≤ U64.max →
      ∃ s : Epoch, types.core.slot_epoch.Epoch.Insts.Safe_arithSafeArithU64.safe_add a b =
        ok (core.result.Result.Ok s) ∧ s.val = a.val + b.val) ∧
    (U64.max < a.val + b.val →
      types.core.slot_epoch.Epoch.Insts.Safe_arithSafeArithU64.safe_add a b =
        ok (core.result.Result.Err safe_arith.ArithError.Overflow)) := by
  have hspec := U64.checked_add_bv_spec a b
  constructor
  · intro hfit
    cases hadd : U64.checked_add a b with
    | none => rw [hadd] at hspec; simp at hspec; omega
    | some s =>
      rw [hadd] at hspec
      refine ⟨s, ?_, hspec.2.1⟩
      simp [types.core.slot_epoch.Epoch.Insts.Safe_arithSafeArithU64.safe_add, lift, hadd,
        P.Insts.CoreOpsFunctionFnOnceTupleU64Epoch.call_once, types.core.slot_epoch.Epoch.new]
  · intro hover
    cases hadd : U64.checked_add a b with
    | some s => rw [hadd] at hspec; simp at hspec; omega
    | none =>
      simp [types.core.slot_epoch.Epoch.Insts.Safe_arithSafeArithU64.safe_add, lift, hadd]

/-! ## The validator-record checks -/

/-- The conditions on the exiting validator's record under which `verify_exit` accepts an exit.
All comparisons are on natural numbers: the sum in `old_enough` does not wrap. -/
structure ExitChecks (v : Validator) (exit : VoluntaryExit) (currentEpoch farFutureEpoch : Epoch)
    (shardCommitteePeriod : U64) : Prop where
  /-- The validator has been activated. -/
  active_from : v.activation_epoch.val ≤ currentEpoch.val
  /-- The validator's exit epoch has not been reached. -/
  active_until : currentEpoch.val < v.exit_epoch.val
  /-- The validator has not initiated an exit. -/
  not_exited : v.exit_epoch = farFutureEpoch
  /-- The exit's own epoch has been reached. -/
  not_future : exit.epoch.val ≤ currentEpoch.val
  /-- The validator has been active for the shard committee period. -/
  old_enough : v.activation_epoch.val + shardCommitteePeriod.val ≤ currentEpoch.val

/-- `verify_exit_validator_checks` never panics, and returns `Ok` exactly when the validator
exists and its record passes `ExitChecks`. -/
theorem verify_exit_validator_checks_ok_iff (validator : Option Validator) (exit : VoluntaryExit)
    (currentEpoch farFutureEpoch : Epoch) (shardCommitteePeriod : U64) :
    ∃ r, verify_exit_validator_checks validator exit currentEpoch farFutureEpoch
        shardCommitteePeriod = ok r ∧
      (r = core.result.Result.Ok () ↔
        ∃ v, validator = some v ∧
          ExitChecks v exit currentEpoch farFutureEpoch shardCommitteePeriod) := by
  cases validator with
  | none =>
    refine ⟨.Err (.Invalid (.ValidatorUnknown exit.validator_index)), ?_, by simp⟩
    simp [verify_exit_validator_checks, error, BlockOperationError.invalid]
  | some v =>
    simp only [verify_exit_validator_checks, is_active_at_eq, epoch_eq, epoch_ge,
      Option.some.injEq, exists_eq_left']
    by_cases hact : v.activation_epoch.val ≤ currentEpoch.val ∧ currentEpoch.val < v.exit_epoch.val
    swap
    · refine ⟨.Err (.Invalid (.NotActive exit.validator_index)), ?_, ?_⟩
      · simp [hact, BlockOperationError.invalid]
      · simp only [reduceCtorEq, false_iff]
        exact fun h => hact ⟨h.active_from, h.active_until⟩
    by_cases hfar : v.exit_epoch = farFutureEpoch
    swap
    · refine ⟨.Err (.Invalid (.AlreadyExited exit.validator_index)), ?_, ?_⟩
      · simp [hact, hfar, BlockOperationError.invalid]
      · simp only [reduceCtorEq, false_iff]
        exact fun h => hfar h.not_exited
    -- `simp` rewrites the exit epoch to the far-future epoch, so restate activity in that form.
    have hlt : currentEpoch.val < farFutureEpoch.val := hfar ▸ hact.2
    by_cases hfut : exit.epoch.val ≤ currentEpoch.val
    swap
    · refine ⟨.Err (.Invalid (.FutureEpoch currentEpoch exit.epoch)), ?_, ?_⟩
      · simp [hact, hlt, hfar, hfut, BlockOperationError.invalid]
      · simp only [reduceCtorEq, false_iff]
        exact fun h => hfut h.not_future
    rcases Nat.lt_or_ge U64.max (v.activation_epoch.val + shardCommitteePeriod.val) with hover | hfit
    · -- The sum overflows: `safe_add` fails, and `?` turns that into an `ArithError`.
      have hadd := (safe_add_eq v.activation_epoch shardCommitteePeriod).2 hover
      refine ⟨.Err (.ArithError .Overflow), ?_, ?_⟩
      · simp [hact, hlt, hfar, hfut, hadd, core.result.Result.Insts.CoreOpsTry.branch,
          core.result.Result.Insts.CoreOpsTry_traitFromResidualResult.from_residual,
          BlockOperationError.Insts.CoreConvertFromArithError.from]
      · simp only [reduceCtorEq, false_iff]
        intro h
        have := h.old_enough
        scalar_tac
    · obtain ⟨s, hadd, hs⟩ := (safe_add_eq v.activation_epoch shardCommitteePeriod).1 hfit
      by_cases hold : s.val ≤ currentEpoch.val
      · refine ⟨.Ok (), ?_, ?_⟩
        · simp [hact, hlt, hfar, hfut, hadd, hold, core.result.Result.Insts.CoreOpsTry.branch]
        · simp only [true_iff]
          exact ⟨hact.1, hact.2, hfar, hfut, by omega⟩
      · refine ⟨.Err (.Invalid (.TooYoungToExit currentEpoch s)), ?_, ?_⟩
        · simp [hact, hlt, hfar, hfut, hadd, hold, core.result.Result.Insts.CoreOpsTry.branch,
            BlockOperationError.invalid]
        · simp only [reduceCtorEq, false_iff]
          intro h
          have := h.old_enough
          omega

/-! ## The pending-balance check -/

/-- `verify_exit_pending_balance` never panics, and returns `Ok` exactly when the pending
balance, if there is one, is zero. -/
theorem verify_exit_pending_balance_ok_iff (validatorIndex : U64) (pending : Option U64) :
    ∃ r, verify_exit_pending_balance validatorIndex pending = ok r ∧
      (r = core.result.Result.Ok () ↔ ∀ p, pending = some p → p.val = 0) := by
  cases pending with
  | none => exact ⟨.Ok (), by simp [verify_exit_pending_balance], by simp⟩
  | some p =>
    by_cases hp : p = 0#u64
    · exact ⟨.Ok (), by simp [verify_exit_pending_balance, hp], by simp [hp]⟩
    · refine ⟨.Err (.Invalid (.PendingWithdrawalInQueue validatorIndex)), ?_, ?_⟩
      · simp [verify_exit_pending_balance, hp, BlockOperationError.invalid]
      · simp only [reduceCtorEq, Option.some.injEq, forall_eq', false_iff]
        intro h
        exact hp (by scalar_tac)

end state_processing
