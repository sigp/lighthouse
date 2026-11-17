import StateProcessing.VerifyExit
import OperationPool.Bridge.Scalars
import EthCLSpecs.Proofs.Fulu.VoluntaryExits

/-!
# From Lighthouse's exit checks to the spec's exit gates

Lighthouse's `verify_exit` reads four things from its `BeaconState`: the exiting validator's
record, the current epoch, the validator's pending balance to withdraw, and two constants of the
chain spec. `StateView` names those reads. `StateCorr view s` says that they agree with the spec
state `s`. That agreement is TRUSTED: `BeaconState<E>` and its accessors are not extracted.

`exitGates_of_coresOk` is the bridge. When both extracted cores of `verify_exit` accept an exit
on a view that corresponds to `s`, the spec's `ExitGates` hold for that exit on `s`.

Names: this file opens the spec's namespace. Extracted Rust items are written with their full
names, because both sides define `Validator`, `Epoch` and `VoluntaryExit`.
-/

namespace OperationPool.Bridge

open EthCLLib.Spec (HasherTag)
open EthCLSpecs.Fulu
open EthCLSpecs.Proofs.Fulu

/-- The Rust `Validator`. -/
abbrev RValidator : Type := state_processing.types.validator.validator.Validator

/-- The Rust `VoluntaryExit`. -/
abbrev RVoluntaryExit : Type := state_processing.types.exit.voluntary_exit.VoluntaryExit

/-- What `verify_exit` reads from Lighthouse's `BeaconState` and `ChainSpec`. -/
structure StateView where
  /-- `state.validators().get(index as usize)`. -/
  validatorAt : Aeneas.Std.U64 → Option RValidator
  /-- `state.current_epoch()`. -/
  currentEpoch : Aeneas.Std.U64
  /-- `state.get_pending_balance_to_withdraw(index as usize).ok()`. -/
  pendingAt : Aeneas.Std.U64 → Option Aeneas.Std.U64
  /-- `spec.far_future_epoch`. -/
  farFutureEpoch : Aeneas.Std.U64
  /-- `spec.shard_committee_period`. -/
  shardCommitteePeriod : Aeneas.Std.U64

/-- Both cores of `verify_exit` accept the exit on the view. -/
def CoresOk (view : StateView) (exit : RVoluntaryExit) : Prop :=
  state_processing.per_block_processing.verify_exit.verify_exit_validator_checks
      (view.validatorAt exit.validator_index) exit view.currentEpoch view.farFutureEpoch
      view.shardCommitteePeriod =
    Aeneas.Std.Result.ok (Aeneas.Std.core.result.Result.Ok ()) ∧
  state_processing.per_block_processing.verify_exit.verify_exit_pending_balance
      exit.validator_index (view.pendingAt exit.validator_index) =
    Aeneas.Std.Result.ok (Aeneas.Std.core.result.Result.Ok ())

section

variable [Preset] [Config]

/-- The reads of `view` agree with the spec state `s`. -/
structure StateCorr (view : StateView) (s : BeaconState) : Prop where
  /-- The current epoch is the epoch of the state's slot. -/
  epoch : u64ToSpec view.currentEpoch = computeEpochAtSlot s.slot
  /-- `far_future_epoch` is the spec's `FAR_FUTURE_EPOCH`. -/
  farFuture : u64ToSpec view.farFutureEpoch = Const.farFutureEpoch
  /-- `shard_committee_period` is the spec's `SHARD_COMMITTEE_PERIOD`. -/
  period : u64ToSpec view.shardCommitteePeriod = Const.shardCommitteePeriod
  /-- A validator the view returns is in the registry, with the same two epochs. -/
  validator : ∀ (i : Aeneas.Std.U64) (v : RValidator), view.validatorAt i = some v →
    i.val < s.validators.val.size ∧
    (s.validators[i.val]!).activationEpoch = u64ToSpec v.activation_epoch ∧
    (s.validators[i.val]!).exitEpoch = u64ToSpec v.exit_epoch
  /-- The pending balance was computed: the state has a pending partial withdrawals queue, and
  the sum over it did not overflow. -/
  pendingSome : ∀ i : Aeneas.Std.U64, ∃ p, view.pendingAt i = some p
  /-- The pending balance is at least each pending amount of the validator, as a sum that did
  not overflow is. -/
  pendingBound : ∀ (i p : Aeneas.Std.U64), view.pendingAt i = some p →
    ∀ q ∈ s.pendingPartialWithdrawals.val, q.validatorIndex = u64ToSpec i →
      q.amount.toNat ≤ p.val

/-- An exit that both cores of `verify_exit` accept passes the spec's gates on the corresponding
state. `sve` is the spec's form of the exit: same validator index and same epoch. -/
theorem exitGates_of_coresOk {view : StateView} {s : BeaconState} (hcorr : StateCorr view s)
    {exit : RVoluntaryExit} {sve : SignedVoluntaryExit}
    (hidx : sve.message.validatorIndex = u64ToSpec exit.validator_index)
    (hepoch : sve.message.epoch = u64ToSpec exit.epoch)
    (hok : CoresOk view exit) : ExitGates s sve := by
  obtain ⟨hchecks, hpending⟩ := hok
  -- The record checks give a validator that passes `ExitChecks`.
  obtain ⟨r, hr, hiff⟩ := state_processing.verify_exit_validator_checks_ok_iff
    (view.validatorAt exit.validator_index) exit view.currentEpoch view.farFutureEpoch
    view.shardCommitteePeriod
  have hrOk : r = Aeneas.Std.core.result.Result.Ok () := by
    have := hchecks.symm.trans hr
    simpa using this.symm
  obtain ⟨v, hv, hc⟩ := hiff.mp hrOk
  obtain ⟨hlt, hact, hexit⟩ := hcorr.validator _ v hv
  -- The pending-balance check gives a zero pending balance.
  obtain ⟨r', hr', hiff'⟩ := state_processing.verify_exit_pending_balance_ok_iff
    exit.validator_index (view.pendingAt exit.validator_index)
  have hr'Ok : r' = Aeneas.Std.core.result.Result.Ok () := by
    have := hpending.symm.trans hr'
    simpa using this.symm
  have hidxNat : sve.message.validatorIndex.toNat = exit.validator_index.val := by
    rw [hidx]
    rfl
  have hvEq : exitValidator s sve = s.validators[exit.validator_index.val]! := by
    show s.validators[sve.message.validatorIndex.toNat]! = _
    rw [hidxNat]
  refine ⟨by rw [hidxNat]; exact hlt, ?_, ?_, ?_, ?_, ?_⟩
  · rw [hvEq]
    unfold isActiveValidator
    rw [hact, hexit, ← hcorr.epoch]
    simp only [Bool.and_eq_true, decide_eq_true_eq, UInt64.le_iff_toNat_le,
      UInt64.lt_iff_toNat_lt, u64ToSpec_toNat]
    exact ⟨hc.active_from, hc.active_until⟩
  · rw [hvEq, hexit, hc.not_exited]
    exact hcorr.farFuture
  · rw [hepoch, ← hcorr.epoch, UInt64.le_iff_toNat_le, u64ToSpec_toNat, u64ToSpec_toNat]
    exact hc.not_future
  · rw [hvEq, hact, ← hcorr.epoch, ← hcorr.period, u64ToSpec_toNat, u64ToSpec_toNat,
      u64ToSpec_toNat]
    exact hc.old_enough
  · intro q hq hqidx
    obtain ⟨p, hp⟩ := hcorr.pendingSome exit.validator_index
    have hp0 : p.val = 0 := hiff'.mp hr'Ok p hp
    have hle := hcorr.pendingBound _ p hp q hq (hqidx.trans hidx)
    apply UInt64.toNat_inj.mp
    simp only [UInt64.toNat_zero]
    omega

end

end OperationPool.Bridge
