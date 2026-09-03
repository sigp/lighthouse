import BuilderPaymentProofs.Generated
import BuilderPaymentProofs.Spec.Default

/-!
# `pay_at_epoch_transition`

One spec per loop, then the function. The headline result here is panic-freedom:
`pay_at_epoch_transition_ok`.
-/


namespace BuilderPaymentProofs

open Aeneas Aeneas.Std Aeneas.Std.WP Result state_processing state_processing.builder_payment_window

/-! ## Panic-freedom of `pay_at_epoch_transition`

    The Rust indexes without bounds checks and adds without overflow checks, behind a single
    up-front check that the window has length `2 * slots_per_epoch`. In the translation those
    operations are `Slice.index_usize`, `Slice.update` and `+`, each of which fails in the
    `Result` monad if the Rust would have panicked. So "returns `ok`" is exactly "does not
    panic". -/

/-- Loop 0 pays out the previous-epoch half. It reads `payments[i]` for `i < spe` and pushes at
    most one withdrawal per iteration. -/
@[step]
theorem pay_at_epoch_transition_loop0_spec
    (payments : Slice PendingPayment) (withdrawals : alloc.vec.Vec PendingWithdrawal)
    (quorum : U64) (spe i : Usize)
    (hspe : spe.val ≤ payments.length) (hi : i.val ≤ spe.val)
    (hw : withdrawals.val.length + (spe.val - i.val) ≤ Usize.max) :
    pay_at_epoch_transition_loop0 payments withdrawals quorum spe i ⦃ _ => True ⦄ := by
  unfold pay_at_epoch_transition_loop0
  apply loop.spec_decr_nat
    (measure := fun (x : alloc.vec.Vec PendingWithdrawal × Usize) => spe.val - x.2.val)
    (inv := fun (x : alloc.vec.Vec PendingWithdrawal × Usize) =>
      x.2.val ≤ spe.val ∧ x.1.val.length + (spe.val - x.2.val) ≤ Usize.max)
  · rintro ⟨w, j⟩ ⟨hj, hwj⟩
    dsimp only at hj hwj
    unfold pay_at_epoch_transition_loop0.body
    dsimp only
    split
    · have hlt : j.val < payments.length := by scalar_tac
      step as ⟨pp, hpp⟩
      split
      · step as ⟨w1, hw1⟩
        step as ⟨j1, hj1⟩
        have hw1l : w1.val.length = w.val.length + 1 := by simp [hw1]
        exact ⟨by scalar_tac, by scalar_tac, by scalar_tac⟩
      · step as ⟨j1, hj1⟩
        exact ⟨by scalar_tac, by scalar_tac, by scalar_tac⟩
    · simp only [spec_ok]
  · exact ⟨hi, hw⟩

/-- Loop 1 shifts the current half down: `payments[i] := payments[i + spe]` for `i < spe`.
    Needs the window to be at least `2 * spe` long; preserves its length. -/
@[step]
theorem pay_at_epoch_transition_loop1_spec
    (payments : Slice PendingPayment) (spe i : Usize)
    (hlen : 2 * spe.val ≤ payments.length) (hi : i.val ≤ spe.val) :
    pay_at_epoch_transition_loop1 payments spe i ⦃ res => res.length = payments.length ⦄ := by
  unfold pay_at_epoch_transition_loop1
  apply loop.spec_decr_nat
    (measure := fun (x : Slice PendingPayment × Usize) => spe.val - x.2.val)
    (inv := fun (x : Slice PendingPayment × Usize) =>
      x.2.val ≤ spe.val ∧ x.1.length = payments.length)
  · rintro ⟨p, j⟩ ⟨hj, hpl⟩
    dsimp only at hj hpl
    unfold pay_at_epoch_transition_loop1.body
    dsimp only
    split
    · have hmax : payments.length ≤ Usize.max := Slice.length_ineq payments
      step as ⟨j1, hj1⟩
      have hlt1 : j1.val < p.length := by scalar_tac
      step as ⟨pp, hpp⟩
      have hlt : j.val < p.length := by scalar_tac
      step as ⟨p1, hp1⟩
      step as ⟨j2, hj2⟩
      exact ⟨by scalar_tac, by simp [hp1, hpl], by scalar_tac⟩
    · simp only [spec_ok]
      exact hpl
  · exact ⟨hi, rfl⟩

/-- Loop 2 clears the current half: `payments[i] := default` for `spe ≤ i < len`. Needs
    `len ≤ payments.length`; preserves the length. -/
@[step]
theorem pay_at_epoch_transition_loop2_spec
    (payments : Slice PendingPayment) (len i : Usize)
    (hlen : len.val ≤ payments.length) (hi : i.val ≤ len.val) :
    pay_at_epoch_transition_loop2 payments len i ⦃ res => res.length = payments.length ⦄ := by
  unfold pay_at_epoch_transition_loop2
  apply loop.spec_decr_nat
    (measure := fun (x : Slice PendingPayment × Usize) => len.val - x.2.val)
    (inv := fun (x : Slice PendingPayment × Usize) =>
      x.2.val ≤ len.val ∧ x.1.length = payments.length)
  · rintro ⟨p, j⟩ ⟨hj, hpl⟩
    dsimp only at hj hpl
    unfold pay_at_epoch_transition_loop2.body
    dsimp only
    split
    · have hmax : payments.length ≤ Usize.max := Slice.length_ineq payments
      step as ⟨pp⟩
      have hlt : j.val < p.length := by scalar_tac
      step as ⟨p1, hp1⟩
      step as ⟨j1, hj1⟩
      exact ⟨by scalar_tac, by simp [hp1, hpl], by scalar_tac⟩
    · simp only [spec_ok]
      exact hpl
  · exact ⟨hi, rfl⟩

/-- **Panic-freedom.** On a window of exactly `2 * slots_per_epoch` entries, with room in the
    withdrawal queue for one withdrawal per previous-epoch slot, `pay_at_epoch_transition`
    returns `Ok` and leaves the window the same length. -/
theorem pay_at_epoch_transition_ok
    (payments : Slice PendingPayment) (withdrawals : alloc.vec.Vec PendingWithdrawal)
    (slots_per_epoch quorum : U64)
    (hlen : payments.length = 2 * slots_per_epoch.val)
    (hw : withdrawals.val.length + slots_per_epoch.val ≤ Usize.max) :
    pay_at_epoch_transition payments withdrawals slots_per_epoch quorum ⦃ res =>
      res.1 = core.result.Result.Ok () ∧ res.2.1.length = payments.length ⦄ := by
  unfold pay_at_epoch_transition
  have hmax : payments.length ≤ Usize.max := Slice.length_ineq payments
  -- `slots_per_epoch as usize`: in bounds because `2 * slots_per_epoch` is a slice length.
  step with UScalar.cast_inBounds_spec as ⟨spe, hspe⟩
  -- `spe.checked_mul(2)`: no overflow for the same reason.
  have hmul := Usize.checked_mul_bv_spec spe 2#usize
  rcases h : spe.checked_mul 2#usize with _ | two_spe <;> simp only [h] at hmul
  · exfalso
    scalar_tac
  obtain ⟨_, htwo, _⟩ := hmul
  simp only [lift, bind_tc_ok, core.option.Option.ok_or_some,
    core.result.Result.Insts.CoreOpsTry.branch]
  split
  · -- The length check cannot fail: the window is `2 * spe` long.
    exfalso
    rename_i hneq
    simp only [bne_iff_ne, ne_eq] at hneq
    apply hneq
    apply UScalar.eq_of_val_eq
    scalar_tac
  · step as ⟨w1⟩
    step as ⟨p1, hp1⟩
    step as ⟨p2, hp2⟩
    all_goals first | rfl | rw [hp2, hp1]

end BuilderPaymentProofs
