import BuilderPaymentProofs.Generated

/-!
# `Default` never fails

The translated `Default` instances build a value and return `ok`; there is nothing that
can fail in them. Registered as `step` lemmas so the loop proofs can walk over them.
-/


namespace BuilderPaymentProofs

open Aeneas Aeneas.Std Aeneas.Std.WP Result state_processing state_processing.builder_payment_window

/-! ## `Default` never fails -/

@[step]
theorem PendingWithdrawal.default_spec :
    PendingWithdrawal.Insts.CoreDefaultDefault.default ⦃ _ => True ⦄ := by
  unfold PendingWithdrawal.Insts.CoreDefaultDefault.default
  simp [core.default.DefaultArray.default, spec_ok]

@[step]
theorem PendingPayment.default_spec :
    PendingPayment.Insts.CoreDefaultDefault.default ⦃ _ => True ⦄ := by
  unfold PendingPayment.Insts.CoreDefaultDefault.default
  step as ⟨pw⟩

end BuilderPaymentProofs
