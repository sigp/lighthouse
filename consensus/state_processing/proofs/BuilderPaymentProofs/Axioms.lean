import BuilderPaymentProofs.Spec.Transition
import BuilderPaymentProofs.NoDoublePayment
open BuilderPaymentProofs
-- One `#print axioms` per top-level theorem. Each must rest only on `propext`,
-- `Classical.choice` and `Quot.sound`.
#print axioms BuilderPaymentProofs.pay_at_epoch_transition_ok
