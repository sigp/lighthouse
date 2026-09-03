import BuilderPaymentProofs.Spec.Transition

/-!
# No double payment

A recorded bid payment is queued as a withdrawal at most once: never both on reveal and at the
epoch transition.

Stated over an arbitrary sequence of operations from an empty window, by induction on the
sequence, using the per-function specs in `Spec/`. Non-zero withdrawals only: with
`quorum == 0` the spec queues zero-amount withdrawals for empty entries, and those move no
money.

Not yet proved. Needs `Spec/Record.lean`, `Spec/Reveal.lean`, `Spec/Weight.lean` (what each
operation does to the window, not just that it succeeds) and an abstract model of "recorded"
and "queued" over lists.
-/

namespace BuilderPaymentProofs

end BuilderPaymentProofs
