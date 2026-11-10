import SlashingProofs.Generated

/-!
# The slashing conditions

The two consensus slashing conditions, stated over the `AttestationRecord` type that Aeneas
generated from `attestation_rules.rs`. Nothing in `Generated.lean` mentions slashing. This file
is the specification the soundness theorem is checked against, so it is kept on its own and
short.
-/

namespace SlashingProofs

open slashing_protection

/-- `outer` surrounds `inner`: `outer` has an earlier source and a later target. -/
def Surrounds (outer inner : attestation_rules.AttestationRecord) : Prop :=
  outer.source_epoch < inner.source_epoch ∧ inner.target_epoch < outer.target_epoch

/-- A double vote: same target epoch, different signing root. -/
def DoubleVote (candidate stored : attestation_rules.AttestationRecord) : Prop :=
  candidate.target_epoch = stored.target_epoch
  ∧ candidate.signing_root.val ≠ stored.signing_root.val

/-- Slashable in either direction. -/
def Slashable (candidate stored : attestation_rules.AttestationRecord) : Prop :=
  DoubleVote candidate stored ∨ Surrounds candidate stored ∨ Surrounds stored candidate

end SlashingProofs
