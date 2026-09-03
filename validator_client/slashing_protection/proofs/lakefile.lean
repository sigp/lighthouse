import Lake
open Lake DSL

/-- Aeneas provides the Lean semantics for the translated Rust (`Result`, `Slice`,
    `Array`, the `loop` combinator and the `step` tactic). Pinned: the generated
    file in `SlashingProofs/Generated.lean` must be produced by the matching
    Aeneas/Charon versions. See README.md. -/
require aeneas from git
  "https://github.com/AeneasVerif/aeneas" @ "453b09f98f2b593c0544a8ad654b77e2a3bc621a"
  / "backends" / "lean"

package «slashing_proofs» where
  -- The loop proofs need more than the default budget.
  leanOptions := #[⟨`maxHeartbeats, (1000000 : Nat)⟩]

@[default_target] lean_lib «SlashingProofs» {}
