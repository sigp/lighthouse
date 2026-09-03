# Slashing protection proofs

A machine-checked proof that `check_attestation` never returns `Verdict::Valid` for an
attestation that is slashable against the validator's stored history.

The proof is **not** about a hand-written model. `SlashingProofs/Generated.lean` is produced
mechanically from `../src/attestation_rules.rs` by [Charon] and [Aeneas], so the theorem is a
statement about the Rust in this repository.

```
../src/attestation_rules.rs
   --charon--> pure.llbc --aeneas--> SlashingProofs/Generated.lean
                                            |
                                     SlashingProofs/Soundness.lean
```

## The theorem

```lean
theorem check_attestation_sound
    (history : Slice attestation_rules.AttRow) (candidate : attestation_rules.AttRow) :
    attestation_rules.check_attestation history candidate ⦃ res =>
      res = attestation_rules.Verdict.Valid → ∀ b ∈ history.v, ¬ Slashable candidate b ⦄
```

`Slashable` is the pair of consensus slashing conditions: a double vote (same target epoch,
different signing root) or a surround vote in either direction.

Supporting lemmas characterise each loop the Rust compiles to:

| Lemma | What it says |
|---|---|
| `roots_eq_spec` | the signing-root comparison terminates (see below) |
| `loop0_spec` | `found` iff some row shares the candidate's target epoch |
| `loop1_spec` | the two surround-vote flags |
| `loop2_spec` | the minima are lower bounds, and are attained |

## Building

```sh
cd validator_client/slashing_protection/proofs
lake exe cache get      # mathlib oleans
lake build
```

Roughly five minutes with a warm cache. `SlashingProofs/Axioms.lean` prints the axiom
dependencies: all five theorems rest only on `propext`, `Classical.choice` and `Quot.sound`,
and there are no `sorry`s.

Neither of those holds by construction. `#print axioms` only reports, and Lean reports a
`sorry` as a warning that does not fail the build, so both are asserted in
`.github/workflows/proofs.yml` -- it requires every `#print axioms` line in the audit file
to report, and each to name exactly those three axioms. The axiom check is the load-bearing one: a `sorry` anywhere
beneath these theorems surfaces as `sorryAx` however deep it hides.

## Regenerating after editing `attestation_rules.rs`

`Generated.lean` is checked in so the proof builds without the Rust toolchain. If you change
`attestation_rules.rs` you must regenerate it, and the proof will very likely need updating too.

```sh
# Charon, pinned to the commit Aeneas expects
git clone https://github.com/AeneasVerif/charon && cd charon
git checkout fea3fc68d445181cf4ce094855a43a17192a2b12
cd charon && cargo build --release

# Aeneas (OCaml 5.2; needs domainslib, so 4.x will not work).
# Use the `rev` pinned in lakefile.toml -- that file is the source of truth, and CI reads it.
git clone https://github.com/AeneasVerif/aeneas && cd aeneas
git checkout 453b09f98f2b593c0544a8ad654b77e2a3bc621a
ln -s ../charon charon && cd src && dune build

# Translate. `--lib` matters: without it Charon picks up src/bin/test_generator.rs
# and emits a file with opaque bodies and no error.
cd validator_client/slashing_protection
charon cargo --preset=aeneas \
  --start-from 'slashing_protection::attestation_rules::check_attestation' \
  --dest-file pure.llbc -- --lib
aeneas -backend lean pure.llbc -dest proofs/SlashingProofs
```

## Why `attestation_rules.rs` is written the way it is

Aeneas only translates a subset of Rust. The constraints that shaped that file, each found by
hitting it:

- **No iterator adapters.** `find`, `any`, `min` translate to opaque `Iter`/`Map`, leaving
  nothing to prove against. Use indexed `while` loops.
- **No `return` from inside a loop.** Rejected outright (`Returns inside of nested loops are
  not supported yet`), and the whole function body is dropped. Accumulate into flags and
  decide after the loop.
- **No references taken inside a loop body.** `roots_eq(&history[i].root, &candidate.root)`
  makes Aeneas's loop join fail with `Could not match the contexts`. Pass `[u8; 32]` by value.
- **Plain `u64` epochs, not `Epoch`.** Keeps the `types` dependency graph out of the
  translation.

## Trusted base

The proof does not stand alone. It also trusts:

- **Charon and Aeneas** — that the Lean they emit faithfully models the Rust.
- **The Aeneas Lean library**. Building this project emits four ``declaration uses `sorry` ``
  warnings from it, two in `Aeneas/Std/Slice.lean` and two in `Aeneas/Std/StringIter.lean`.
  (Aeneas contains other textual `sorry`s, but those sit in tactic implementations and in its
  own tutorial exercises, not in admitted theorems.) None of the four is reachable from the
  theorems here -- that is exactly what the axiom check enforces, since depending on one
  would show up as `sorryAx`.
- **mathlib** and the Lean kernel.

And it says nothing about the SQL in `slashing_database.rs`, which is covered instead by the
bounded exhaustive equivalence test in `../src/exhaustive_tests.rs`.

## What the proof does *not* cover

`roots_eq` is proved only to terminate, not to compute the right answer. That is deliberate:
the root comparison only ever separates `SameData` from `DoubleVote`, and neither of those is
`Valid`, so it cannot affect the theorem. Its real behaviour matters — a null signing root
must never compare equal, not even to another null root, or an imported row could be mistaken
for "same data" — and that is pinned by `null_root_is_never_same_data` in
`../src/exhaustive_tests.rs` rather than here.

## Scope

Soundness only. A checker that rejected everything would satisfy this theorem and stop the
validator attesting. Completeness is false by design — the `MIN` lower bounds deliberately
reject attestations that are provably non-slashable — so liveness is not covered here.

[Charon]: https://github.com/AeneasVerif/charon
[Aeneas]: https://github.com/AeneasVerif/aeneas
