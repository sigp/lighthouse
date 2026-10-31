# Slashing protection proofs

A machine-checked proof that `check_attestation` never returns `Verdict::Valid` for an
attestation that is slashable against the validator's stored history.

`SlashingProofs/Generated.lean` is produced mechanically from `../src/attestation_rules.rs`
by [Charon] and [Aeneas].

```
../src/attestation_rules.rs
   --charon--> pure.llbc --aeneas--> SlashingProofs/Generated.lean
                                            |
                                     SlashingProofs/Soundness.lean
```

## The theorem

```lean
theorem check_attestation_sound
    (history : Slice attestation_rules.AttestationRecord)
    (candidate : attestation_rules.AttestationRecord) :
    attestation_rules.check_attestation history candidate ⦃ res =>
      res = attestation_rules.Verdict.Valid → ∀ stored ∈ history.v, ¬ Slashable candidate stored ⦄
```

> For any stored history and any candidate attestation, if `check_attestation` returns
> `Valid`, then no row in the history is slashable against the candidate attestation.

`Slashable` is the pair of consensus slashing conditions: a double vote (same target epoch,
different signing root) or a surround vote in either direction. It is defined in
`SlashingProofs/Spec.lean`, which holds nothing else, so the specification can be reviewed
on its own.

Supporting lemmas characterise each loop the Rust compiles to:

| Lemma | What it says |
|---|---|
| `roots_eq_loop_spec`, `roots_eq_spec` | the signing-root comparison does not fail (see below) |
| `double_vote_scan_spec` | `found` iff some row shares the candidate's target epoch |
| `surround_scan_spec` | the two surround-vote flags |
| `minima_spec` | the minima are lower bounds, and are attained |

## Scope

Soundness only. A checker that rejected everything would satisfy this theorem and stop the
validator attesting. Completeness is false by design. The `MIN` lower bounds deliberately
reject attestations that are provably non-slashable, so liveness is not covered here.

We could eventually follow this up with another proof:

> If the candidate is not slashable against any stored row, and its source is at least the
> minimum stored source, and its target is above the minimum stored target, then the function
> returns `Valid` or `SameData`.

`roots_eq` is proved only not to fail, not to compute the right answer. That is deliberate:
the root comparison only ever separates `SameData` from `DoubleVote`, and neither of those is
`Valid`, so it cannot affect the theorem. Its real behaviour matters, a null signing root
must never compare equal, not even to another null root, or an imported row could be mistaken
for "same data". That behaviour is pinned by `null_root_is_never_same_data` in
`../src/exhaustive_tests.rs` rather than here.

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

## Building

```sh
cd validator_client/slashing_protection/proofs
lake exe cache get      # mathlib oleans
lake build
```

`SlashingProofs/AxiomAudit.lean` walks every theorem in the library and fails the build if one
depends on an axiom outside `propext`, `Classical.choice` and `Quot.sound`. A `sorry` anywhere
under a theorem shows up as `sorryAx`, so it rejects incomplete proofs too. It also rejects
any axiom declared in the library itself. CI runs it again directly, since Lake can replay a
cached log instead of re-elaborating.

## Regenerating after editing `attestation_rules.rs`

`Generated.lean` is checked in so the proof builds without the Rust toolchain. If you change
`attestation_rules.rs` you must regenerate it, and the proof will very likely need updating too.

Build Charon and Aeneas once. Charon is pinned in `.github/workflows/proofs.yml` and Aeneas in
`lakefile.toml`. The build steps are in the workflow's "Build Charon and Aeneas" step and
work unchanged on a Linux machine.

Then run the script. It runs Charon and Aeneas and overwrites `Generated.lean` in place:

```sh
CHARON=path/to/charon/charon/target/release/charon \
AENEAS=path/to/aeneas/src/_build/default/main.exe \
  validator_client/slashing_protection/proofs/regenerate.sh
```

CI runs the same script and fails if the result differs from the checked-in file.

## Why `attestation_rules.rs` is written the way it is

Aeneas only translates a subset of Rust. The constraints:

- **No iterator adapters.** `find`, `any`, `min` translate to opaque `Iter`/`Map`, leaving
  nothing to prove against. Use indexed `while` loops instead.
- **No `return` from inside a loop.** Rejected outright (`Returns inside of nested loops are
  not supported yet`), and the whole function body is dropped. Accumulate into flags and
  decide after the loop.
- **No references taken inside a loop body.** `roots_eq(&history[i].root, &candidate.root)`
  makes Aeneas's loop join fail with `Could not match the contexts`. Pass `[u8; 32]` by value.
- **Plain `u64` epochs, not `Epoch`.** Keeps the `types` dependency graph out of the
  translation.

[Charon]: https://github.com/AeneasVerif/charon
[Aeneas]: https://github.com/AeneasVerif/aeneas
