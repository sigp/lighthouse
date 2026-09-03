# Builder payment window proofs

Machine-checked proofs about `consensus/state_processing/src/builder_payment_window/mod.rs`,
the builder pending-payment window. The headline theorem is **no double payment**: a recorded
bid payment is queued as a withdrawal at most once.

The proofs are **not** about a hand-written model. `BuilderPaymentProofs/Generated.lean` is
produced mechanically from `mod.rs` by [Charon] and [Aeneas], and since the swap in
`adapter.rs` that module *is* the implementation `BeaconState` runs. So the theorems are
statements about the Rust in this repository.

```
../src/builder_payment_window/mod.rs
   --charon--> window.llbc --aeneas--> BuilderPaymentProofs/Generated.lean
                                              |
                                       BuilderPaymentProofs/NoDoublePayment.lean
```

## Properties

Stated over an arbitrary sequence of operations from an empty window. Non-zero withdrawals
only: with `quorum == 0` the spec queues zero-amount withdrawals for empty entries, and those
move no money.

| Theorem | What it says | Status |
|---|---|---|
| `pay_at_epoch_transition_ok` | on a `2 * slots_per_epoch` window the transition returns `ok` (panic-freedom; justifies the lint allows on the Rust) | **proved** |
| no double payment | a recorded payment is queued at most once, never both on reveal and at the transition | not started |
| no invented payments | every non-zero withdrawal queued equals some recorded bid payment's withdrawal | not started |
| withdrawal order | the transition queues withdrawals in slot order | not started |

## Layout

```
BuilderPaymentProofs/
  Generated.lean          Aeneas output. Never edited by hand.
  Spec/                   one file per Rust function: what it does, as a `step` lemma
    Default.lean            the `Default` instances never fail
    Transition.lean         loop specs + `pay_at_epoch_transition_ok`
  NoDoublePayment.lean    top-level theorem, reasons only via `Spec/`
  Axioms.lean             `#print axioms`, one per top-level theorem
```

`Spec/` is the layer that has to change when `mod.rs` changes; the top-level theorems only
change if the behaviour did.

## Building

```sh
cd consensus/state_processing/proofs
lake build
```

`BuilderPaymentProofs/Axioms.lean` prints the axiom dependencies; every theorem must rest only
on `propext`, `Classical.choice` and `Quot.sound`, and there must be no `sorry`.

## Regenerating after editing `mod.rs`

`Generated.lean` is checked in so the proofs build without the Rust toolchain. If you change
`mod.rs` you must regenerate it, and the proofs will very likely need updating too. CI
regenerates and diffs, so a stale file fails the build.

```sh
# Charon, pinned to the commit Aeneas expects
git clone https://github.com/AeneasVerif/charon && cd charon
git checkout fea3fc68d445181cf4ce094855a43a17192a2b12
cd charon && cargo build --release

# Aeneas (OCaml 5.2; needs domainslib, so 4.x will not work)
git clone https://github.com/AeneasVerif/aeneas && cd aeneas
git checkout 453b09f98f2b593c0544a8ad654b77e2a3bc621a
ln -s ../charon charon && cd src && dune build

# Translate. `--lib` matters: without it Charon may pick up non-library targets and emit
# opaque bodies with no error. The four entry points pull in everything they reach
# (`payment_index`, the types, `PaymentEpoch`).
cd consensus/state_processing
charon cargo --preset=aeneas \
  --start-from 'state_processing::builder_payment_window::record_bid_payment' \
  --start-from 'state_processing::builder_payment_window::add_attestation_weight' \
  --start-from 'state_processing::builder_payment_window::pay_on_reveal' \
  --start-from 'state_processing::builder_payment_window::pay_at_epoch_transition' \
  --dest-file "$PWD/window.llbc" -- --lib     # --dest-file resolves against the workspace root
aeneas -backend lean window.llbc -dest proofs/BuilderPaymentProofs
```

The first time, there is no committed `Generated.lean`. CI detects that, runs the translation,
and uploads the result as an artifact to commit.

## Why `mod.rs` is written the way it is

Aeneas only translates a subset of Rust. `mod.rs` is deliberately unidiomatic — indexed `while`
loops, no iterator adapters, no `return` inside a loop, no references taken in a loop body,
plain integers — because that is the subset. The full list of constraints, each found by
hitting it, is in `../../validator_client/slashing_protection/proofs/README.md`.

`pay_at_epoch_transition` indexes without bounds checks and adds without overflow checks,
behind `#[allow(indexing_slicing, arithmetic_side_effects)]`. `.get()?` and `checked_add()?`
are early returns inside a loop, which Aeneas rejects. The one precondition that makes every
access safe — the window is exactly `2 * slots_per_epoch` long — is checked once before the
loops. `pay_at_epoch_transition_ok` is what turns that comment into a proof.

## Trusted base

- **The adapter** (`../src/builder_payment_window/adapter.rs`): type conversions and the
  `Vector` copy-in/out. Not proved; kept branch-free and covered by
  `../src/builder_payment_window/diff_tests.rs` and the spec vectors.
- **The callers**: which attestations add weight, when a reveal counts, and the quorum
  computation, all decided outside the window.
- **Charon and Aeneas** — that the Lean they emit faithfully models the Rust.
- **The Aeneas Lean library** and the Lean kernel.

[Charon]: https://github.com/AeneasVerif/charon
[Aeneas]: https://github.com/AeneasVerif/aeneas
