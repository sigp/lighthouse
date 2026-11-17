# Voluntary-exit packing: proved valid against the consensus spec

Machine-checked proofs, in Lean 4, that the voluntary exits packed by
`OperationPool::get_slashings_and_exits` are valid for inclusion in the block: the consensus spec
processes them, in order, without an error, after the block's packed proposer and attester
slashings.

The Rust is translated to Lean by [Charon](https://github.com/AeneasVerif/charon) and
[Aeneas](https://github.com/AeneasVerif/aeneas). The spec is the Fulu fork of
[Etheorem](https://github.com/etheorem/etheorem), an executable Lean model of the consensus
specification. One Lean project depends on both.

## What is proved

The main theorem is `packed_exits_valid_after_slashings_uniform`
(`OperationPool/PackedExitsValid.lean`). Informally:

> Let `s` be the spec state that corresponds to the Lighthouse state the op pool packs on. Let
> the spec process the packed proposer slashings and then the packed attester slashings from
> `s`, reaching `s₂`. If the exit queue of `s₂` has room for `MAX_VOLUNTARY_EXITS` exits, then
> `filter_limit_operations` does not panic, it returns at most `MAX_VOLUNTARY_EXITS` exits, and
> the spec's `process_voluntary_exit` succeeds on each of them in order, starting from `s₂`.

The room hypothesis is `exitStart s₂ + limit * exitStep (2^64 - 1) +
MIN_VALIDATOR_WITHDRAWABILITY_DELAY < 2^64`. On mainnet it holds when the earliest exit epoch is
at least about `2.3e9` epochs below `2^64`.

| Theorem | File | Statement |
|---|---|---|
| `filter_limit_operations_eq` | `OperationPool/FilterLimit.lean` | The packed list is `((pool.filter keep).take limit).map exitOf`; no panic |
| `verify_exit_validator_checks_ok_iff` | `StateProcessing/VerifyExit.lean` | Returns `Ok` exactly when the validator exists and its record passes `ExitChecks`; no panic |
| `verify_exit_pending_balance_ok_iff` | `StateProcessing/VerifyExit.lean` | Returns `Ok` exactly when the pending balance, if computed, is zero; no panic |
| `exclusionSet_covers` | `OperationPool/ExclusionSet.lean` | The exclusion set holds each packed proposer slashing's proposer and each index common to the two attestations of a packed attester slashing |
| `exitGates_of_coresOk` | `OperationPool/Bridge/StateCorr.lean` | An exit both `verify_exit` cores accept passes the spec's `ExitGates` |
| `mem_qsort` | `OperationPool/Bridge/QSort.lean` | `Array.qsort` returns a permutation of its input |
| `packed_exits_valid` | `OperationPool/PackedExitsValid.lean` | The packed exits succeed from any state with the exit view of the packing state |
| `packed_exits_valid_after_slashings` | `OperationPool/PackedExitsValid.lean` | The packed exits succeed after the packed slashings |

The spec-side theorems live in Etheorem, on branch `voluntary-exit-proofs`
(`packages/EthCLSpecs/EthCLSpecs/Proofs/Fulu/VoluntaryExits.lean` and
`VoluntaryExits/Slashings.lean`):

| Theorem | Statement |
|---|---|
| `processVoluntaryExit_succeeds` | An exit that passes `ExitGates` and `ExitSigned` cannot fail when the exit queue has room |
| `voluntaryExits_succeed_of_exitView` | Exits that name pairwise distinct validators and pass the gates succeed in order, from any state with the same `ExitView` |
| `exitView_of_slashings` | The proposer and attester slashings of a block keep the exit view for the validators they cannot slash |

No proof uses `sorry`. `./lake.sh build Audit` prints the axioms of each theorem: Lean's
`propext`, `Classical.choice` and `Quot.sound`, plus the opaque external declarations listed
under "What is trusted". The Etheorem theorems use the three standard axioms only.

## Why the property holds

Packing checks each exit with `verify_exit` against the unmodified state. Block processing
applies the exits in order, each one writing the state the next one reads, after the slashings.
The proof closes that gap with four facts:

1. Each packed exit passed `verify_exit` on the packing state (`filter_limit_operations_eq`,
   `verify_exit_*_ok_iff`, `exitGates_of_coresOk`).
2. The packed exits name pairwise distinct validators, and an exit of one validator leaves the
   checks of the others alone (`voluntaryExits_succeed_of_exitView`).
3. No packed exit names a validator the packed slashings can slash (`exclusionSet_covers`), and
   a slashing changes nothing else an exit reads (`exitView_of_slashings`).
4. `initiate_validator_exit`, which packing never runs, cannot fail when the exit queue has
   room (`processVoluntaryExit_succeeds`).

## The Rust that is extracted

Five functions, each free of `EthSpec`, split out of the real code so that Aeneas can translate
them:

| Function | Crate | Role |
|---|---|---|
| `filter_limit_operations` | `operation_pool` | The packing loop, generic over the iterator and the two closures |
| `insert_proposer_slashing_indices` | `operation_pool` | Adds the packed proposer slashings' proposers to the exclusion set |
| `insert_common_attesting_indices` | `operation_pool` | Adds the indices common to an attester slashing's two attestations |
| `verify_exit_validator_checks` | `state_processing` | The checks of `verify_exit` on the validator record |
| `verify_exit_pending_balance` | `state_processing` | The pending-withdrawal check of `verify_exit` |

`get_slashings_and_exits` already held the validators to be slashed in `to_be_slashed`. That set
is exact, but its correctness runs through the max cover over attester slashings. The two
`insert_*` functions add the same validators again from the packed slashings alone, so the proof
does not depend on the max cover. They add the whole intersection of the two attestations, where
the max cover adds its slashable members. A validator in the intersection that is not slashable
is slashed already, not yet active, or withdrawable, and has no valid exit, so the packed exits
are the same on any reachable state.

## What is trusted

Not proved, and to be checked by inspection:

| Item | Where it enters |
|---|---|
| Charon, Aeneas and the Lean kernel | Translation and checking |
| The external models: `HashSet` as a list of distinct values (`with_capacity`, `insert`, `contains`), and the opaque external types and hashing functions | `OperationPool/TypesExternal.lean`, `OperationPool/FunsExternal.lean`, `StateProcessing/TypesExternal.lean`, `ExternalTypes.lean` |
| The pool's iterator yields each pool entry once | `hinto`, `hyields` |
| The pool's `HashMap` is keyed by `message.validator_index` (`insert_voluntary_exit`, `persistence.rs`), so the entries name pairwise distinct validators | `hkeys` |
| The closures of `get_voluntary_exits`: the filter is `filter(exit) && signature_is_still_valid && verify_exit(..).is_ok()`, and the mapping clones the exit | `hfilter`, `hmapping`, `hkeep` |
| `verify_exit<E>` calls the two cores with the validator at the exit's index, the state's current epoch, the chain spec's constants, and the pending balance when it was computed | `hkeep` (`CoresOk`), `StateView` |
| The Lighthouse state corresponds to the spec state: same validator epochs, same current epoch, and a pending balance that was computed without overflow | `hcorr` (`StateCorr`) |
| An exit in the pool has a valid signature for the packing state. `SigVerifiedOp` is built only after a signature check; in Fulu the exit domain is fixed at the Capella fork version, and a validator's public key never changes | `hkeep` (`ExitSigned`) |
| The call site in `get_slashings_and_exits` builds the exclusion set with the two `insert_*` functions on the packed slashings, and filters the exits with it | `hexcl`, `hkeep` |
| The spec's forms of the packed exits and slashings carry the same indices and epochs as the Rust values | `hmessage`, `hproposers`, `hattesters` |
| Etheorem's Fulu model is the consensus spec, with a valid preset and config (`PresetValid`, `ConfigValid`, proved for `mainnet` and `minimal`) | The spec-side theorems |

Two hypotheses are assumptions about the run, by design:

- The spec processes the packed slashings without an error (`hslash₁`, `hslash₂`).
- The exit queue has room (`hroom`). Etheorem's reachable-state invariants do not bound the
  earliest exit epoch yet, so this stays a hypothesis.

## Scope

- **Fork.** The spec side is Fulu. Gloas overrides the exit churn and runs the parent's execution
  requests before the exits; the Gloas filter for those is proved in `../block_production`.
- **Steps before the exits.** The theorem covers the slashings. A block also runs its header,
  withdrawals, execution payload, RANDAO, eth1 data and attestations before the exits. None of
  them writes what an exit reads, but that is not proved here. `ExitView` is the interface for
  adding them: a step that keeps the exit view extends the theorem.
- **The spec's loop.** The exits fold is stated as `ForM.forM exits processVoluntaryExit`.
  `forIn_voluntaryExits_eq` (Etheorem) proves that the `for` loop over `body.voluntary_exits`
  is that fold. The split of `process_operations` into its loops is proved in Etheorem for
  Gloas (`processOperations_eq_seq`), and not yet ported to Fulu.
- **Completeness.** The theorems say every packed exit is valid. They do not say that every valid
  exit is packed.

## Layout

```
ExternalTypes.lean            opaque external types shared by both crates (hand-written, trusted)
OperationPool/
  Types.lean, Funs.lean       generated from `operation_pool`
  TypesExternal.lean          hand-written models of external types (trusted)
  FunsExternal.lean           hand-written models of external functions (trusted)
  FilterLimit.lean            proof: the packing loop
  ExclusionSet.lean           proof: the exclusion set
  Bridge/Scalars.lean         Rust `u64` to the spec's `UInt64`
  Bridge/QSort.lean           `Array.qsort` returns a permutation
  Bridge/StateCorr.lean       the state correspondence; Rust checks to spec gates
  PackedExitsValid.lean       the main theorems
StateProcessing/
  Types.lean, Funs.lean       generated from `state_processing`
  TypesExternal.lean          hand-written opaque external types (trusted)
  VerifyExit.lean             proof: the `verify_exit` cores
Audit.lean                    prints the axioms of the main theorems
extract.sh                    regenerates the generated files
lake.sh                       runs `lake` for this project
```

The `*_Template.lean` files are generated by Aeneas and list what the hand-written external
files have to provide.

## Dependencies

Both sit under `../deps`, which Git ignores. No script fetches them yet.

- `aeneas-release-5a392f4/`: the Aeneas release `nightly-2026.11.09-5a392f4`, the last one on
  Lean v4.35.0, unpacked from `aeneas-linux-x86_64.tar.gz`. It bundles the `aeneas` and `charon`
  binaries and the Lean library.
- `etheorem-lean4.35/`: a checkout of Etheorem at commit `5ba10c4`, on branch
  `voluntary-exit-proofs` of `github.com/michaelsproul/etheorem`. The branch sets
  `lean-toolchain` to v4.35.0. The checkout also needs the vendored native sources, which
  Etheorem's `just hazmat-*-vendor` recipes fetch.

## Regenerating and checking

```sh
./extract.sh          # Rust -> LLBC -> {OperationPool,StateProcessing}/{Types,Funs}.lean
./lake.sh build       # checks the generated code, the models and the proofs
./lake.sh build Audit # prints the axioms each main theorem depends on
```

Use `./lake.sh` in place of `lake`. Etheorem's native libraries link only when Lake starts
inside the Etheorem checkout, and the script takes care of that. To check one file that does not
import Etheorem, `./lake.sh env lean OperationPool/FilterLimit.lean` takes a few seconds. A file
that imports Etheorem has to go through `./lake.sh build <Module>`.

The first build needs the Mathlib cache: `./lake.sh exe cache get`.

`extract.sh` runs Charon once per crate. Aeneas emits a function of another crate only when an
extracted body calls it, so each crate's functions are extracted from that crate. Neither crate
builds on its own, and the script unifies Cargo features across the workspace to make them
build.
