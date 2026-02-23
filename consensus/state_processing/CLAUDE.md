# state_processing crate

Implements Ethereum consensus spec state transitions. **Strictest safety rules in the repo.**

## Compile-Time Enforcement

This crate denies unsafe patterns via clippy attributes in `src/lib.rs`:

```rust
#[deny(
    clippy::arithmetic_side_effects,  // No a + b, a - b, a * b
    clippy::disallowed_methods,
    clippy::indexing_slicing,         // No array[i]
    clippy::unwrap_used,              // No .unwrap()
    clippy::expect_used,              // No .expect()
    clippy::panic,                    // No panic!()
    clippy::let_underscore_must_use
)]
```

These are **not conventions** — they are compiler errors. Code that violates them will not build.

## Required Patterns

```rust
// Arithmetic: always safe
let result = a.saturating_add(b);
let result = a.safe_add(b)?;          // via safe_arith::SafeArith
let result = a.checked_sub(b).ok_or(Error::Underflow)?;

// Indexing: always bounds-checked
let item = slice.get(i).ok_or(Error::OutOfBounds)?;

// Errors: always propagated
let value = fallible_call()?;
```

## Spec Compliance

Code must match the Ethereum consensus spec. Reference spec sections in comments:
```rust
// Spec: https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#deposits
```

## Structure

- `per_block_processing/` — Process individual block operations (attestations, deposits, slashings, exits)
- `per_epoch_processing/` — Rewards, penalties, validator activations, slashing
- `per_slot_processing.rs` — Slot increment, RANDAO
- `consensus_context.rs` — Consensus parameters passed through processing

## Testing

```bash
# Unit tests
cargo nextest run -p state_processing

# Ethereum Foundation spec vectors (downloads ~500MB first time)
make test-ef
```
