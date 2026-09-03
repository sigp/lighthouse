//! The attester slashing conditions, as a pure function over a validator's history.
//!
//! `SlashingDatabase::check_attestation` spreads these conditions across four SQL queries.
//! This module states them once, in ordinary Rust over plain data, so that the rules can be
//! read, tested and mechanically verified independently of the storage layer.
//!
//! A machine-checked proof that this function never returns `Verdict::Valid` for a slashable
//! attestation lives in `../proofs`. It is not a proof about a hand-written model: the Lean
//! definition it reasons about is generated from this file by Charon and Aeneas, so editing
//! this file invalidates the proof and the CI job in
//! `.github/workflows/slashing-proofs.yml` will say so.
//!
//! # Why this is written the way it is
//!
//! The style here is deliberately unidiomatic: indexed `while` loops, no iterator adapters,
//! and no `return` from inside a loop. That is what the Aeneas verification toolchain can
//! translate: iterator combinators (`find`, `any`, `min`) become opaque, and an early return
//! inside a loop is rejected outright. Written this way, the function below is machine
//! translated to a Lean definition against which the slashing-soundness theorem is proved.
//!
//! References must also not be taken inside a loop body, which is why `roots_eq` takes its
//! arrays by value.
//!
//! It also takes plain `u64` epochs and a raw signing root rather than `Epoch`/`SigningRoot`,
//! so that verifying it does not drag in the whole `types` dependency graph.

/// A previously signed attestation, reduced to what slashing depends on.
pub struct AttRow {
    pub source: u64,
    pub target: u64,
    pub root: [u8; 32],
}

/// The outcome of the check, mirroring `Safe`/`InvalidAttestation`.
#[derive(Debug, PartialEq, Eq)]
pub enum Verdict {
    Valid,
    SameData,
    SourceExceedsTarget,
    DoubleVote,
    PrevSurroundsNew,
    NewSurroundsPrev,
    SourceLessThanLowerBound,
    TargetLessThanOrEqLowerBound,
}

/// Signing-root equality, matching `impl PartialEq for SigningRoot`.
///
/// Note this is deliberately *not* byte equality: a null (all-zero) stored root never
/// compares equal, not even to another null root. Rows written by an interchange import
/// carry a null root, and must never be mistaken for "same data".
///
/// Written as an explicit loop so it stays translatable, and taking its arrays by value
/// because a reference created inside a loop body defeats Aeneas.
fn roots_eq(a: [u8; 32], b: [u8; 32]) -> bool {
    let mut a_is_null = true;
    let mut equal = true;
    let mut i = 0;
    while i < 32 {
        if a[i] != 0 {
            a_is_null = false;
        }
        if a[i] != b[i] {
            equal = false;
        }
        i += 1;
    }
    equal && !a_is_null
}

/// Decide whether `candidate` is safe to sign given that the database holds `history`.
///
/// Mirrors `SlashingDatabase::check_attestation` guard for guard, in the same order.
pub fn check_attestation_pure(history: &[AttRow], candidate: &AttRow) -> Verdict {
    if candidate.source > candidate.target {
        return Verdict::SourceExceedsTarget;
    }

    let n = history.len();

    // Double vote. The schema's `UNIQUE (validator_id, target_epoch)` means at most one row
    // can share a target, so a single match settles it.
    let mut same_target_found = false;
    let mut same_root = false;
    let mut i = 0;
    while i < n {
        if history[i].target == candidate.target {
            same_target_found = true;
            if roots_eq(history[i].root, candidate.root) {
                same_root = true;
            }
        }
        i += 1;
    }

    if same_target_found {
        if same_root {
            return Verdict::SameData;
        }
        return Verdict::DoubleVote;
    }

    // Surround votes, in both directions.
    let mut prev_surrounds = false;
    let mut new_surrounds = false;
    let mut i = 0;
    while i < n {
        if history[i].source < candidate.source && history[i].target > candidate.target {
            prev_surrounds = true;
        }
        if history[i].source > candidate.source && history[i].target < candidate.target {
            new_surrounds = true;
        }
        i += 1;
    }

    if prev_surrounds {
        return Verdict::PrevSurroundsNew;
    }
    if new_surrounds {
        return Verdict::NewSurroundsPrev;
    }

    // Lower bounds. Skipped entirely on an empty history, matching SQL's `MIN` over no rows
    // returning NULL and the guard being bypassed.
    if n > 0 {
        let mut min_source = history[0].source;
        let mut min_target = history[0].target;
        let mut i = 1;
        while i < n {
            if history[i].source < min_source {
                min_source = history[i].source;
            }
            if history[i].target < min_target {
                min_target = history[i].target;
            }
            i += 1;
        }
        if candidate.source < min_source {
            return Verdict::SourceLessThanLowerBound;
        }
        if candidate.target <= min_target {
            return Verdict::TargetLessThanOrEqLowerBound;
        }
    }

    Verdict::Valid
}
