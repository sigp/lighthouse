//! The attester slashing rules as a pure function over a validator's history.
//!
//! `SlashingDatabase::check_attestation` used to spread these rules across five SQL queries.
//! This module states them once in plain Rust over plain data. The database now only loads
//! the validator's rows and calls `check_attestation`. This makes the rules easier to
//! read, test and formally verify.
//!
//! A machine checked proof that this function never returns `Verdict::Valid` for a slashable
//! attestation lives in `../proofs`. The proof is about this file, not a hand written model.
//! Charon and Aeneas generate the Lean definition directly from this Rust. If you edit this
//! file, the proof no longer matches and the CI job in `.github/workflows/proofs.yml` fails.
//!
//! # Why this is written the way it is
//!
//! The style here is unidiomatic on purpose. Indexed `while` loops, no iterator adapters,
//! and no `return` from inside a loop. This is the subset of Rust that Aeneas can translate.
//! Iterator combinators like `find`, `any` and `min` become opaque. An early return inside a
//! loop is rejected outright.
//!
//! References must not be taken inside a loop body. This is why `roots_eq` takes its arrays
//! by value.
//!
//! The function takes plain `u64` epochs and a raw signing root instead of `Epoch` and
//! `SigningRoot`. This keeps the `types` crate out of the verification build.

/// A previously signed attestation, reduced to what slashing depends on.
pub struct AttestationRecord {
    pub source_epoch: u64,
    pub target_epoch: u64,
    pub signing_root: [u8; 32],
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

/// Signing root equality. Matches `impl PartialEq for SigningRoot`.
///
/// This is not byte equality on purpose. A null (all zero) stored root is never equal, not
/// even to another null root. Rows written by an interchange import carry a null root and
/// must never count as "same data".
///
/// Written as an explicit loop over arrays passed by value so Aeneas can translate it.
fn roots_eq(stored_root: [u8; 32], candidate_root: [u8; 32]) -> bool {
    let mut stored_root_is_null = true;
    let mut equal = true;
    let mut i = 0;
    while i < 32 {
        if stored_root[i] != 0 {
            stored_root_is_null = false;
        }
        if stored_root[i] != candidate_root[i] {
            equal = false;
        }
        i += 1;
    }
    equal && !stored_root_is_null
}

/// Decide whether `candidate` is safe to sign given that the database holds `history`.
///
/// The guards run in the same order as the SQL queries they replaced.
pub fn check_attestation(history: &[AttestationRecord], candidate: &AttestationRecord) -> Verdict {
    let candidate_source = candidate.source_epoch;
    let candidate_target = candidate.target_epoch;
    let candidate_root = candidate.signing_root;

    // Although it's not required to avoid slashing, we disallow attestations
    // which are obviously invalid by virtue of their source epoch exceeding their target.
    if candidate_source > candidate_target {
        return Verdict::SourceExceedsTarget;
    }

    let history_len = history.len();

    // Check for a double vote. Namely, an existing attestation with the same target epoch,
    // and a different signing root. If the new attestation is identical to the existing
    // attestation, then we already know that it is safe.
    let mut same_target_found = false;
    let mut same_root = false;
    let mut i = 0;
    while i < history_len {
        if history[i].target_epoch == candidate_target {
            same_target_found = true;
            if roots_eq(history[i].signing_root, candidate_root) {
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

    // Check that no previous vote is surrounding `candidate`, and that no previous vote is
    // surrounded by `candidate`.
    let mut prev_surrounds = false;
    let mut new_surrounds = false;
    let mut i = 0;
    while i < history_len {
        if history[i].source_epoch < candidate_source && history[i].target_epoch > candidate_target
        {
            prev_surrounds = true;
        }
        if history[i].source_epoch > candidate_source && history[i].target_epoch < candidate_target
        {
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

    // Check lower bounds: ensure that source is greater than or equal to min source,
    // and target is greater than min target. This allows pruning, and compatibility
    // with the interchange format. On an empty history there are no bounds to check,
    // matching `MIN` over no rows returning NULL.
    if history_len > 0 {
        let mut min_source = history[0].source_epoch;
        let mut min_target = history[0].target_epoch;
        let mut i = 1;
        while i < history_len {
            if history[i].source_epoch < min_source {
                min_source = history[i].source_epoch;
            }
            if history[i].target_epoch < min_target {
                min_target = history[i].target_epoch;
            }
            i += 1;
        }
        if candidate_source < min_source {
            return Verdict::SourceLessThanLowerBound;
        }
        if candidate_target <= min_target {
            return Verdict::TargetLessThanOrEqLowerBound;
        }
    }

    // Everything has been checked, return Valid
    Verdict::Valid
}
