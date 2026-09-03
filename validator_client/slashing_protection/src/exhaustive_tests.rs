//! Bounded exhaustive equivalence check for the attester slashing conditions.
//!
//! `check_attestation` contains slashing rules across five SQL queries. This test suite
//! restates these rules in plain Rust and compares it against the production codepaths for
//! every attestation history up to `MAX_HISTORY` attestations from epochs `0..=MAX_EPOCH`.
//!
//! Exhaustive tests are helpful here because the rules for `check_attestation` only depend
//! on relative attestation ordering between epochs. For example attestation histories with
//! epochs `{5, 40, 1000}` work the same as ones with epochs `{0, 1, 2}`. The gaps between epochs
//! are irrelevant, so we can stick to a small range of epochs.
//!
//! These tests exist to add more coverage to the SQL itself. Our other test cases test
//! against the same SQL queries but for a much smaller set of inputs.

#![cfg(test)]

use crate::test_utils::*;
use crate::*;
use tempfile::tempdir;
use types::{AttestationData, Checkpoint, Epoch, Slot};

/// Epochs are drawn from `0..=MAX_EPOCH`.
const MAX_EPOCH: u64 = 7;

/// Histories of up to this many attestations are enumerated.
const MAX_HISTORY: usize = 3;

/// An attestation reduced to what slashing depends on: `(source, target)`.
type Att = (u64, u64);

fn attestation_data(source: u64, target: u64) -> AttestationData {
    let checkpoint = |epoch| Checkpoint {
        epoch: Epoch::from(epoch),
        root: Hash256::ZERO,
    };
    AttestationData {
        slot: Slot::from(0u64),
        index: 0,
        beacon_block_root: Hash256::ZERO,
        source: checkpoint(source),
        target: checkpoint(target),
    }
}

/// Every well-formed attestation over `0..=MAX_EPOCH`.
fn all_attestations() -> Vec<Att> {
    (0..=MAX_EPOCH)
        .flat_map(|source| (source..=MAX_EPOCH).map(move |target| (source, target)))
        .collect()
}

/// Every `(source, target)` pair over `0..=MAX_EPOCH`, including malformed ones where
/// `source > target`. These are only used as candidates. A malformed attestation is always
/// rejected, so it never ends up in a history.
fn all_candidates() -> Vec<Att> {
    (0..=MAX_EPOCH)
        .flat_map(|source| (0..=MAX_EPOCH).map(move |target| (source, target)))
        .collect()
}

/// Every history of up to `MAX_HISTORY` attestations, as ordered sequences.
fn all_histories() -> Vec<Vec<Att>> {
    let atts = all_attestations();
    let mut histories = vec![vec![]];
    let mut frontier = vec![vec![]];

    for _ in 0..MAX_HISTORY {
        let mut next = Vec::new();
        for history in &frontier {
            for att in &atts {
                let mut extended = history.clone();
                extended.push(*att);
                next.push(extended);
            }
        }
        histories.extend(next.iter().cloned());
        frontier = next;
    }
    histories
}

/// The slashing conditions, stated once. Returns `true` if the database should accept
/// `candidate` given that it currently holds `history`.
///
/// Mirrors `SlashingDatabase::check_attestation`.
fn reference_check(history: &[Att], candidate: Att) -> bool {
    let (source, target) = candidate;

    // Invalid: source after target.
    if source > target {
        return false;
    }

    // Double vote: an existing attestation with the same target. The schema's
    // `UNIQUE (validator_id, target_epoch)` means there is at most one, and an exact match is
    // `Safe::SameData` rather than an error.
    if let Some(&(existing_source, _)) = history.iter().find(|&&(_, t)| t == target) {
        return existing_source == source;
    }

    // A stored attestation surrounds the candidate.
    if history.iter().any(|&(s, t)| s < source && t > target) {
        return false;
    }

    // The candidate surrounds a stored attestation.
    if history.iter().any(|&(s, t)| s > source && t < target) {
        return false;
    }

    // Lower bounds. Note MIN, not MAX: the candidate must sit at or above the *oldest*
    // retained source, and strictly above the *oldest* retained target.
    if let Some(min_source) = history.iter().map(|&(s, _)| s).min()
        && source < min_source
    {
        return false;
    }

    if let Some(min_target) = history.iter().map(|&(_, t)| t).min()
        && target <= min_target
    {
        return false;
    }

    true
}

/// Compare `reference_check` against the database on every enumerated history.
///
/// Two comparisons are made per history:
///
/// 1. **Insertion.** Each attestation is checked in order against the current history,
///    and if accepted, is written to the slashing db.
/// 2. **Candidates.** Every candidate, including malformed ones, is then checked against
///    the final state of the slashing db w/ `preliminary_check_attestation` which reads
///    the db but never writes to the db.
///
/// `preliminary_check_attestation` is clippy-disallowed because it must never decide whether
/// to sign. Here nothing is signed and nothing is stored: it is used for its
/// read-only property, so that one database can serve every candidate for a given history.
#[test]
#[allow(clippy::disallowed_methods)]
fn reference_agrees_with_database() {
    let dir = tempdir().unwrap();
    let db = SlashingDatabase::create(&dir.path().join("slashing_protection.sqlite")).unwrap();
    let candidates = all_candidates();
    let histories = all_histories();

    let mut comparisons = 0usize;

    for (i, history) in histories.iter().enumerate() {
        let validator = pubkey(i);
        db.register_validator(validator).unwrap();

        // (1) Build the history, checking agreement on every insertion.
        let mut stored: Vec<Att> = Vec::new();
        for &att in history {
            let data = attestation_data(att.0, att.1);
            let db_verdict = db
                .with_transaction(|txn| {
                    db.check_and_insert_attestation(&validator, &data, DEFAULT_DOMAIN, txn)
                })
                .is_ok();
            let reference_verdict = reference_check(&stored, att);

            assert_eq!(
                db_verdict, reference_verdict,
                "insertion disagreement: history {stored:?}, inserting {att:?} \
                 (database accepted: {db_verdict}, reference accepted: {reference_verdict})"
            );
            comparisons += 1;

            // `Safe::SameData` is accepted but not stored, so only record genuinely new rows.
            if db_verdict && !stored.iter().any(|&(_, t)| t == att.1) {
                stored.push(att);
            }
        }

        // (2) Offer every candidate against the resulting history, without mutating it.
        for &candidate in &candidates {
            let data = attestation_data(candidate.0, candidate.1);
            let db_verdict = db
                .preliminary_check_attestation(&validator, &data, DEFAULT_DOMAIN)
                .is_ok();
            let reference_verdict = reference_check(&stored, candidate);

            assert_eq!(
                db_verdict, reference_verdict,
                "check disagreement: history {stored:?}, candidate {candidate:?} \
                 (database accepted: {db_verdict}, reference accepted: {reference_verdict})"
            );
            comparisons += 1;
        }
    }

    let insertions: usize = histories.iter().map(Vec::len).sum();
    let expected = insertions + histories.len() * candidates.len();
    assert_eq!(comparisons, expected);
}

/// The lower bound guard rejects attestations older than the oldest stored one.
/// This guard exists because pruning deletes old history rows, and the surround and
/// double vote checks cannot see rows that have been pruned. The guard uses `MIN`,
/// because an attestation between two stored attestations is still valid.
///
/// This test makes sure that `all_histories` includes an attestation history with
/// two different sources and an attestation whose source lies between them.
///
/// Without such a history, a query that uses `MAX` where `MIN` was intended would pass
/// `reference_agrees_with_database`.
#[test]
fn all_histories_reaches_min_max_case() {
    let history = [(0, 1), (2, 3)];
    let candidate = (1, 2);

    // `>= MIN(source)` accepts: 1 >= 0.
    assert!(reference_check(&history, candidate));

    // `>= MAX(source)` would reject: 1 < 2.
    let max_source = history.iter().map(|&(s, _)| s).max().unwrap();
    assert!(candidate.0 < max_source);

    // And the shape is inside the enumerated space.
    assert!(history.iter().all(|&(s, t)| t <= MAX_EPOCH && s <= t));
    assert!(history.len() <= MAX_HISTORY);
}
