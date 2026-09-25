//! Bounded exhaustive equivalence check for the attester slashing conditions.
//!
//! `check_attestation` used to contain slashing rules across five SQL queries. They now live
//! in `attestation_rules::check_attestation`. This test suite restates these rules a third
//! time and compares all three against each other for every attestation history up to
//! `MAX_HISTORY` attestations from epochs `0..=MAX_EPOCH`.
//!
//! Exhaustive tests are helpful here because the rules for `check_attestation` only depend
//! on relative attestation ordering between epochs. For example attestation histories with
//! epochs `{5, 40, 1000}` work the same as ones with epochs `{0, 1, 2}`. The gaps between epochs
//! are irrelevant, so we can stick to a small range of epochs.
//!
//! These tests exist to add more coverage to the SQL itself. Our other test cases test
//! against the same SQL queries but for a much smaller set of inputs.

#![cfg(test)]

use crate::attestation_rules::{self, AttestationRecord, Verdict};
use crate::test_utils::*;
use crate::*;
use tempfile::tempdir;
use types::{AttestationData, Checkpoint, Epoch, Slot};

/// Epochs are drawn from `0..=MAX_EPOCH`.
const MAX_EPOCH: u64 = 7;

/// Histories of up to this many attestations are enumerated.
const MAX_HISTORY: usize = 3;

/// An attestation reduced to what slashing depends on: `(source, target)`.
type EpochPair = (u64, u64);

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
fn well_formed_attestations() -> Vec<EpochPair> {
    (0..=MAX_EPOCH)
        .flat_map(|source| (source..=MAX_EPOCH).map(move |target| (source, target)))
        .collect()
}

/// Every `(source, target)` pair over `0..=MAX_EPOCH`, including malformed ones where
/// `source > target`. These are only used as candidates. A malformed attestation is always
/// rejected, so it never ends up in a history.
fn all_epoch_pairs() -> Vec<EpochPair> {
    (0..=MAX_EPOCH)
        .flat_map(|source| (0..=MAX_EPOCH).map(move |target| (source, target)))
        .collect()
}

/// Every history of up to `MAX_HISTORY` attestations, as ordered sequences.
fn all_histories() -> Vec<Vec<EpochPair>> {
    let atts = well_formed_attestations();
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

/// The slashing conditions, stated once. Returns the verdict the database should reach for
/// `candidate` given that it currently holds `history`.
///
/// Mirrors `SlashingDatabase::check_attestation`.
///
/// Returns a `Verdict` so that a guard reporting the *wrong reason* is caught as well
/// as one reaching the wrong accept/reject.
fn reference_check(history: &[EpochPair], candidate: EpochPair) -> Verdict {
    let (source, target) = candidate;

    // Invalid: source after target.
    if source > target {
        return Verdict::SourceExceedsTarget;
    }

    // Double vote: an existing attestation with the same target. The schema's
    // `UNIQUE (validator_id, target_epoch)` means there is at most one, and an exact match is
    // `Safe::SameData` rather than an error.
    if let Some(&(existing_source, _)) = history.iter().find(|&&(_, t)| t == target) {
        if existing_source == source {
            return Verdict::SameData;
        }
        return Verdict::DoubleVote;
    }

    // A stored attestation surrounds the candidate.
    if history.iter().any(|&(s, t)| s < source && t > target) {
        return Verdict::PrevSurroundsNew;
    }

    // The candidate surrounds a stored attestation.
    if history.iter().any(|&(s, t)| s > source && t < target) {
        return Verdict::NewSurroundsPrev;
    }

    // Lower bounds. Note MIN, not MAX: the candidate must sit at or above the *oldest*
    // retained source, and strictly above the *oldest* retained target.
    if let Some(min_source) = history.iter().map(|&(s, _)| s).min()
        && source < min_source
    {
        return Verdict::SourceLessThanLowerBound;
    }

    if let Some(min_target) = history.iter().map(|&(_, t)| t).min()
        && target <= min_target
    {
        return Verdict::TargetLessThanOrEqLowerBound;
    }

    Verdict::Valid
}

/// `true` if the verdict means the database accepts the attestation.
fn accepts(verdict: &Verdict) -> bool {
    matches!(verdict, Verdict::Valid | Verdict::SameData)
}

/// The verdict corresponding to a `check_attestation` result, so the database can be compared
/// against the reference by reason and not merely by accept/reject.
fn verdict_of(result: &Result<Safe, NotSafe>) -> Verdict {
    match result {
        Ok(Safe::Valid) => Verdict::Valid,
        Ok(Safe::SameData) => Verdict::SameData,
        Err(NotSafe::InvalidAttestation(invalid)) => match invalid {
            InvalidAttestation::SourceExceedsTarget => Verdict::SourceExceedsTarget,
            InvalidAttestation::DoubleVote(_) => Verdict::DoubleVote,
            InvalidAttestation::PrevSurroundsNew { .. } => Verdict::PrevSurroundsNew,
            InvalidAttestation::NewSurroundsPrev { .. } => Verdict::NewSurroundsPrev,
            InvalidAttestation::SourceLessThanLowerBound { .. } => {
                Verdict::SourceLessThanLowerBound
            }
            InvalidAttestation::TargetLessThanOrEqLowerBound { .. } => {
                Verdict::TargetLessThanOrEqLowerBound
            }
        },
        other => panic!("unexpected result outside the slashing conditions: {other:?}"),
    }
}

/// The signing root `attestation_data` produces for a given `(source, target)`.
fn signing_root_bytes(att: EpochPair) -> [u8; 32] {
    let data = attestation_data(att.0, att.1);
    SignedAttestation::from_attestation(&data, DEFAULT_DOMAIN)
        .signing_root
        .to_hash256_raw()
        .0
}

fn to_row(att: EpochPair) -> AttestationRecord {
    AttestationRecord {
        source_epoch: att.0,
        target_epoch: att.1,
        signing_root: signing_root_bytes(att),
    }
}

fn to_rows(atts: &[EpochPair]) -> Vec<AttestationRecord> {
    atts.iter().map(|att| to_row(*att)).collect()
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
    let candidates = all_epoch_pairs();
    let histories = all_histories();

    let mut comparisons = 0usize;

    for (i, attempts) in histories.iter().enumerate() {
        let validator = pubkey(i);
        db.register_validator(validator).unwrap();

        // (1) Build the history, checking agreement on every insertion.
        let mut stored: Vec<EpochPair> = Vec::new();
        for &att in attempts {
            let data = attestation_data(att.0, att.1);
            let db_result = db.with_transaction(|txn| {
                db.check_and_insert_attestation(&validator, &data, DEFAULT_DOMAIN, txn)
            });
            let db_verdict = verdict_of(&db_result);
            let reference_verdict = reference_check(&stored, att);

            assert_eq!(
                db_verdict, reference_verdict,
                "insertion disagreement: history {stored:?}, inserting {att:?}"
            );
            comparisons += 1;

            // `Safe::SameData` is accepted but not stored, so only record genuinely new rows.
            if accepts(&db_verdict) && !stored.iter().any(|&(_, t)| t == att.1) {
                stored.push(att);
            }
        }

        // (2) Offer every candidate against the resulting history, without mutating it.
        for &candidate in &candidates {
            let data = attestation_data(candidate.0, candidate.1);
            let db_result = db.preliminary_check_attestation(&validator, &data, DEFAULT_DOMAIN);
            let db_verdict = verdict_of(&db_result);
            let reference_verdict = reference_check(&stored, candidate);

            assert_eq!(
                db_verdict, reference_verdict,
                "check disagreement: history {stored:?}, candidate {candidate:?}"
            );
            comparisons += 1;

            // (3) The same candidate, passed straight to `attestation_rules::check_attestation`
            // with no database in the way. Agreement here separates a logic bug from a bug in
            // the `Epoch`/`u64` and `SigningRoot`/`[u8; 32]` conversions.
            let rules_verdict =
                attestation_rules::check_attestation(&to_rows(&stored), &to_row(candidate));
            assert_eq!(
                rules_verdict, reference_verdict,
                "rules disagreement: history {stored:?}, candidate {candidate:?}"
            );
            comparisons += 1;
        }
    }

    let insertions: usize = histories.iter().map(Vec::len).sum();
    let expected = insertions + 2 * histories.len() * candidates.len();
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
fn all_histories_covers_min_vs_max_bound() {
    let history = [(0, 1), (2, 3)];
    let candidate = (1, 2);

    // `>= MIN(source)` accepts: 1 >= 0.
    assert_eq!(reference_check(&history, candidate), Verdict::Valid);

    // `>= MAX(source)` would reject: 1 < 2.
    let max_source = history.iter().map(|&(s, _)| s).max().unwrap();
    assert!(candidate.0 < max_source);

    // The enumeration really produces this history.
    assert!(all_histories().contains(&history.to_vec()));
    assert!(well_formed_attestations().contains(&candidate));
}

/// `roots_eq` must match `impl PartialEq for SigningRoot`. A null root is never equal.
#[test]
fn null_root_is_never_same_data() {
    let null = [0u8; 32];
    let candidate = AttestationRecord {
        source_epoch: 1,
        target_epoch: 2,
        signing_root: null,
    };

    // Stored row with a null root, identical epochs. This is a double vote, NOT same data.
    let history = vec![AttestationRecord {
        source_epoch: 1,
        target_epoch: 2,
        signing_root: null,
    }];
    assert_eq!(
        attestation_rules::check_attestation(&history, &candidate),
        Verdict::DoubleVote
    );

    // A non-null stored root matching the candidate's is same data.
    let mut root = [0u8; 32];
    root[0] = 7;
    let history = vec![AttestationRecord {
        source_epoch: 1,
        target_epoch: 2,
        signing_root: root,
    }];
    let candidate = AttestationRecord {
        source_epoch: 1,
        target_epoch: 2,
        signing_root: root,
    };
    assert_eq!(
        attestation_rules::check_attestation(&history, &candidate),
        Verdict::SameData
    );
}
