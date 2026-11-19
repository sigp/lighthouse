//! Tests that stress the concurrency safety of the slashing protection DB.
#![cfg(test)]

use crate::attestation_tests::attestation_data_builder;
use crate::block_tests::block;
use crate::test_utils::*;
use crate::*;
use rayon::prelude::*;
use tempfile::tempdir;

#[test]
fn xmss_leaf_reservations_survive_races_and_restarts() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("slashing_protection.sqlite");
    let db = SlashingDatabase::create(&path).unwrap();
    let pubkey = pubkey(0);
    let leaf = 1 << 15;
    db.register_validator(pubkey).unwrap();

    let roots = [Hash256::ZERO, Hash256::with_last_byte(1)];
    let barrier = std::sync::Barrier::new(roots.len());
    let winner = std::thread::scope(|scope| {
        let (db, barrier) = (&db, &barrier);
        let workers = roots.map(|root| {
            scope.spawn(move || {
                barrier.wait();
                (
                    root,
                    db.with_transaction(|txn| db.reserve_xmss_leaf(txn, &pubkey, leaf, root)),
                )
            })
        });
        let mut winner = None;
        for worker in workers {
            let (root, result) = worker.join().unwrap();
            match result {
                Ok(Safe::Valid) => assert!(winner.replace(root).is_none()),
                result => assert_eq!(result, Err(NotSafe::ConflictingXmssLeaf(leaf))),
            }
        }
        winner.unwrap()
    });

    drop(db);
    let db = SlashingDatabase::open(&path).unwrap();
    assert!(matches!(
        db.export_all_interchange_info(Hash256::ZERO),
        Err(InterchangeError::XmssLeavesNotRepresentable(key)) if key == pubkey
    ));
    for root in roots {
        assert_eq!(
            db.with_transaction(|txn| db.reserve_xmss_leaf(txn, &pubkey, leaf, root)),
            if root == winner {
                Ok(Safe::SameData)
            } else {
                Err(NotSafe::ConflictingXmssLeaf(leaf))
            }
        );
    }
}

#[test]
fn block_same_slot() {
    let dir = tempdir().unwrap();
    let slashing_db_file = dir.path().join("slashing_protection.sqlite");
    let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

    let pk = pubkey(0);

    slashing_db.register_validator(pk).unwrap();

    // A stream of blocks all with the same slot.
    let num_blocks = 10;
    let results = (0..num_blocks)
        .into_par_iter()
        .map(|_| slashing_db.check_and_insert_block_proposal(&pk, &block(1), DEFAULT_DOMAIN))
        .collect::<Vec<_>>();

    let num_successes = results.iter().filter(|res| res.is_ok()).count();
    assert_eq!(num_successes, 1);
}

#[test]
fn attestation_same_target() {
    let dir = tempdir().unwrap();
    let slashing_db_file = dir.path().join("slashing_protection.sqlite");
    let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

    let pk = pubkey(0);

    slashing_db.register_validator(pk).unwrap();

    // A stream of attestations all with the same target.
    let num_attestations = 10;
    let results = (0..num_attestations)
        .into_par_iter()
        .map(|i| {
            slashing_db.with_transaction(|txn| {
                slashing_db.check_and_insert_attestation(
                    &pk,
                    &attestation_data_builder(i, num_attestations),
                    DEFAULT_DOMAIN,
                    txn,
                )
            })
        })
        .collect::<Vec<_>>();

    let num_successes = results.iter().filter(|res| res.is_ok()).count();
    assert_eq!(num_successes, 1);
}

#[test]
fn attestation_surround_fest() {
    let dir = tempdir().unwrap();
    let slashing_db_file = dir.path().join("slashing_protection.sqlite");
    let slashing_db = SlashingDatabase::create(&slashing_db_file).unwrap();

    let pk = pubkey(0);

    slashing_db.register_validator(pk).unwrap();

    // A stream of attestations that all surround each other.
    let num_attestations = 10;

    let results = (0..num_attestations)
        .into_par_iter()
        .map(|i| {
            let att = attestation_data_builder(i, 2 * num_attestations - i);
            slashing_db.with_transaction(|txn| {
                slashing_db.check_and_insert_attestation(&pk, &att, DEFAULT_DOMAIN, txn)
            })
        })
        .collect::<Vec<_>>();

    let num_successes = results.iter().filter(|res| res.is_ok()).count();
    assert_eq!(num_successes, 1);
}
