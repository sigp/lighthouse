//! Tests that stress the concurrency safety of the slashing protection DB.
#![cfg(test)]

use crate::attestation_tests::attestation_data_builder;
use crate::block_tests::block;
use crate::test_utils::*;
use crate::*;
use rayon::prelude::*;
use tempfile::tempdir;

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
            slashing_db.check_and_insert_attestation(
                &pk,
                &attestation_data_builder(i, num_attestations),
                DEFAULT_DOMAIN,
            )
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
            slashing_db.check_and_insert_attestation(&pk, &att, DEFAULT_DOMAIN)
        })
        .collect::<Vec<_>>();

    let num_successes = results.iter().filter(|res| res.is_ok()).count();
    assert_eq!(num_successes, 1);
}
