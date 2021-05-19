use maplit::hashset;
use rayon::prelude::*;
use slasher::{
    config::DEFAULT_CHUNK_SIZE,
    test_utils::{att_slashing, indexed_att, logger, slashed_validators_from_slashings, E},
    Config, Slasher,
};
use std::collections::HashSet;
use tempfile::tempdir;
use types::{AttesterSlashing, Epoch, IndexedAttestation};

#[test]
fn double_vote_single_val() {
    let v = vec![99];
    let att1 = indexed_att(&v, 0, 1, 0);
    let att2 = indexed_att(&v, 0, 1, 1);
    let slashings = hashset![att_slashing(&att1, &att2)];
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &slashings, 1);
    slasher_test_indiv(&attestations, &slashings, 1000);
}

#[test]
fn double_vote_multi_vals() {
    let v = vec![0, 1, 2];
    let att1 = indexed_att(&v, 0, 1, 0);
    let att2 = indexed_att(&v, 0, 1, 1);
    let slashings = hashset![att_slashing(&att1, &att2)];
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &slashings, 1);
    slasher_test_indiv(&attestations, &slashings, 1000);
}

// A subset of validators double vote.
#[test]
fn double_vote_some_vals() {
    let v1 = vec![0, 1, 2, 3, 4, 5, 6];
    let v2 = vec![0, 2, 4, 6];
    let att1 = indexed_att(&v1, 0, 1, 0);
    let att2 = indexed_att(&v2, 0, 1, 1);
    let slashings = hashset![att_slashing(&att1, &att2)];
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &slashings, 1);
    slasher_test_indiv(&attestations, &slashings, 1000);
}

// A subset of validators double vote, others vote twice for the same thing.
#[test]
fn double_vote_some_vals_repeat() {
    let v1 = vec![0, 1, 2, 3, 4, 5, 6];
    let v2 = vec![0, 2, 4, 6];
    let v3 = vec![1, 3, 5];
    let att1 = indexed_att(&v1, 0, 1, 0);
    let att2 = indexed_att(&v2, 0, 1, 1);
    let att3 = indexed_att(&v3, 0, 1, 0);
    let slashings = hashset![att_slashing(&att1, &att2)];
    let attestations = vec![att1, att2, att3];
    slasher_test_indiv(&attestations, &slashings, 1);
    slasher_test_indiv(&attestations, &slashings, 1000);
}

// Nobody double votes, nobody gets slashed.
#[test]
fn no_double_vote_same_target() {
    let v1 = vec![0, 1, 2, 3, 4, 5, 6];
    let v2 = vec![0, 1, 2, 3, 4, 5, 7, 8];
    let att1 = indexed_att(&v1, 0, 1, 0);
    let att2 = indexed_att(&v2, 0, 1, 0);
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &hashset! {}, 1);
    slasher_test_indiv(&attestations, &hashset! {}, 1000);
}

// Two groups votes for different things, no slashings.
#[test]
fn no_double_vote_distinct_vals() {
    let v1 = vec![0, 1, 2, 3];
    let v2 = vec![4, 5, 6, 7];
    let att1 = indexed_att(&v1, 0, 1, 0);
    let att2 = indexed_att(&v2, 0, 1, 1);
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &hashset! {}, 1);
    slasher_test_indiv(&attestations, &hashset! {}, 1000);
}

#[test]
fn no_double_vote_repeated() {
    let v = vec![0, 1, 2, 3, 4];
    let att1 = indexed_att(&v, 0, 1, 0);
    let att2 = att1.clone();
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &hashset! {}, 1);
    slasher_test_batch(&attestations, &hashset! {}, 1);
    parallel_slasher_test(&attestations, hashset! {}, 1);
}

#[test]
fn surrounds_existing_single_val_single_chunk() {
    let v = vec![0];
    let att1 = indexed_att(&v, 1, 2, 0);
    let att2 = indexed_att(&v, 0, 3, 0);
    let slashings = hashset![att_slashing(&att2, &att1)];
    slasher_test_indiv(&[att1, att2], &slashings, 3);
}

#[test]
fn surrounds_existing_multi_vals_single_chunk() {
    let validators = vec![0, 16, 1024, 300_000, 300_001];
    let att1 = indexed_att(validators.clone(), 1, 2, 0);
    let att2 = indexed_att(validators, 0, 3, 0);
    let slashings = hashset![att_slashing(&att2, &att1)];
    slasher_test_indiv(&[att1, att2], &slashings, 3);
}

#[test]
fn surrounds_existing_many_chunks() {
    let v = vec![0];
    let chunk_size = DEFAULT_CHUNK_SIZE as u64;
    let att1 = indexed_att(&v, 3 * chunk_size, 3 * chunk_size + 1, 0);
    let att2 = indexed_att(&v, 0, 3 * chunk_size + 2, 0);
    let slashings = hashset![att_slashing(&att2, &att1)];
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &slashings, 4 * chunk_size);
}

#[test]
fn surrounded_by_single_val_single_chunk() {
    let v = vec![0];
    let att1 = indexed_att(&v, 0, 15, 0);
    let att2 = indexed_att(&v, 1, 14, 0);
    let slashings = hashset![att_slashing(&att1, &att2)];
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &slashings, 15);
}

#[test]
fn surrounded_by_single_val_multi_chunk() {
    let v = vec![0];
    let chunk_size = DEFAULT_CHUNK_SIZE as u64;
    let att1 = indexed_att(&v, 0, 3 * chunk_size, 0);
    let att2 = indexed_att(&v, chunk_size, chunk_size + 1, 0);
    let slashings = hashset![att_slashing(&att1, &att2)];
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &slashings, 3 * chunk_size);
    slasher_test_indiv(&attestations, &slashings, 4 * chunk_size);
}

// Process each attestation individually, and confirm that the slashings produced are as expected.
fn slasher_test_indiv(
    attestations: &[IndexedAttestation<E>],
    expected: &HashSet<AttesterSlashing<E>>,
    current_epoch: u64,
) {
    slasher_test(attestations, expected, current_epoch, |_| true);
}

// Process all attestations in one batch.
fn slasher_test_batch(
    attestations: &[IndexedAttestation<E>],
    expected: &HashSet<AttesterSlashing<E>>,
    current_epoch: u64,
) {
    slasher_test(attestations, expected, current_epoch, |_| false);
}

fn slasher_test(
    attestations: &[IndexedAttestation<E>],
    expected: &HashSet<AttesterSlashing<E>>,
    current_epoch: u64,
    should_process_after: impl Fn(usize) -> bool,
) {
    let tempdir = tempdir().unwrap();
    let config = Config::new(tempdir.path().into()).for_testing();
    let slasher = Slasher::open(config, logger()).unwrap();
    let current_epoch = Epoch::new(current_epoch);

    for (i, attestation) in attestations.iter().enumerate() {
        slasher.accept_attestation(attestation.clone());

        if should_process_after(i) {
            slasher.process_queued(current_epoch).unwrap();
        }
    }
    slasher.process_queued(current_epoch).unwrap();

    let slashings = slasher.get_attester_slashings();

    assert_eq!(&slashings, expected);

    // Pruning should not error.
    slasher.prune_database(current_epoch).unwrap();
    // windows won't delete the temporary directory if you don't do this..
    drop(slasher);
}

fn parallel_slasher_test(
    attestations: &[IndexedAttestation<E>],
    expected_slashed_validators: HashSet<u64>,
    current_epoch: u64,
) {
    let tempdir = tempdir().unwrap();
    let config = Config::new(tempdir.path().into()).for_testing();
    let slasher = Slasher::open(config, logger()).unwrap();
    let current_epoch = Epoch::new(current_epoch);

    attestations
        .into_par_iter()
        .try_for_each(|attestation| {
            slasher.accept_attestation(attestation.clone());
            slasher.process_queued(current_epoch).map(|_| ())
        })
        .expect("parallel processing shouldn't race");

    let slashings = slasher.get_attester_slashings();
    let slashed_validators = slashed_validators_from_slashings(&slashings);
    assert_eq!(slashed_validators, expected_slashed_validators);
    // windows won't delete the temporary directory if you don't do this..
    drop(slasher);
}
