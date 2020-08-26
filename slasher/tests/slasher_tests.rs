use slasher::{config::DEFAULT_CHUNK_SIZE, Config, Slasher};
use slog::{o, Drain, Logger};
use tempdir::TempDir;
use types::{
    AggregateSignature, AttestationData, AttesterSlashing, Checkpoint, Epoch, Hash256,
    IndexedAttestation, MainnetEthSpec, Slot,
};

type E = MainnetEthSpec;

fn indexed_att(
    attesting_indices: impl AsRef<[u64]>,
    source_epoch: u64,
    target_epoch: u64,
    target_root: u64,
) -> IndexedAttestation<E> {
    IndexedAttestation {
        attesting_indices: attesting_indices.as_ref().to_vec().into(),
        data: AttestationData {
            slot: Slot::new(0),
            index: 0,
            beacon_block_root: Hash256::zero(),
            source: Checkpoint {
                epoch: Epoch::new(source_epoch),
                root: Hash256::from_low_u64_be(0),
            },
            target: Checkpoint {
                epoch: Epoch::new(target_epoch),
                root: Hash256::from_low_u64_be(target_root),
            },
        },
        signature: AggregateSignature::empty(),
    }
}

fn att_slashing(
    attestation_1: &IndexedAttestation<E>,
    attestation_2: &IndexedAttestation<E>,
) -> AttesterSlashing<E> {
    AttesterSlashing {
        attestation_1: attestation_1.clone(),
        attestation_2: attestation_2.clone(),
    }
}

#[test]
fn double_vote_single_val() {
    let v = vec![99];
    let att1 = indexed_att(&v, 0, 1, 0);
    let att2 = indexed_att(&v, 0, 1, 1);
    let slashings = vec![att_slashing(&att1, &att2)];
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &slashings, 1);
    slasher_test_indiv(&attestations, &slashings, 1000);
}

#[test]
fn double_vote_multi_vals() {
    let v = vec![0, 1, 2];
    let att1 = indexed_att(&v, 0, 1, 0);
    let att2 = indexed_att(&v, 0, 1, 1);
    let slashings = vec![att_slashing(&att1, &att2)];
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
    let slashings = vec![att_slashing(&att1, &att2)];
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
    let slashings = vec![att_slashing(&att1, &att2)];
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
    slasher_test_indiv(&attestations, &[], 1);
    slasher_test_indiv(&attestations, &[], 1000);
}

// Two groups votes for different things, no slashings.
#[test]
fn no_double_vote_distinct_vals() {
    let v1 = vec![0, 1, 2, 3];
    let v2 = vec![4, 5, 6, 7];
    let att1 = indexed_att(&v1, 0, 1, 0);
    let att2 = indexed_att(&v2, 0, 1, 1);
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &[], 1);
    slasher_test_indiv(&attestations, &[], 1000);
}

#[test]
fn surrounds_existing_single_val_single_chunk() {
    let v = vec![0];
    let att1 = indexed_att(&v, 1, 2, 0);
    let att2 = indexed_att(&v, 0, 3, 0);
    let slashings = vec![att_slashing(&att1, &att2)];
    slasher_test_indiv(&[att1, att2], &slashings, 3);
}

/* FIXME: refactor these tests
#[test]
fn surrounds_existing_multi_vals_single_chunk() {
    let v = vec![0];
    let att1 = indexed_att(&v, 1, 2, 0);
    let att2 = indexed_att(&v, 0, 3, 0);
    let slashings = vec![att_slashing(&att1, &att2)];
    slasher_test_indiv(&[att1, att2], &slashings, 3);
    let validators = vec![0, 16, 1024, 300_000, 300_001];
    let att1 = indexed_att(validators.clone(), 1, 2, 0);
    let att2 = indexed_att(validators.clone(), 0, 3, 0);

    slasher.accept_attestation(att1);
    slasher.process_attestations();
    slasher.accept_attestation(att2);
    slasher.process_attestations();
}


#[test]
fn surrounds_existing_many_chunks() {
    let v = vec![0];
    let chunk_size = Config::default().chunk_size as u64;
    let att1 = indexed_att(&v, 3 * chunk_size, 3 * chunk_size + 1, 0);
    let att2 = indexed_att(&v, 0, 3 * chunk_size + 2, 0);
    let slashings = vec![att_slashing(&att1, &att2)];
    let attestations = vec![att1, att2];
    slasher_test(&attestations, &slashings, 4 * chunk_size, |_| true);
}
*/

#[test]
fn surrounded_by_single_val_single_chunk() {
    let v = vec![0];
    let att1 = indexed_att(&v, 0, 15, 0);
    let att2 = indexed_att(&v, 1, 14, 0);
    let slashings = vec![att_slashing(&att1, &att2)];
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &slashings, 15);
}

#[test]
fn surrounded_by_single_val_multi_chunk() {
    let v = vec![0];
    let chunk_size = DEFAULT_CHUNK_SIZE as u64;
    let att1 = indexed_att(&v, 0, 3 * chunk_size, 0);
    let att2 = indexed_att(&v, chunk_size, chunk_size + 1, 0);
    let slashings = vec![att_slashing(&att1, &att2)];
    let attestations = vec![att1, att2];
    slasher_test_indiv(&attestations, &slashings, 3 * chunk_size);
    slasher_test_indiv(&attestations, &slashings, 4 * chunk_size);
}

/*
fn slasher_tests(attestations: &[IndexedAttestation<E>], expected: &[AttesterSlashing<E>]) {
    // Process after every attestation.
    // slasher_test(attestations, expected, |_| true);
    // Process only at the end.
    slasher_test(attestations, expected, |_| false);
    // Process every second attestation.
    // slasher_test(attestations, expected, |i| i % 2 == 0);
}
*/

// Process each attestation individually, and confirm that the slashings produced are as expected.
fn slasher_test_indiv(
    attestations: &[IndexedAttestation<E>],
    expected: &[AttesterSlashing<E>],
    current_epoch: u64,
) {
    slasher_test(attestations, expected, current_epoch, |_| true);
}

// FIXME(sproul): move this somewhere else
fn logger() -> Logger {
    let decorator = slog_term::PlainDecorator::new(slog_term::TestStdoutWriter);
    let drain = slog_term::FullFormat::new(decorator).build();
    Logger::root(Box::new(std::sync::Mutex::new(drain)).fuse(), o!())
}

fn slasher_test(
    attestations: &[IndexedAttestation<E>],
    expected: &[AttesterSlashing<E>],
    current_epoch: u64,
    should_process_after: impl Fn(usize) -> bool,
) {
    let tempdir = TempDir::new("slasher").unwrap();
    let config = Config::new(tempdir.path().into());
    let slasher = Slasher::open(config, logger()).unwrap();
    let current_epoch = Epoch::new(current_epoch);

    for (i, attestation) in attestations.iter().enumerate() {
        slasher.accept_attestation(attestation.clone());

        if should_process_after(i) {
            slasher.process_attestations(current_epoch).unwrap();
        }
    }
    slasher.process_attestations(current_epoch).unwrap();

    let slashings = slasher.get_attester_slashings();

    for (i, slashing) in expected.iter().enumerate() {
        assert_eq!(*slashing, slashings[i], "slashing {} should match", i);
    }

    assert_eq!(expected, &slashings[..]);
}
