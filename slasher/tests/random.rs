#![cfg(any(feature = "mdbx", feature = "lmdb", feature = "redb"))]

use logging::test_logger;
use rand::prelude::*;
use slasher::{
    test_utils::{
        block, chain_spec, indexed_att, slashed_validators_from_attestations,
        slashed_validators_from_slashings, E,
    },
    Config, Slasher, SlasherDB,
};
use std::cmp::max;
use std::sync::Arc;
use tempfile::{tempdir, TempDir};
use types::{Epoch, EthSpec};

#[derive(Debug)]
struct TestConfig {
    num_validators: usize,
    max_attestations: usize,
    check_slashings: bool,
    add_blocks: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            num_validators: 4,
            max_attestations: 50,
            check_slashings: false,
            add_blocks: false,
        }
    }
}

fn make_db() -> (TempDir, SlasherDB<E>) {
    let tempdir = tempdir().unwrap();
    let initial_config = Arc::new(Config::new(tempdir.path().into()));
    let logger = test_logger();
    let spec = chain_spec();
    let db = SlasherDB::open(initial_config.clone(), spec, logger).unwrap();
    (tempdir, db)
}

fn random_test(seed: u64, mut db: SlasherDB<E>, test_config: TestConfig) -> SlasherDB<E> {
    let check_slashings = test_config.check_slashings;
    let num_validators = test_config.num_validators;
    let max_attestations = test_config.max_attestations;

    println!("Running with seed {}", seed);
    let mut rng = StdRng::seed_from_u64(seed);

    let mut config = Config::new(db.get_config().database_path.clone());
    config.validator_chunk_size = 1 << rng.gen_range(1..4);

    let chunk_size_exponent = rng.gen_range(1..4);
    config.chunk_size = 1 << chunk_size_exponent;
    config.history_length = 1 << rng.gen_range(chunk_size_exponent..chunk_size_exponent + 3);

    let config = Arc::new(config);
    db.update_config(config.clone());

    let slasher = Slasher::<E>::from_config_and_db(config.clone(), db, test_logger()).unwrap();

    let validators = (0..num_validators as u64).collect::<Vec<u64>>();

    let num_attestations = rng.gen_range(2..max_attestations + 1);

    let mut current_epoch = Epoch::new(0);
    let mut attestations = vec![];

    for _ in 0..num_attestations {
        let num_attesters = rng.gen_range(1..num_validators);
        let mut attesting_indices = validators
            .choose_multiple(&mut rng, num_attesters)
            .copied()
            .collect::<Vec<u64>>();
        attesting_indices.sort_unstable();

        // If checking slashings, generate valid attestations in range.
        let (source, target) = if check_slashings {
            let source = rng.gen_range(
                current_epoch
                    .as_u64()
                    .saturating_sub(config.history_length as u64 - 1)
                    ..current_epoch.as_u64() + 1,
            );
            let target = rng.gen_range(source..current_epoch.as_u64() + 1);
            (source, target)
        } else {
            let source = rng.gen_range(0..max(3 * current_epoch.as_u64(), 1));
            let target = rng.gen_range(source..max(3 * current_epoch.as_u64(), source + 1));
            (source, target)
        };
        let target_root = rng.gen_range(0..3);
        let attestation = indexed_att(&attesting_indices, source, target, target_root);

        if check_slashings {
            attestations.push(attestation.clone());
        }

        // Supply to slasher
        slasher.accept_attestation(attestation);

        // Maybe add a random block too
        if test_config.add_blocks && rng.gen_bool(0.1) {
            let slot = rng.gen_range(0..1 + 3 * current_epoch.as_u64() * E::slots_per_epoch() / 2);
            let proposer = rng.gen_range(0..num_validators as u64);
            let block_root = rng.gen_range(0..2);
            slasher.accept_block_header(block(slot, proposer, block_root));
        }

        // Maybe process
        if rng.gen_bool(0.1) {
            slasher.process_queued(current_epoch).unwrap();

            // Maybe prune
            if rng.gen_bool(0.1) {
                slasher.prune_database(current_epoch).unwrap();
            }
        }

        // Maybe advance to the next epoch
        if rng.gen_bool(0.5) {
            if check_slashings {
                slasher.process_queued(current_epoch).unwrap();
            }
            current_epoch += 1;
        }
    }

    if !check_slashings {
        return slasher.into_reset_db().unwrap();
    }

    slasher.process_queued(current_epoch).unwrap();

    let slashings = slasher.get_attester_slashings();

    let slashed_validators = slashed_validators_from_slashings(&slashings);
    let expected_slashed_validators = slashed_validators_from_attestations(&attestations);
    assert_eq!(slashed_validators, expected_slashed_validators);

    // Return the database for reuse.
    slasher.into_reset_db().unwrap()
}

// Fuzz-like test that runs forever on different seeds looking for crashes.
#[test]
#[ignore]
fn no_crash() {
    let mut rng = thread_rng();
    let (_tempdir, mut db) = make_db();
    loop {
        db = random_test(rng.gen(), db, TestConfig::default());
    }
}

// Fuzz-like test that runs forever on different seeds looking for crashes.
#[test]
#[ignore]
fn no_crash_with_blocks() {
    let mut rng = thread_rng();
    let (_tempdir, mut db) = make_db();
    loop {
        db = random_test(
            rng.gen(),
            db,
            TestConfig {
                add_blocks: true,
                ..TestConfig::default()
            },
        );
    }
}

// Fuzz-like test that runs forever on different seeds looking for missed slashings.
#[test]
#[ignore]
fn check_slashings() {
    let mut rng = thread_rng();
    let (_tempdir, mut db) = make_db();
    loop {
        db = random_test(
            rng.gen(),
            db,
            TestConfig {
                check_slashings: true,
                ..TestConfig::default()
            },
        );
    }
}

#[test]
fn check_slashings_example1() {
    let (_tempdir, db) = make_db();
    random_test(
        1,
        db,
        TestConfig {
            check_slashings: true,
            ..TestConfig::default()
        },
    );
}

#[test]
fn check_slashings_example2() {
    let (_tempdir, db) = make_db();
    random_test(
        2,
        db,
        TestConfig {
            check_slashings: true,
            max_attestations: 3,
            ..TestConfig::default()
        },
    );
}

#[test]
fn check_slashings_example3() {
    let (_tempdir, db) = make_db();
    random_test(
        3,
        db,
        TestConfig {
            check_slashings: true,
            max_attestations: 100,
            ..TestConfig::default()
        },
    );
}

#[test]
fn no_crash_example1() {
    let (_tempdir, db) = make_db();
    random_test(1, db, TestConfig::default());
}

#[test]
fn no_crash_example2() {
    let (_tempdir, db) = make_db();
    random_test(2, db, TestConfig::default());
}

#[test]
fn no_crash_example3() {
    let (_tempdir, db) = make_db();
    random_test(3, db, TestConfig::default());
}

#[test]
fn no_crash_blocks_example1() {
    let (_tempdir, db) = make_db();
    random_test(
        1,
        db,
        TestConfig {
            add_blocks: true,
            ..TestConfig::default()
        },
    );
}

#[test]
fn no_crash_aug_24() {
    let (_tempdir, db) = make_db();
    random_test(13519442335106054152, db, TestConfig::default());
}
