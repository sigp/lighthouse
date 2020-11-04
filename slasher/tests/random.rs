use rand::prelude::*;
use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};
use slasher::{
    test_utils::{indexed_att, logger, E},
    Config, Slasher,
};
use std::cmp::max;
use std::collections::HashSet;
use std::iter::FromIterator;
use tempdir::TempDir;
use types::{AttesterSlashing, Epoch, IndexedAttestation};

#[derive(Debug)]
struct TestConfig {
    num_validators: usize,
    max_attestations: usize,
    check_slashings: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            num_validators: 4,
            max_attestations: 50,
            check_slashings: false,
        }
    }
}

fn random_test(seed: u64, test_config: TestConfig) {
    let check_slashings = test_config.check_slashings;
    let num_validators = test_config.num_validators;
    let max_attestations = test_config.max_attestations;

    println!("Running with seed {}", seed);
    let mut rng = StdRng::seed_from_u64(seed);

    let tempdir = TempDir::new("slasher").unwrap();

    let mut config = Config::new(tempdir.path().into());
    config.validator_chunk_size = 1 << rng.gen_range(1, 4);

    eprintln!("Validator chunk size: {}", config.validator_chunk_size);

    let chunk_size_exponent = rng.gen_range(1, 4);
    config.chunk_size = 1 << chunk_size_exponent;
    config.history_length = 1 << rng.gen_range(chunk_size_exponent, chunk_size_exponent + 3);

    eprintln!("Chunk size: {}", config.chunk_size);
    eprintln!("History length: {}", config.history_length);

    let slasher = Slasher::<E>::open(config.clone(), logger()).unwrap();

    let validators = (0..num_validators as u64).collect::<Vec<u64>>();

    let num_attestations = rng.gen_range(2, max_attestations + 1);

    let mut current_epoch = Epoch::new(0);
    let mut attestations = vec![];

    for _ in 0..num_attestations {
        let num_attesters = rng.gen_range(1, num_validators);
        let mut attesting_indices = validators
            .choose_multiple(&mut rng, num_attesters)
            .copied()
            .collect::<Vec<u64>>();
        attesting_indices.sort();

        // If checking slashings, generate valid attestations in range.
        let (source, target) = if check_slashings {
            let source = rng.gen_range(
                current_epoch
                    .as_u64()
                    .saturating_sub(config.history_length as u64 - 1),
                current_epoch.as_u64() + 1,
            );
            let target = rng.gen_range(source, current_epoch.as_u64() + 1);
            (source, target)
        } else {
            let source = rng.gen_range(0, max(3 * current_epoch.as_u64(), 1));
            let target = rng.gen_range(source, max(3 * current_epoch.as_u64(), source + 1));
            (source, target)
        };
        let target_root = rng.gen_range(0, 3);
        let attestation = indexed_att(&attesting_indices, source, target, target_root);

        eprintln!(
            "Attestation {}=>{} from {:?} for root {}",
            source, target, attesting_indices, target_root
        );

        if check_slashings {
            attestations.push(attestation.clone());
        }

        // Supply to slasher
        slasher.accept_attestation(attestation);

        // Maybe process
        if rng.gen_bool(0.1) {
            eprintln!("Processing {}", current_epoch);
            slasher.process_queued(current_epoch).unwrap();

            // Maybe prune
            if rng.gen_bool(0.1) {
                eprintln!("Pruning at epoch {}", current_epoch);
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
        return;
    }

    slasher.process_queued(current_epoch).unwrap();

    let slashings = slasher.get_attester_slashings();

    let slashed_validators = slashed_validators_from_slashings(&slashings);
    let expected_slashed_validators = slashed_validators_from_attestations(&attestations);
    assert_eq!(slashed_validators, expected_slashed_validators);
}

fn hashset_intersection(
    attestation_1_indices: &[u64],
    attestation_2_indices: &[u64],
) -> HashSet<u64> {
    &HashSet::from_iter(attestation_1_indices.iter().copied())
        & &HashSet::from_iter(attestation_2_indices.iter().copied())
}

fn slashed_validators_from_slashings(slashings: &HashSet<AttesterSlashing<E>>) -> HashSet<u64> {
    slashings
        .iter()
        .flat_map(|slashing| {
            let att1 = &slashing.attestation_1;
            let att2 = &slashing.attestation_2;
            assert!(
                att1.is_double_vote(att2) || att1.is_surround_vote(att2),
                "invalid slashing: {:#?}",
                slashing
            );
            hashset_intersection(&att1.attesting_indices, &att2.attesting_indices)
        })
        .collect()
}

fn slashed_validators_from_attestations(attestations: &[IndexedAttestation<E>]) -> HashSet<u64> {
    let mut slashed_validators = HashSet::new();
    // O(n^2) code, watch out.
    for att1 in attestations {
        for att2 in attestations {
            if att1 == att2 {
                continue;
            }

            if att1.is_double_vote(att2) || att1.is_surround_vote(att2) {
                slashed_validators.extend(hashset_intersection(
                    &att1.attesting_indices,
                    &att2.attesting_indices,
                ));
            }
        }
    }
    slashed_validators
}

#[test]
#[ignore]
fn no_crash() {
    let mut rng = thread_rng();
    loop {
        random_test(rng.gen(), TestConfig::default());
    }
}

#[test]
#[ignore]
fn check_slashings() {
    let mut rng = thread_rng();
    loop {
        random_test(
            rng.gen(),
            TestConfig {
                check_slashings: true,
                ..TestConfig::default()
            },
        );
    }
}

#[test]
fn problema() {
    random_test(
        17417858527589321514,
        TestConfig {
            check_slashings: true,
            ..TestConfig::default()
        },
    );
}

#[test]
fn slash_out_of_order() {
    random_test(
        3534213164912297730,
        TestConfig {
            check_slashings: true,
            max_attestations: 3,
            ..TestConfig::default()
        },
    );
}

#[test]
fn ooft() {
    random_test(
        16346384169145986037,
        TestConfig {
            check_slashings: true,
            ..TestConfig::default()
        },
    );
}
