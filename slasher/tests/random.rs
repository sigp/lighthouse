use rand::prelude::*;
use rand::{rngs::StdRng, thread_rng, Rng, SeedableRng};
use slasher::{
    test_utils::{indexed_att, logger, E},
    Config, Slasher,
};
use std::cmp::max;
use tempdir::TempDir;
use types::Epoch;

fn random_test(seed: u64, check_slashings: bool) {
    let num_validators = 4_usize;
    let max_attestations = 50;

    eprintln!("Running with seed {}", seed);
    let mut rng = StdRng::seed_from_u64(seed);

    let tempdir = TempDir::new("slasher").unwrap();

    let mut config = Config::new(tempdir.path().into());
    config.validator_chunk_size = 1 << rng.gen_range(1, 4);

    println!("Validator chunk size: {}", config.validator_chunk_size);

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
                current_epoch.as_u64() - config.history_length as u64 + 1,
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

    let _slashings = slasher.get_attester_slashings();
}

#[test]
fn no_crash() {
    let mut rng = thread_rng();
    loop {
        random_test(rng.gen(), false);
    }
}

#[test]
fn check_slashings() {
    let mut rng = thread_rng();
    loop {
        random_test(rng.gen(), true);
    }
}

#[test]
fn problem() {
    random_test(2064946994010930548, false);
}

#[test]
fn problem2() {
    random_test(10684284558065464334, false);
}
