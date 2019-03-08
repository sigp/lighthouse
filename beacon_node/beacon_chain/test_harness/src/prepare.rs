use crate::beacon_chain_harness::generate_deterministic_keypairs;
use bls::get_withdrawal_credentials;
use clap::{value_t, ArgMatches};
use log::debug;
use serde_yaml;
use std::path::Path;
use std::{fs, fs::File};
use types::*;

const KEYPAIRS_FILE: &str = "keypairs.yaml";
const VALIDATORS_FILE: &str = "validators.yaml";

pub fn prepare(matches: &ArgMatches, spec: &ChainSpec) {
    let validator_count = value_t!(matches.value_of("validator_count"), usize)
        .expect("Validator count is required argument");
    let output_dir = matches
        .value_of("output_dir")
        .expect("Output dir has a default value.");

    debug!("Created keypairs and validators, writing to file...");

    fs::create_dir_all(Path::new(output_dir)).unwrap();

    // Ensure that keypairs is dropped before writing validators, this provides a big memory saving
    // for large validator_counts.
    let validators: Vec<Validator> = {
        debug!("Creating {} keypairs...", validator_count);
        let keypairs = generate_deterministic_keypairs(validator_count);
        debug!("Writing {} keypairs to file...", validator_count);
        write_keypairs(output_dir, &keypairs);
        debug!("Creating {} validators...", validator_count);
        keypairs
            .iter()
            .map(|keypair| generate_validator(&keypair, spec))
            .collect()
    };

    debug!("Writing {} validators to file...", validator_count);
    write_validators(output_dir, &validators);
}

fn generate_validator(keypair: &Keypair, spec: &ChainSpec) -> Validator {
    let withdrawal_credentials = Hash256::from_slice(&get_withdrawal_credentials(
        &keypair.pk,
        spec.bls_withdrawal_prefix_byte,
    ));

    Validator {
        pubkey: keypair.pk.clone(),
        withdrawal_credentials,
        activation_epoch: spec.far_future_epoch,
        exit_epoch: spec.far_future_epoch,
        withdrawable_epoch: spec.far_future_epoch,
        initiated_exit: false,
        slashed: false,
    }
}

fn write_keypairs(output_dir: &str, keypairs: &[Keypair]) {
    let keypairs_path = Path::new(output_dir).join(KEYPAIRS_FILE);
    let keypairs_file = File::create(keypairs_path).unwrap();
    serde_yaml::to_writer(keypairs_file, &keypairs).unwrap();
}

fn write_validators(output_dir: &str, validators: &[Validator]) {
    let validators_path = Path::new(output_dir).join(VALIDATORS_FILE);
    let validators_file = File::create(validators_path).unwrap();
    serde_yaml::to_writer(validators_file, &validators).unwrap();
}
