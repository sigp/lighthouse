use crate::beacon_chain_harness::generate_deposits_with_deterministic_keypairs;
use clap::{value_t, ArgMatches};
use log::debug;
use serde_yaml;
use std::path::Path;
use std::{fs, fs::File};
use types::*;

const KEYPAIRS_FILE: &str = "keypairs.yaml";
const DEPOSITS_FILE: &str = "deposits.yaml";

pub fn prepare(matches: &ArgMatches, spec: &ChainSpec) {
    let validator_count = value_t!(matches.value_of("validator_count"), usize)
        .expect("Validator count is required argument");
    let genesis_time =
        value_t!(matches.value_of("genesis_time"), u64).expect("Genesis time is required argument");
    let output_dir = matches
        .value_of("output_dir")
        .expect("Output dir has a default value.");

    let (keypairs, deposits) =
        generate_deposits_with_deterministic_keypairs(validator_count, genesis_time, &spec);

    debug!("Created keypairs and deposits, writing to file...");

    fs::create_dir_all(Path::new(output_dir)).unwrap();

    let keypairs_path = Path::new(output_dir).join(KEYPAIRS_FILE);
    let keypairs_file = File::create(keypairs_path).unwrap();
    serde_yaml::to_writer(keypairs_file, &keypairs).unwrap();

    let deposits_path = Path::new(output_dir).join(DEPOSITS_FILE);
    let deposits_file = File::create(deposits_path).unwrap();
    serde_yaml::to_writer(deposits_file, &deposits).unwrap();
}
