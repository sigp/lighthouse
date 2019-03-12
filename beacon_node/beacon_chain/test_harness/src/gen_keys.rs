use clap::{value_t, ArgMatches};
use log::debug;
use std::path::Path;
use types::test_utils::{generate_deterministic_keypairs, KeypairsFile};

pub fn gen_keys(matches: &ArgMatches) {
    let validator_count = value_t!(matches.value_of("validator_count"), usize)
        .expect("Validator count is required argument");
    let output_file = matches
        .value_of("output_file")
        .expect("Output file has a default value.");

    let keypairs = generate_deterministic_keypairs(validator_count);

    debug!("Writing keypairs to file...");

    let keypairs_path = Path::new(output_file);

    keypairs.to_raw_file(&keypairs_path, &keypairs).unwrap();
}
