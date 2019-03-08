use log::debug;
use serde_yaml;
use std::fs::File;
use std::path::Path;
use types::*;

pub fn load_deposits_from_file(
    validator_count: usize,
    keypairs_path: &Path,
    deposits_path: &Path,
) -> (Vec<Keypair>, Vec<Deposit>) {
    debug!("Loading keypairs from file...");
    let keypairs_file = File::open(keypairs_path).unwrap();
    let mut keypairs: Vec<Keypair> = serde_yaml::from_reader(&keypairs_file).unwrap();

    debug!("Loading deposits from file...");
    let deposits_file = File::open(deposits_path).unwrap();
    let mut deposits: Vec<Deposit> = serde_yaml::from_reader(&deposits_file).unwrap();

    assert!(
        keypairs.len() >= validator_count,
        "Unable to load {} keypairs from file ({} available)",
        validator_count,
        keypairs.len()
    );

    assert!(
        deposits.len() >= validator_count,
        "Unable to load {} deposits from file ({} available)",
        validator_count,
        deposits.len()
    );

    keypairs.truncate(validator_count);
    deposits.truncate(validator_count);

    (keypairs, deposits)
}
