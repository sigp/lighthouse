use clap::ArgMatches;
use std::fs;
use std::path::PathBuf;
use validator_dir::{Builder as ValidatorBuilder, Manager as ValidatorManager};

pub fn run(matches: &ArgMatches) -> Result<(), String> {
    let validator_count: usize = clap_utils::parse_required(matches, "count")?;
    let validators_dir: PathBuf = clap_utils::parse_required(matches, "validators-dir")?;
    let secrets_dir: PathBuf = clap_utils::parse_required(matches, "secrets-dir")?;

    if !validators_dir.exists() {
        fs::create_dir_all(&validators_dir)
            .map_err(|e| format!("Unable to create validators dir: {:?}", e))?;
    }

    if !secrets_dir.exists() {
        fs::create_dir_all(&secrets_dir)
            .map_err(|e| format!("Unable to create secrets dir: {:?}", e))?;
    }

    let mgr = ValidatorManager::open(&validators_dir)
        .map_err(|e| format!("Unable to create validator manager: {:?}", e))?;

    let num_existing_validators = mgr
        .directory_names()
        .map_err(|e| format!("Unable to list existing validators: {:?}", e))?
        .len();

    let n = validator_count.saturating_sub(num_existing_validators);

    eprintln!(
        "Requested {} validators when {} already exist. Creating {}.",
        validator_count, num_existing_validators, n
    );

    // Second, write all the builders to file.
    //
    // Doing this part separate to the concurrent generation ensures that the validators are
    // written to disk in order. This gives more confidence when assuming that if there are `n`
    // validators in a directory then those are validators `0..n`, not some random assortment.
    for i in num_existing_validators..validator_count {
        println!("Validator {}/{}", i + 1, validator_count);

        ValidatorBuilder::new(validators_dir.clone(), secrets_dir.clone())
            .store_withdrawal_keystore(false)
            .insecure_voting_keypair(i)
            .map_err(|e| format!("Unable to generate keys: {:?}", e))?
            .build()
            .map_err(|e| format!("Unable to build validator: {:?}", e))?;
    }

    Ok(())
}
