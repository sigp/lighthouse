use clap::ArgMatches;
use std::fs;
use std::path::PathBuf;
use validator_dir::Builder as ValidatorBuilder;

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

    for i in 0..validator_count {
        println!("Validator {}/{}", i + 1, validator_count);

        ValidatorBuilder::new(validators_dir.clone())
            .password_dir(secrets_dir.clone())
            .store_withdrawal_keystore(false)
            .insecure_voting_keypair(i)
            .map_err(|e| format!("Unable to generate keys: {:?}", e))?
            .build()
            .map_err(|e| format!("Unable to build validator: {:?}", e))?;
    }

    Ok(())
}
