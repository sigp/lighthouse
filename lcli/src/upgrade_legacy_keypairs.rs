use clap::ArgMatches;
use clap_utils::parse_required;
use eth2_keystore::KeystoreBuilder;
use rand::{distributions::Alphanumeric, Rng};
use std::fs::{read_dir, write, File};
use std::path::{Path, PathBuf};
use types::{EthSpec, Keypair};
use validator_dir::{
    unencrypted_keys::load_unencrypted_keypair, VOTING_KEYSTORE_FILE, WITHDRAWAL_KEYSTORE_FILE,
};

pub fn run<T: EthSpec>(matches: &ArgMatches) -> Result<(), String> {
    let validators_dir: PathBuf = parse_required(matches, "validators-dir")?;
    let secrets_dir: PathBuf = parse_required(matches, "secrets-dir")?;

    read_dir(&validators_dir)
        .map_err(|e| {
            format!(
                "Failed to read validators directory {:?}: {:?}",
                validators_dir, e
            )
        })?
        .try_for_each(|dir| {
            let path = dir
                .map_err(|e| format!("Unable to read dir: {}", e))?
                .path();

            if path.is_dir() {
                if let Err(e) =
                    upgrade_keypair(&path, &secrets_dir, "voting_keypair", VOTING_KEYSTORE_FILE)
                {
                    println!("Validator {:?}: {:?}", path, e);
                } else {
                    println!("Validator {:?} voting keys: success", path);
                }

                if let Err(e) = upgrade_keypair(
                    &path,
                    &secrets_dir,
                    "withdrawal_keypair",
                    WITHDRAWAL_KEYSTORE_FILE,
                ) {
                    println!("Validator {:?}: {:?}", path, e);
                } else {
                    println!("Validator {:?} withdrawal keys: success", path);
                }
            }

            Ok(())
        })
}

fn upgrade_keypair<P: AsRef<Path>>(
    validator_dir: P,
    secrets_dir: P,
    input_filename: &str,
    output_filename: &str,
) -> Result<(), String> {
    let validator_dir = validator_dir.as_ref();
    let secrets_dir = secrets_dir.as_ref();

    let keypair: Keypair = load_unencrypted_keypair(validator_dir.join(input_filename))?.into();

    let password = rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .collect::<String>()
        .into_bytes();

    let keystore = KeystoreBuilder::new(&keypair, &password, "".into())
        .map_err(|e| format!("Unable to create keystore builder: {:?}", e))?
        .build()
        .map_err(|e| format!("Unable to build keystore: {:?}", e))?;

    let keystore_path = validator_dir.join(output_filename);

    if keystore_path.exists() {
        return Err(format!("{:?} already exists", keystore_path));
    }

    let mut file = File::create(&keystore_path).map_err(|e| format!("Cannot create: {:?}", e))?;
    keystore
        .to_json_writer(&mut file)
        .map_err(|e| format!("Cannot write keystore to {:?}: {:?}", keystore_path, e))?;

    let password_path = secrets_dir.join(format!("{}", keypair.pk.as_hex_string()));

    if password_path.exists() {
        return Err(format!("{:?} already exists", password_path));
    }

    write(&password_path, &password)
        .map_err(|e| format!("Unable to write password to {:?}: {:?}", password_path, e))?;

    Ok(())
}
