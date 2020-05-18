//! This command allows migrating from the old method of storing keys (unencrypted SSZ) to the
//! current method of using encrypted EIP-2335 keystores.
//!
//! This command should be completely removed once the `unencrypted_keys` feature is removed from
//! the `validator_dir` command. This should hopefully be in mid-June 2020.
//!
//! ## Example
//!
//! This command will upgrade all keypairs in the `--validators-dir`, storing the newly-generated
//! passwords in `--secrets-dir`.
//!
//! ```ignore
//! lighthouse am upgrade-legacy-keypairs \
//!     --validators-dir ~/.lighthouse/validators \
//!     --secrets-dir ~/.lighthouse/secrets
//! ```

use crate::{SECRETS_DIR_FLAG, VALIDATOR_DIR_FLAG};
use clap::{App, Arg, ArgMatches};
use clap_utils::parse_required;
use eth2_keystore::KeystoreBuilder;
use rand::{distributions::Alphanumeric, Rng};
use std::fs::{create_dir_all, read_dir, write, File};
use std::path::{Path, PathBuf};
use types::Keypair;
use validator_dir::{
    unencrypted_keys::load_unencrypted_keypair, VOTING_KEYSTORE_FILE, WITHDRAWAL_KEYSTORE_FILE,
};

pub const CMD: &str = "upgrade-legacy-keypairs";
pub const VOTING_KEYPAIR_FILE: &str = "voting_keypair";
pub const WITHDRAWAL_KEYPAIR_FILE: &str = "withdrawal_keypair";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about(
            "Converts legacy unencrypted SSZ keypairs into encrypted keystores.",
        )
        .arg(
            Arg::with_name(VALIDATOR_DIR_FLAG)
                .long(VALIDATOR_DIR_FLAG)
                .value_name("VALIDATORS_DIRECTORY")
                .takes_value(true)
                .required(true)
                .help("The directory containing legacy validators. Generally ~/.lighthouse/validators"),
        )
        .arg(
            Arg::with_name(SECRETS_DIR_FLAG)
                .long(SECRETS_DIR_FLAG)
                .value_name("SECRETS_DIRECTORY")
                .takes_value(true)
                .required(true)
                .help("The directory where keystore passwords will be stored. Generally ~/.lighthouse/secrets"),
        )
}

pub fn cli_run(matches: &ArgMatches) -> Result<(), String> {
    let validators_dir: PathBuf = parse_required(matches, VALIDATOR_DIR_FLAG)?;
    let secrets_dir: PathBuf = parse_required(matches, SECRETS_DIR_FLAG)?;

    if !secrets_dir.exists() {
        create_dir_all(&secrets_dir)
            .map_err(|e| format!("Failed to create secrets dir {:?}: {:?}", secrets_dir, e))?;
    }

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
                if let Err(e) = upgrade_keypair(
                    &path,
                    &secrets_dir,
                    VOTING_KEYPAIR_FILE,
                    VOTING_KEYSTORE_FILE,
                ) {
                    println!("Validator {:?}: {:?}", path, e);
                } else {
                    println!("Validator {:?} voting keys: success", path);
                }

                if let Err(e) = upgrade_keypair(
                    &path,
                    &secrets_dir,
                    WITHDRAWAL_KEYPAIR_FILE,
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
