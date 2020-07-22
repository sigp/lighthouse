use crate::{common::ensure_dir_exists, VALIDATOR_DIR_FLAG};
use account_utils::{
    eth2_keystore::Keystore,
    validator_definitions::{
        recursively_find_voting_keystores, ValidatorDefinitions, CONFIG_FILENAME,
    },
    ZeroizeString,
};
use clap::{App, Arg, ArgMatches};
use environment::Environment;
use std::io::{self, BufRead, Stdin};
use std::path::PathBuf;
use std::thread::sleep;
use std::time::Duration;
use types::EthSpec;

pub const CMD: &str = "import";
pub const KEYSTORE_FLAG: &str = "keystore";
pub const DIR_FLAG: &str = "directory";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about(
            "Reads existing EIP-2335 keystores and imports them into a Lighthouse \
            validator client.",
        )
        .arg(
            Arg::with_name(KEYSTORE_FLAG)
                .long(KEYSTORE_FLAG)
                .value_name("KEYSTORE_PATH")
                .help("Path to a single keystore to be imported.")
                .conflicts_with(DIR_FLAG)
                .required_unless(DIR_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(DIR_FLAG)
                .long(DIR_FLAG)
                .value_name("KEYSTORES_DIRECTORY")
                .help(
                    "Path to a directory which contains zero or more keystores \
                    for import. This directory and all sub-directories will be \
                    searched and any file name which contains 'keystore' and \
                    has the '.json' extension will be attempted to be imported.",
                )
                .conflicts_with(KEYSTORE_FLAG)
                .required_unless(KEYSTORE_FLAG)
                .takes_value(true),
        )
        .arg(
            Arg::with_name(VALIDATOR_DIR_FLAG)
                .long(VALIDATOR_DIR_FLAG)
                .value_name("VALIDATOR_DIRECTORY")
                .help(
                    "The path where the validator directories will be created. \
                    Defaults to ~/.lighthouse/validators",
                )
                .takes_value(true),
        )
}

pub fn cli_run(matches: &ArgMatches) -> Result<(), String> {
    let keystore: Option<PathBuf> = clap_utils::parse_optional(matches, KEYSTORE_FLAG)?;
    let keystores_dir: Option<PathBuf> = clap_utils::parse_optional(matches, DIR_FLAG)?;
    let validator_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        VALIDATOR_DIR_FLAG,
        PathBuf::new().join(".lighthouse").join("validators"),
    )?;
    let stdin = io::stdin();

    ensure_dir_exists(&validator_dir)?;

    let defs = ValidatorDefinitions::open_or_create(&validator_dir)
        .map_err(|e| format!("Unable to open {}: {:?}", CONFIG_FILENAME, e))?;

    let keystore_paths = match (keystore, keystores_dir) {
        (Some(keystore), None) => vec![keystore],
        (None, Some(keystores_dir)) => {
            let mut keystores = vec![];

            recursively_find_voting_keystores(&keystores_dir, &mut keystores)
                .map_err(|e| format!("Unable to search {:?}: {:?}", keystores_dir, e))?;

            if keystores.is_empty() {
                eprintln!("No keystores found in {:?}", keystores_dir);
                return Ok(());
            }

            keystores
        }
        _ => {
            return Err(format!(
                "Must supply either --{} or --{}",
                KEYSTORE_FLAG, DIR_FLAG
            ))
        }
    };

    for keystore_path in &keystore_paths {
        let keystore = Keystore::from_json_file(keystore_path)
            .map_err(|e| format!("Unable to read keystore JSON {:?}: {:?}", keystore_path, e))?;

        eprintln!("");
        eprintln!("Keystore found at {:?}:", keystore_path);
        eprintln!("");
        eprintln!(" - Description: {}", "TODO");
        eprintln!(" - Public key: 0x{}", keystore.pubkey());
        eprintln!(" - UUID: {}", keystore.uuid());
        eprintln!("");
        eprintln!("You may enter a password so the validator is decrypted automatically");
        eprintln!("whenever the validator client starts. Whilst this is favourable");
        eprintln!("for validator uptime, it means that the password to the keystore");
        eprintln!(
            "is saved on-disk in the {} file. If you choose not to enter a password",
            CONFIG_FILENAME
        );
        eprintln!("you will be prompted to enter the password each time the validator client");
        eprintln!("starts.");
        eprintln!("");
        eprintln!("Enter a password, or press enter to omit a password:");

        let password_opt = loop {
            let password = stdin
                .lock()
                .lines()
                .next()
                .ok_or_else(|| "Failed to read from stdin".to_string())?
                .map_err(|e| format!("Error reading from stdin: {}", e))
                .map(ZeroizeString::from)?;

            if password.as_ref().is_empty() {
                eprintln!("Continuing without password.");
                sleep(Duration::from_secs(1)); // Provides nicer UX.
                break None;
            }

            eprintln!("");

            match keystore.decrypt_keypair(password.as_ref()) {
                Ok(_) => {
                    eprintln!("Password is correct.");
                    sleep(Duration::from_secs(1)); // Provides nicer UX.
                    break Some(password);
                }
                Err(eth2_keystore::Error::InvalidPassword) => {
                    eprintln!("Invalid password, try again (or press Ctrl+c to exit):");
                }
                Err(e) => return Err(format!("Error whilst decrypting keypair: {:?}", e)),
            }
        };
    }

    Ok(())
}
