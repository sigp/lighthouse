mod cli;

use clap::ArgMatches;
use environment::RuntimeContext;
use rayon::prelude::*;
use slog::{crit, info};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use types::{ChainSpec, EthSpec};
use validator_client::validator_directory::{ValidatorDirectory, ValidatorDirectoryBuilder};

pub use cli::cli_app;

/// Run the account manager, logging an error if the operation did not succeed.
pub fn run<T: EthSpec>(matches: &ArgMatches, context: RuntimeContext<T>) {
    let log = context.log.clone();
    match run_account_manager(matches, context) {
        Ok(()) => (),
        Err(e) => crit!(log, "Account manager failed"; "error" => e),
    }
}

/// Run the account manager, returning an error if the operation did not succeed.
fn run_account_manager<T: EthSpec>(
    matches: &ArgMatches,
    context: RuntimeContext<T>,
) -> Result<(), String> {
    let log = context.log.clone();

    let datadir = matches
        .value_of("datadir")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            let mut default_dir = match dirs::home_dir() {
                Some(v) => v,
                None => {
                    panic!("Failed to find a home directory");
                }
            };
            default_dir.push(".lighthouse");
            default_dir.push("validators");
            default_dir
        });

    fs::create_dir_all(&datadir).map_err(|e| format!("Failed to initialize datadir: {}", e))?;

    info!(
        log,
        "Located data directory";
        "path" => format!("{:?}", datadir)
    );

    match matches.subcommand() {
        ("validator", Some(matches)) => match matches.subcommand() {
            ("new", Some(matches)) => run_new_validator_subcommand(matches, datadir, context)?,
            _ => {
                return Err("Invalid 'validator new' command. See --help.".to_string());
            }
        },
        _ => {
            return Err("Invalid 'validator' command. See --help.".to_string());
        }
    }

    Ok(())
}

/// Describes the crypto key generation methods for a validator.
enum KeygenMethod {
    /// Produce an insecure "deterministic" keypair. Used only for interop and testing.
    Insecure(usize),
    /// Generate a new key from the `rand` thread random RNG.
    ThreadRandom,
}

/// Process the subcommand for creating new validators.
fn run_new_validator_subcommand<T: EthSpec>(
    matches: &ArgMatches,
    datadir: PathBuf,
    context: RuntimeContext<T>,
) -> Result<(), String> {
    let log = context.log.clone();

    let methods: Vec<KeygenMethod> = match matches.subcommand() {
        ("insecure", Some(matches)) => {
            let first = matches
                .value_of("first")
                .ok_or_else(|| "No first index".to_string())?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse first index: {}", e))?;
            let last = matches
                .value_of("last")
                .ok_or_else(|| "No last index".to_string())?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse first index: {}", e))?;

            (first..last).map(KeygenMethod::Insecure).collect()
        }
        ("random", Some(matches)) => {
            let count = matches
                .value_of("validator_count")
                .ok_or_else(|| "No validator count".to_string())?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse validator count: {}", e))?;

            (0..count).map(|_| KeygenMethod::ThreadRandom).collect()
        }
        _ => {
            return Err("Invalid 'validator' command. See --help.".to_string());
        }
    };

    let validators = make_validators(datadir.clone(), &methods, context.eth2_config.spec)?;

    info!(
        log,
        "Generated validator directories";
        "base_path" => format!("{:?}", datadir),
        "count" => validators.len(),
    );

    Ok(())
}

/// Produces a validator directory for each of the key generation methods provided in `methods`.
fn make_validators(
    datadir: PathBuf,
    methods: &[KeygenMethod],
    spec: ChainSpec,
) -> Result<Vec<ValidatorDirectory>, String> {
    methods
        .par_iter()
        .map(|method| {
            let mut builder = ValidatorDirectoryBuilder::default()
                .spec(spec.clone())
                .full_deposit_amount()?;

            builder = match method {
                KeygenMethod::Insecure(index) => builder.insecure_keypairs(*index),
                KeygenMethod::ThreadRandom => builder.thread_random_keypairs(),
            };

            builder
                .create_directory(datadir.clone())?
                .write_keypair_files()?
                .write_eth1_data_file()?
                .build()
        })
        .collect()
}

/// Generate and store validator and withdrawal keystores.
fn generate_deposit_keystores(log: &slog::Logger) {
    // Get password from user
    // TODO: fix the order of log and print
    print!("Enter password: ");
    std::io::stdout().flush().unwrap();
    let password = read_password().expect("Unable to read password");

    // Generate keypairs
    let validator_keypair = Keypair::random();
    let withdrawal_keypair = Keypair::random();

    // Note: Validator and withdrawal keystores have same uuid
    let validator_keystore =
        Keystore::to_keystore(&validator_keypair, password.clone(), None, None, None);
    let withdrawal_keystore = Keystore::to_keystore(
        &withdrawal_keypair,
        password,
        None,
        None,
        Some(validator_keystore.uuid),
    );
    debug!(log, "Saving keys in keystores");
    save_keystore(&validator_keystore, KeyType::Voting, log);
    save_keystore(&withdrawal_keystore, KeyType::Withdrawal, log);
}

fn save_keystore(keystore: &Keystore, key_type: KeyType, log: &slog::Logger) {
    let key_path: PathBuf = keystore
        .save_keystore(PathBuf::from(DEFAULT_DATA_DIR), key_type)
        .unwrap();
    debug!(
        log,
        "Keystore file generated ,saved to: {:?}",
        key_path.to_string_lossy()
    );
}
