use crate::common::read_wallet_name_from_cli;
use crate::wallet::create::MNEMONIC_TYPES;
use crate::WALLETS_DIR_FLAG;
use account_utils::{
    random_password, read_password_from_user, strip_off_newlines, validator_definitions, PlainText,
    STDIN_INPUTS_FLAG,
};
use clap::ArgMatches;
use directory::{ensure_dir_exists, DEFAULT_SECRET_DIR, DEFAULT_WALLET_DIR};
use environment::Environment;
use eth2_wallet::bip39::MnemonicType;
use eth2_wallet_manager::WalletManager;
use slashing_protection::{SlashingDatabase, SLASHING_PROTECTION_FILENAME};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use types::EthSpec;
use validator_dir::Builder as ValidatorDirBuilder;

use super::cli::Create;

pub const COUNT_FLAG: &str = "count";
pub const AT_MOST_FLAG: &str = "at-most";
pub const WALLET_PASSWORD_PROMPT: &str = "Enter your wallet's password:";

pub fn cli_run<E: EthSpec>(
    create_config: &Create,
    matches: &ArgMatches,
    env: Environment<E>,
    validator_dir: PathBuf,
) -> Result<(), String> {
    let spec = env.core_context().eth2_config.spec;

    let name: Option<String> = create_config.wallet_name.clone();
    let stdin_inputs = cfg!(windows) || matches.get_flag(STDIN_INPUTS_FLAG);

    let wallet_base_dir = if matches.get_one::<String>("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_WALLET_DIR)
    } else {
        create_config
            .wallets_dir
            .clone()
            .unwrap_or(PathBuf::from(DEFAULT_WALLET_DIR))
    };
    let secrets_dir = if matches.get_one::<String>("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_SECRET_DIR)
    } else {
        create_config
            .secrets_dir
            .clone()
            .unwrap_or(PathBuf::from(DEFAULT_SECRET_DIR))
    };

    let deposit_gwei = create_config
        .deposit_gwei
        .unwrap_or(spec.max_effective_balance);
    let count = create_config.count;
    let at_most = create_config.at_most;

    // The command will always fail if the wallet dir does not exist.
    if !wallet_base_dir.exists() {
        return Err(format!(
            "No wallet directory at {:?}. Use the `lighthouse --network {} {} {} {}` command to create a wallet",
            wallet_base_dir,
            matches.get_one::<String>("network").unwrap_or(&String::from("<NETWORK>")),
            crate::CMD,
            crate::wallet::CMD,
            crate::wallet::create::CMD
        ));
    }

    ensure_dir_exists(&validator_dir)?;
    ensure_dir_exists(&secrets_dir)?;

    eprintln!("secrets-dir path {:?}", secrets_dir);
    eprintln!("wallets-dir path {:?}", wallet_base_dir);

    let starting_validator_count = existing_validator_count(&validator_dir)?;

    let n = match (count, at_most) {
        (Some(_), Some(_)) => Err(format!(
            "Cannot supply --{} and --{}",
            COUNT_FLAG, AT_MOST_FLAG
        )),
        (None, None) => Err(format!(
            "Must supply either --{} or --{}",
            COUNT_FLAG, AT_MOST_FLAG
        )),
        (Some(count), None) => Ok(count),
        (None, Some(at_most)) => Ok(at_most.saturating_sub(starting_validator_count)),
    }?;

    if n == 0 {
        eprintln!(
            "No validators to create. {}={:?}, {}={:?}",
            COUNT_FLAG, count, AT_MOST_FLAG, at_most
        );
        return Ok(());
    }

    let wallet_password_path = create_config.wallet_password.clone();

    let wallet_name = read_wallet_name_from_cli(name, stdin_inputs)?;
    let wallet_password = read_wallet_password_from_cli(wallet_password_path, stdin_inputs)?;

    let mgr = WalletManager::open(&wallet_base_dir)
        .map_err(|e| format!("Unable to open --{}: {:?}", WALLETS_DIR_FLAG, e))?;

    let mut wallet = mgr
        .wallet_by_name(&wallet_name)
        .map_err(|e| format!("Unable to open wallet: {:?}", e))?;

    let slashing_protection_path = validator_dir.join(SLASHING_PROTECTION_FILENAME);
    let slashing_protection =
        SlashingDatabase::open_or_create(&slashing_protection_path).map_err(|e| {
            format!(
                "Unable to open or create slashing protection database at {}: {:?}",
                slashing_protection_path.display(),
                e
            )
        })?;

    // Create an empty transaction and drops it. Used to test if the database is locked.
    slashing_protection.test_transaction().map_err(|e| {
        format!(
            "Cannot create keys while the validator client is running: {:?}",
            e
        )
    })?;

    for i in 0..n {
        let voting_password = random_password();
        let withdrawal_password = random_password();

        let keystores = wallet
            .next_validator(
                wallet_password.as_bytes(),
                voting_password.as_bytes(),
                withdrawal_password.as_bytes(),
            )
            .map_err(|e| format!("Unable to create validator keys: {:?}", e))?;

        let voting_pubkey = keystores.voting.public_key().ok_or_else(|| {
            format!(
                "Keystore public key is invalid: {}",
                keystores.voting.pubkey()
            )
        })?;

        slashing_protection
            .register_validator(voting_pubkey.compress())
            .map_err(|e| {
                format!(
                    "Error registering validator {}: {:?}",
                    voting_pubkey.as_hex_string(),
                    e
                )
            })?;

        ValidatorDirBuilder::new(validator_dir.clone())
            .password_dir(secrets_dir.clone())
            .voting_keystore(keystores.voting, voting_password.as_bytes())
            .withdrawal_keystore(keystores.withdrawal, withdrawal_password.as_bytes())
            .create_eth1_tx_data(deposit_gwei, &spec)
            .store_withdrawal_keystore(create_config.store_withdrawal_keystore)
            .build()
            .map_err(|e| format!("Unable to build validator directory: {:?}", e))?;

        println!("{}/{}\t{}", i + 1, n, voting_pubkey.as_hex_string());
    }

    Ok(())
}

/// Returns the number of validators that exist in the given `validator_dir`.
///
/// This function just assumes all files and directories, excluding the validator definitions YAML
/// and slashing protection database are validator directories, making it likely to return a higher
/// number than accurate but never a lower one.
fn existing_validator_count<P: AsRef<Path>>(validator_dir: P) -> Result<usize, String> {
    fs::read_dir(validator_dir.as_ref())
        .map(|iter| {
            iter.filter_map(|e| e.ok())
                .filter(|e| {
                    e.file_name() != OsStr::new(validator_definitions::CONFIG_FILENAME)
                        && e.file_name()
                            != OsStr::new(slashing_protection::SLASHING_PROTECTION_FILENAME)
                })
                .count()
        })
        .map_err(|e| format!("Unable to read {:?}: {}", validator_dir.as_ref(), e))
}

/// Used when a user is accessing an existing wallet. Read in a wallet password from a file if the password file
/// path is provided. Otherwise, read from an interactive prompt using tty unless the `--stdin-inputs`
/// flag is provided.
pub fn read_wallet_password_from_cli(
    password_file_path: Option<PathBuf>,
    stdin_inputs: bool,
) -> Result<PlainText, String> {
    match password_file_path {
        Some(path) => fs::read(&path)
            .map_err(|e| format!("Unable to read {:?}: {:?}", path, e))
            .map(|bytes| strip_off_newlines(bytes).into()),
        None => {
            eprintln!();
            eprintln!("{}", WALLET_PASSWORD_PROMPT);
            let password =
                PlainText::from(read_password_from_user(stdin_inputs)?.as_ref().to_vec());
            Ok(password)
        }
    }
}

pub fn validate_mnemonic_length(len: &str) -> Result<(), String> {
    match len
        .parse::<usize>()
        .ok()
        .and_then(|words| MnemonicType::for_word_count(words).ok())
    {
        Some(_) => Ok(()),
        None => Err(format!(
            "Mnemonic length must be one of {}",
            MNEMONIC_TYPES
                .iter()
                .map(|t| t.word_count().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}
