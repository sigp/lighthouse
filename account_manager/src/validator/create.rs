use crate::common::read_wallet_name_from_cli;
use crate::wallet::create::STDIN_INPUTS_FLAG;
use crate::{SECRETS_DIR_FLAG, WALLETS_DIR_FLAG};
use account_utils::{
    random_password, read_password_from_user, strip_off_newlines, validator_definitions, PlainText,
};
use clap::{App, Arg, ArgMatches};
use directory::{
    ensure_dir_exists, parse_path_or_default_with_flag, DEFAULT_SECRET_DIR, DEFAULT_WALLET_DIR,
};
use environment::Environment;
use eth2_wallet_manager::WalletManager;
use slashing_protection::{SlashingDatabase, SLASHING_PROTECTION_FILENAME};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use types::EthSpec;
use validator_dir::Builder as ValidatorDirBuilder;

pub const CMD: &str = "create";
pub const WALLET_NAME_FLAG: &str = "wallet-name";
pub const WALLET_PASSWORD_FLAG: &str = "wallet-password";
pub const DEPOSIT_GWEI_FLAG: &str = "deposit-gwei";
pub const STORE_WITHDRAW_FLAG: &str = "store-withdrawal-keystore";
pub const COUNT_FLAG: &str = "count";
pub const AT_MOST_FLAG: &str = "at-most";
pub const WALLET_PASSWORD_PROMPT: &str = "Enter your wallet's password:";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about(
            "Creates new validators from an existing EIP-2386 wallet using the EIP-2333 HD key \
            derivation scheme.",
        )
        .arg(
            Arg::with_name(WALLET_NAME_FLAG)
                .long(WALLET_NAME_FLAG)
                .value_name("WALLET_NAME")
                .help("Use the wallet identified by this name")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(WALLET_PASSWORD_FLAG)
                .long(WALLET_PASSWORD_FLAG)
                .value_name("WALLET_PASSWORD_PATH")
                .help("A path to a file containing the password which will unlock the wallet.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(WALLETS_DIR_FLAG)
                .long(WALLETS_DIR_FLAG)
                .value_name(WALLETS_DIR_FLAG)
                .help("A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/{network}/wallets")
                .takes_value(true)
                .conflicts_with("datadir"),
        )
        .arg(
            Arg::with_name(SECRETS_DIR_FLAG)
                .long(SECRETS_DIR_FLAG)
                .value_name("SECRETS_DIR")
                .help(
                    "The path where the validator keystore passwords will be stored. \
                    Defaults to ~/.lighthouse/{network}/secrets",
                )
                .conflicts_with("datadir")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(DEPOSIT_GWEI_FLAG)
                .long(DEPOSIT_GWEI_FLAG)
                .value_name("DEPOSIT_GWEI")
                .help(
                    "The GWEI value of the deposit amount. Defaults to the minimum amount \
                    required for an active validator (MAX_EFFECTIVE_BALANCE)",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name(STORE_WITHDRAW_FLAG)
                .long(STORE_WITHDRAW_FLAG)
                .help(
                    "If present, the withdrawal keystore will be stored alongside the voting \
                    keypair. It is generally recommended to *not* store the withdrawal key and \
                    instead generate them from the wallet seed when required.",
                ),
        )
        .arg(
            Arg::with_name(COUNT_FLAG)
                .long(COUNT_FLAG)
                .value_name("VALIDATOR_COUNT")
                .help("The number of validators to create, regardless of how many already exist")
                .conflicts_with("at-most")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(AT_MOST_FLAG)
                .long(AT_MOST_FLAG)
                .value_name("AT_MOST_VALIDATORS")
                .help(
                    "Observe the number of validators in --validator-dir, only creating enough to \
                    reach the given count. Never deletes an existing validator.",
                )
                .conflicts_with("count")
                .takes_value(true),
        )
        .arg(
            Arg::with_name(STDIN_INPUTS_FLAG)
                .takes_value(false)
                .hidden(cfg!(windows))
                .long(STDIN_INPUTS_FLAG)
                .help("If present, read all user inputs from stdin instead of tty."),
        )
}

pub fn cli_run<T: EthSpec>(
    matches: &ArgMatches,
    mut env: Environment<T>,
    validator_dir: PathBuf,
) -> Result<(), String> {
    let spec = env.core_context().eth2_config.spec;

    let name: Option<String> = clap_utils::parse_optional(matches, WALLET_NAME_FLAG)?;
    let stdin_inputs = cfg!(windows) || matches.is_present(STDIN_INPUTS_FLAG);

    let wallet_base_dir = if matches.value_of("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_WALLET_DIR)
    } else {
        parse_path_or_default_with_flag(matches, WALLETS_DIR_FLAG, DEFAULT_WALLET_DIR)?
    };
    let secrets_dir = if matches.value_of("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_SECRET_DIR)
    } else {
        parse_path_or_default_with_flag(matches, SECRETS_DIR_FLAG, DEFAULT_SECRET_DIR)?
    };

    let deposit_gwei = clap_utils::parse_optional(matches, DEPOSIT_GWEI_FLAG)?
        .unwrap_or(spec.max_effective_balance);
    let count: Option<usize> = clap_utils::parse_optional(matches, COUNT_FLAG)?;
    let at_most: Option<usize> = clap_utils::parse_optional(matches, AT_MOST_FLAG)?;

    // The command will always fail if the wallet dir does not exist.
    if !wallet_base_dir.exists() {
        return Err(format!(
            "No wallet directory at {:?}. Use the `lighthouse --network {} {} {} {}` command to create a wallet",
            wallet_base_dir,
            matches.value_of("network").unwrap_or("<NETWORK>"),
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

    let wallet_password_path: Option<PathBuf> =
        clap_utils::parse_optional(matches, WALLET_PASSWORD_FLAG)?;

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
                    voting_pubkey.to_hex_string(),
                    e
                )
            })?;

        ValidatorDirBuilder::new(validator_dir.clone())
            .password_dir(secrets_dir.clone())
            .voting_keystore(keystores.voting, voting_password.as_bytes())
            .withdrawal_keystore(keystores.withdrawal, withdrawal_password.as_bytes())
            .create_eth1_tx_data(deposit_gwei, &spec)
            .store_withdrawal_keystore(matches.is_present(STORE_WITHDRAW_FLAG))
            .build()
            .map_err(|e| format!("Unable to build validator directory: {:?}", e))?;

        println!("{}/{}\t{}", i + 1, n, voting_pubkey.to_hex_string());
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
