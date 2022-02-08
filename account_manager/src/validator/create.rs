use crate::common::read_wallet_name_from_cli;
use crate::validator::cli::Create;
use crate::WALLETS_DIR_FLAG;
use account_utils::{
    random_password, read_password_from_user, strip_off_newlines, validator_definitions, PlainText,
};
use clap_utils::GlobalConfig;
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

pub fn cli_run<T: EthSpec>(
    create_config: &Create,
    global_config: &GlobalConfig,
    mut env: Environment<T>,
    validator_dir: PathBuf,
) -> Result<(), String> {
    let spec = env.core_context().eth2_config.spec;

    let name: Option<String> = create_config.wallet_name.clone();
    let stdin_inputs = cfg!(windows) || create_config.stdin_inputs;

    let wallet_base_dir = if let Some(datadir) = global_config.datadir.as_ref() {
        datadir.join(DEFAULT_WALLET_DIR)
    } else {
        parse_path_or_default_with_flag(
            create_config.wallets_dir.clone(),
            global_config,
            DEFAULT_WALLET_DIR,
        )?
    };
    let secrets_dir = if let Some(datadir) = global_config.datadir.as_ref() {
        datadir.join(DEFAULT_WALLET_DIR)
    } else {
        parse_path_or_default_with_flag(
            create_config.secrets_dir.clone(),
            global_config,
            DEFAULT_SECRET_DIR,
        )?
    };

    let deposit_gwei = create_config
        .deposit_gwei
        .unwrap_or(spec.max_effective_balance);
    let count: Option<usize> = create_config.count;
    let at_most: Option<usize> = create_config.at_most;

    // The command will always fail if the wallet dir does not exist.
    if !wallet_base_dir.exists() {
        return Err(format!(
            "No wallet directory at {:?}. Use the `lighthouse --network {} {} {} {}` command to create a wallet",
            wallet_base_dir,
            global_config.network.as_ref().unwrap_or(&"<NETWORK>".to_string()),
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

    let wallet_password_path: Option<PathBuf> = create_config.wallet_password.clone();

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
