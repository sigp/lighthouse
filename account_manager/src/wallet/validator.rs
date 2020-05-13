use super::{ensure_dir_exists, random_password};
use clap::{App, Arg, ArgMatches};
use environment::Environment;
use eth2_wallet::PlainText;
use eth2_wallet_manager::WalletManager;
use slog::info;
use std::fs;
use std::path::{Path, PathBuf};
use types::EthSpec;
use validator_dir::Builder as ValidatorDirBuilder;

pub const CMD: &str = "validator";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Creates new validators from an existing wallet located in --base-dir.")
        .arg(
            Arg::with_name("name")
                .long("name")
                .value_name("WALLET_NAME")
                .help("Use the wallet identified by this name")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("wallet-password")
                .long("wallet-passphrase")
                .value_name("WALLET_PASSWORD_PATH")
                .help("A path to a file containing the password which will unlock the wallet.")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("validator-dir")
                .long("validator-dir")
                .value_name("VALIDATOR_DIRECTORY")
                .help(
                    "The path where the validator directories will be created. \
                            Defaults to ~/.lighthouse/validators",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("secrets-dir")
                .long("secrets-dir")
                .value_name("SECRETS_DIR")
                .help(
                    "The path where the validator keystore passwords will be stored. \
                            Defaults to ~/.lighthouse/secrets",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("deposit-gwei")
                .long("deposit-gwei")
                .value_name("DEPOSIT_GWEI")
                .help(
                    "The GWEI value of the deposit amount. Defaults to the minimum amount
                            required for an active validator (MAX_EFFECTIVE_BALANCE)",
                )
                .takes_value(true),
        )
        .arg(
            Arg::with_name("store-withdrawal-keystore")
                .long("store-withdrawal-keystore")
                .value_name("SHOULD_STORE_WITHDRAWAL_KEYSTORE")
                .help(
                    "If present, the withdrawal keystore will be stored alongside the voting \
                    keypair. It is generally recommended to not store the withdrawal key and \
                    instead generated them from the wallet seed when required, after phase 0.",
                ),
        )
        .arg(
            Arg::with_name("count")
                .long("count")
                .value_name("VALIDATOR_COUNT")
                .help("The number of validators to create, regardless of how many already exist")
                .conflicts_with("at-most")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("at-most")
                .long("at-most")
                .value_name("AT_MOST_VALIDATORS")
                .help(
                    "Observe the number of validators in --validator-dir, only creating enough to
                        ensure reach the given count. Never deletes an existing validator.",
                )
                .conflicts_with("count")
                .takes_value(true),
        )
}

pub fn cli_run<T: EthSpec>(
    matches: &ArgMatches,
    mut env: Environment<T>,
    wallet_base_dir: PathBuf,
) -> Result<(), String> {
    let spec = env.core_context().eth2_config.spec;
    let log = env.core_context().log;

    let name: String = clap_utils::parse_required(matches, "name")?;
    let wallet_password_path: PathBuf = clap_utils::parse_required(matches, "wallet-password")?;
    let validator_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        "validator-dir",
        PathBuf::new().join(".lighthouse").join("validators"),
    )?;
    let secrets_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        "secrets-dir",
        PathBuf::new().join(".lighthouse").join("secrets"),
    )?;
    let deposit_gwei = clap_utils::parse_optional(matches, "deposit-gwei")?
        .unwrap_or_else(|| spec.max_effective_balance);
    let count: Option<usize> = clap_utils::parse_optional(matches, "count")?;
    let at_most: Option<usize> = clap_utils::parse_optional(matches, "at-most")?;

    ensure_dir_exists(&validator_dir)?;
    ensure_dir_exists(&secrets_dir)?;

    let starting_validator_count = existing_validator_count(&validator_dir)?;

    let n = match (count, at_most) {
        (Some(_), Some(_)) => Err("Cannot supply --count and --at-most".to_string()),
        (None, None) => Err("Must supply either --count or --at-most".to_string()),
        (Some(count), None) => Ok(count),
        (None, Some(at_most)) => Ok(at_most.saturating_sub(starting_validator_count)),
    }?;

    if n == 0 {
        info!(
            log,
            "No need to produce and validators, exiting";
            "--count" => count,
            "--at-most" => at_most,
            "existing_validators" => starting_validator_count,
        );
        return Ok(());
    }

    let wallet_password = fs::read(&wallet_password_path)
        .map_err(|e| format!("Unable to read {:?}: {:?}", wallet_password_path, e))
        .map(|bytes| PlainText::from(bytes))?;

    let mgr = WalletManager::open(&wallet_base_dir)
        .map_err(|e| format!("Unable to open --base-dir: {:?}", e))?;

    let mut wallet = mgr
        .wallet_by_name(&name)
        .map_err(|e| format!("Unable to open wallet: {:?}", e))?;

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

        ValidatorDirBuilder::new(validator_dir.clone(), secrets_dir.clone())
            .voting_keystore(keystores.voting, voting_password.as_bytes())
            .withdrawal_keystore(keystores.withdrawal, withdrawal_password.as_bytes())
            .create_eth1_tx_data(deposit_gwei, &spec)
            .store_withdrawal_keystore(matches.is_present("store-withdrawal-keystore"))
            .build()
            .map_err(|e| format!("Unable to build validator director: {:?}", e))?;

        info!(
            log,
            "Created validator";
            "progress" => format!("{} of {}", i + 1, n)
        );
    }

    Ok(())
}

/// Returns the number of validators that exist in the given `validator_dir`.
///
/// This function just assumes any file is a validator directory, making it likely to return a
/// higher number than accurate but never a lower one.
fn existing_validator_count<P: AsRef<Path>>(validator_dir: P) -> Result<usize, String> {
    fs::read_dir(validator_dir.as_ref())
        .map(|iter| iter.count())
        .map_err(|e| format!("Unable to read {:?}: {}", validator_dir.as_ref(), e))
}
