mod common;
pub mod validator;
pub mod wallet;

use clap::App;
use clap::ArgMatches;
use environment::Environment;
use types::EthSpec;

pub const CMD: &str = "account_manager";
pub const SECRETS_DIR_FLAG: &str = "secrets-dir";
pub const VALIDATOR_DIR_FLAG: &str = "validator-dir";
pub const VALIDATOR_DIR_FLAG_ALIAS: &str = "validators-dir";
pub const WALLETS_DIR_FLAG: &str = "wallets-dir";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .visible_aliases(&["a", "am", "account", CMD])
        .about("Utilities for generating and managing Ethereum 2.0 accounts.")
        .subcommand(wallet::cli_app())
        .subcommand(validator::cli_app())
}

/// Run the account manager, returning an error if the operation did not succeed.
pub fn run<T: EthSpec>(matches: &ArgMatches<'_>, env: Environment<T>) -> Result<(), String> {
    match matches.subcommand() {
        (wallet::CMD, Some(matches)) => wallet::cli_run(matches)?,
        (validator::CMD, Some(matches)) => validator::cli_run(matches, env)?,
        (unknown, _) => {
            return Err(format!(
                "{} is not a valid {} command. See --help.",
                unknown, CMD
            ));
        }
    }

    Ok(())
}
