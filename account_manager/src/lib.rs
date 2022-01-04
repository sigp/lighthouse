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
pub const WALLETS_DIR_FLAG: &str = "wallets-dir";

pub fn cli_app<'a>() -> App<'a> {
    App::new(CMD)
        .visible_aliases(&["a", "am", "account", CMD])
        .help("Utilities for generating and managing Ethereum 2.0 accounts.")
        .subcommand(wallet::cli_app())
        .subcommand(validator::cli_app())
}

/// Run the account manager, returning an error if the operation did not succeed.
pub fn run<T: EthSpec>(matches: &ArgMatches, env: Environment<T>) -> Result<(), String> {
    match matches.subcommand() {
        Some((wallet::CMD, matches)) => wallet::cli_run(matches)?,
        Some((validator::CMD, matches)) => validator::cli_run(matches, env)?,
        Some((unknown, _)) => {
            return Err(format!(
                "{} is not a valid {} command. See --help.",
                unknown, CMD
            ));
        }
        None => return Err(format!("{} does not have a subcommand. See --help", CMD)),
    }

    Ok(())
}
