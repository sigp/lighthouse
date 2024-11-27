mod common;
pub mod validator;
pub mod wallet;

use clap::Arg;
use clap::ArgAction;
use clap::ArgMatches;
use clap::Command;
use clap_utils::FLAG_HEADER;
use environment::Environment;
use types::EthSpec;

pub const CMD: &str = "account_manager";
pub const SECRETS_DIR_FLAG: &str = "secrets-dir";
pub const VALIDATOR_DIR_FLAG: &str = "validator-dir";
pub const VALIDATOR_DIR_FLAG_ALIAS: &str = "validators-dir";
pub const WALLETS_DIR_FLAG: &str = "wallets-dir";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .visible_aliases(["a", "am", "account"])
        .about("Utilities for generating and managing Ethereum 2.0 accounts.")
        .display_order(0)
        .arg(
            Arg::new("help")
                .long("help")
                .short('h')
                .help("Prints help information")
                .action(ArgAction::HelpLong)
                .display_order(0)
                .help_heading(FLAG_HEADER),
        )
        .subcommand(wallet::cli_app())
        .subcommand(validator::cli_app())
}

/// Run the account manager, returning an error if the operation did not succeed.
pub fn run<E: EthSpec>(matches: &ArgMatches, env: Environment<E>) -> Result<(), String> {
    match matches.subcommand() {
        Some((wallet::CMD, matches)) => wallet::cli_run(matches)?,
        Some((validator::CMD, matches)) => validator::cli_run(matches, env)?,
        Some((unknown, _)) => {
            return Err(format!(
                "{} is not a valid {} command. See --help.",
                unknown, CMD
            ));
        }
        _ => return Err("No subcommand provided, see --help for options".to_string()),
    }

    Ok(())
}
