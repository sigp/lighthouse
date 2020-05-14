mod common;
mod validator;
mod wallet;

use clap::App;
use clap::ArgMatches;
use environment::Environment;
use slog::info;
use std::fs;
use std::path::PathBuf;
use types::EthSpec;

pub const CMD: &str = "account_manager";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .visible_aliases(&["a", "am", "account", CMD])
        .about("Utilities for generating and managing Ethereum 2.0 accounts.")
        .subcommand(wallet::cli_app())
        .subcommand(validator::cli_app())
}

/// Run the account manager, returning an error if the operation did not succeed.
pub fn run<T: EthSpec>(matches: &ArgMatches<'_>, mut env: Environment<T>) -> Result<(), String> {
    let context = env.core_context();
    let log = context.log.clone();

    // If the `datadir` was not provided, default to the home directory. If the home directory is
    // not known, use the current directory.
    let datadir = matches
        .value_of("datadir")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(".lighthouse")
                .join("validators")
        });

    fs::create_dir_all(&datadir).map_err(|e| format!("Failed to create datadir: {}", e))?;

    info!(
        log,
        "Located data directory";
        "path" => format!("{:?}", datadir)
    );

    match matches.subcommand() {
        (wallet::CMD, Some(matches)) => wallet::cli_run(matches, env)?,
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
