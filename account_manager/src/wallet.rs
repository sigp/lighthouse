mod create;
mod validator;

use clap::{App, Arg, ArgMatches};
use clap_utils;
use environment::Environment;
use std::fs::create_dir_all;
use std::path::PathBuf;
use types::EthSpec;

pub const CMD: &str = "wallet";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("TODO")
        .arg(
            Arg::with_name("base-dir")
                .long("base-dir")
                .value_name("BASE_DIRECTORY")
                .help("A path containing Eth2 EIP-2386 wallets. Defaults to ~/.lighthouse/wallets")
                .takes_value(true),
        )
        .subcommand(create::cli_app())
        .subcommand(validator::cli_app())
}

pub fn cli_run<T: EthSpec>(matches: &ArgMatches, _env: Environment<T>) -> Result<(), String> {
    let base_dir = clap_utils::parse_path_with_default_in_home_dir(
        matches,
        "validator_dir",
        PathBuf::new().join(".lighthouse").join("wallets"),
    )?;

    if !base_dir.exists() {
        create_dir_all(&base_dir)
            .map_err(|e| format!("Unable to create {:?}: {:?}", base_dir, e))?;
    }

    match matches.subcommand() {
        (create::CMD, Some(matches)) => create::cli_run::<T>(matches, base_dir),
        (validator::CMD, Some(matches)) => validator::cli_run::<T>(matches, base_dir),
        (unknown, _) => {
            return Err(format!(
                "{} does not have a {} command. See --help",
                CMD, unknown
            ));
        }
    }
}
