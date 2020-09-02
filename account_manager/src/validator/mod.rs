pub mod create;
pub mod deposit;
pub mod import;
pub mod list;

use crate::VALIDATOR_DIR_FLAG;
use clap::{App, Arg, ArgMatches};
use directory::{custom_base_dir, DEFAULT_VALIDATOR_DIR};
use environment::Environment;
use std::path::PathBuf;
use types::EthSpec;

pub const CMD: &str = "validator";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Provides commands for managing Eth2 validators.")
        .arg(
            Arg::with_name(VALIDATOR_DIR_FLAG)
                .long(VALIDATOR_DIR_FLAG)
                .value_name("VALIDATOR_DIRECTORY")
                .help(
                    "The path to search for validator directories. \
                    Defaults to ~/.lighthouse/{testnet}/validators",
                )
                .takes_value(true),
        )
        .about("Lists the names of all validators.")
        .subcommand(create::cli_app())
        .subcommand(deposit::cli_app())
        .subcommand(import::cli_app())
        .subcommand(list::cli_app())
}

pub fn cli_run<T: EthSpec>(matches: &ArgMatches, env: Environment<T>) -> Result<(), String> {
    let base_dir = if matches.value_of("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_VALIDATOR_DIR)
    } else {
        custom_base_dir(matches, VALIDATOR_DIR_FLAG, DEFAULT_VALIDATOR_DIR)?
    };
    eprintln!("validator-dir path: {:?}", base_dir);

    match matches.subcommand() {
        (create::CMD, Some(matches)) => create::cli_run::<T>(matches, env, base_dir),
        (deposit::CMD, Some(matches)) => deposit::cli_run::<T>(matches, env, base_dir),
        (import::CMD, Some(matches)) => import::cli_run(matches, base_dir),
        (list::CMD, Some(_)) => list::cli_run(base_dir),
        (unknown, _) => Err(format!(
            "{} does not have a {} command. See --help",
            CMD, unknown
        )),
    }
}
