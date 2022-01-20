pub mod create;
pub mod exit;
pub mod import;
pub mod list;
pub mod modify;
pub mod recover;
pub mod slashing_protection;

use crate::VALIDATOR_DIR_FLAG;
use clap::{App, Arg, ArgMatches};
use directory::{parse_path_or_default_with_flag, DEFAULT_VALIDATOR_DIR};
use environment::Environment;
use std::path::PathBuf;
use types::EthSpec;

pub const CMD: &str = "validator";

pub fn cli_app<'a>() -> App<'a> {
    App::new(CMD)
        .about("Provides commands for managing Eth2 validators.")
        .arg(
            Arg::new(VALIDATOR_DIR_FLAG)
                .long(VALIDATOR_DIR_FLAG)
                .value_name("VALIDATOR_DIRECTORY")
                .help(
                    "The path to search for validator directories. \
                    Defaults to ~/.lighthouse/{network}/validators",
                )
                .takes_value(true)
                .conflicts_with("datadir"),
        )
        .subcommand(create::cli_app())
        .subcommand(modify::cli_app())
        .subcommand(import::cli_app())
        .subcommand(list::cli_app())
        .subcommand(recover::cli_app())
        .subcommand(slashing_protection::cli_app())
        .subcommand(exit::cli_app())
}

pub fn cli_run<T: EthSpec>(matches: &ArgMatches, env: Environment<T>) -> Result<(), String> {
    let validator_base_dir = if matches.value_of("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_VALIDATOR_DIR)
    } else {
        parse_path_or_default_with_flag(matches, VALIDATOR_DIR_FLAG, DEFAULT_VALIDATOR_DIR)?
    };
    eprintln!("validator-dir path: {:?}", validator_base_dir);

    match matches.subcommand() {
        Some((create::CMD, matches)) => create::cli_run::<T>(matches, env, validator_base_dir),
        Some((modify::CMD, matches)) => modify::cli_run(matches, validator_base_dir),
        Some((import::CMD, matches)) => import::cli_run(matches, validator_base_dir),
        Some((list::CMD, _)) => list::cli_run(validator_base_dir),
        Some((recover::CMD, matches)) => recover::cli_run(matches, validator_base_dir),
        Some((slashing_protection::CMD, matches)) => {
            slashing_protection::cli_run(matches, env, validator_base_dir)
        }
        Some((exit::CMD, matches)) => exit::cli_run(matches, env),
        Some((unknown, _)) => Err(format!(
            "{} does not have a {} command. See --help",
            CMD, unknown
        )),
        None => return Err(format!("{} requires a command. See --help", CMD)),
    }
}
