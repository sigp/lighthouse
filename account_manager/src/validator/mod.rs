pub mod cli;
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

pub fn cli_run<T: EthSpec>(matches: &ArgMatches, env: Environment<T>) -> Result<(), String> {
    let validator_base_dir = if matches.value_of("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_VALIDATOR_DIR)
    } else {
        parse_path_or_default_with_flag(matches, VALIDATOR_DIR_FLAG, DEFAULT_VALIDATOR_DIR)?
    };
    eprintln!("validator-dir path: {:?}", validator_base_dir);

    match matches.subcommand() {
        (create::CMD, Some(matches)) => create::cli_run::<T>(matches, env, validator_base_dir),
        (modify::CMD, Some(matches)) => modify::cli_run(matches, validator_base_dir),
        (import::CMD, Some(matches)) => import::cli_run(matches, validator_base_dir),
        (list::CMD, Some(_)) => list::cli_run(validator_base_dir),
        (recover::CMD, Some(matches)) => recover::cli_run(matches, validator_base_dir),
        (slashing_protection::CMD, Some(matches)) => {
            slashing_protection::cli_run(matches, env, validator_base_dir)
        }
        (exit::CMD, Some(matches)) => exit::cli_run(matches, env),
        (unknown, _) => Err(format!(
            "{} does not have a {} command. See --help",
            CMD, unknown
        )),
    }
}
