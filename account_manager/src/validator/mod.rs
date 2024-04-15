pub mod create;
pub mod exit;
pub mod import;
pub mod list;
pub mod modify;
pub mod recover;
pub mod slashing_protection;

use crate::{VALIDATOR_DIR_FLAG, VALIDATOR_DIR_FLAG_ALIAS};
use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_utils::FLAG_HEADER;
use directory::{parse_path_or_default_with_flag, DEFAULT_VALIDATOR_DIR};
use environment::Environment;
use std::path::PathBuf;
use types::EthSpec;

pub const CMD: &str = "validator";

pub fn cli_app() -> Command {
    Command::new(CMD)
        .display_order(0)
        .about("Provides commands for managing Eth2 validators.")
        .arg(
            Arg::new("help")
                .long("help")
                .short('h')
                .help("Prints help information")
                .action(ArgAction::HelpLong)
                .display_order(0)
                .help_heading(FLAG_HEADER),
        )
        .arg(
            Arg::new(VALIDATOR_DIR_FLAG)
                .long(VALIDATOR_DIR_FLAG)
                .alias(VALIDATOR_DIR_FLAG_ALIAS)
                .value_name("VALIDATOR_DIRECTORY")
                .help(
                    "The path to search for validator directories. \
                    Defaults to ~/.lighthouse/{network}/validators",
                )
                .action(ArgAction::Set)
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

pub fn cli_run<E: EthSpec>(matches: &ArgMatches, env: Environment<E>) -> Result<(), String> {
    let validator_base_dir = if matches.get_one::<String>("datadir").is_some() {
        let path: PathBuf = clap_utils::parse_required(matches, "datadir")?;
        path.join(DEFAULT_VALIDATOR_DIR)
    } else {
        parse_path_or_default_with_flag(matches, VALIDATOR_DIR_FLAG, DEFAULT_VALIDATOR_DIR)?
    };
    eprintln!("validator-dir path: {:?}", validator_base_dir);

    match matches.subcommand() {
        Some((create::CMD, matches)) => create::cli_run::<E>(matches, env, validator_base_dir),
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
        _ => Err(format!("No command provided for {}. See --help", CMD)),
    }
}
