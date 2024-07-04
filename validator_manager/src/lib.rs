use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_utils::{get_color_style, FLAG_HEADER};
use common::write_to_json_file;
use environment::Environment;
use serde::Serialize;
use std::path::PathBuf;
use types::EthSpec;

pub mod common;
pub mod create_validators;
pub mod import_validators;
pub mod move_validators;

pub const CMD: &str = "validator_manager";

/// This flag is on the top-level `lighthouse` binary.
const DUMP_CONFIGS_FLAG: &str = "dump-config";

/// Used only in testing, this allows a command to dump its configuration to a file and then exit
/// successfully. This allows for testing how the CLI arguments translate to some configuration.
pub enum DumpConfig {
    Disabled,
    Enabled(PathBuf),
}

impl DumpConfig {
    /// Returns `Ok(true)` if the configuration was successfully written to a file and the
    /// application should exit successfully without doing anything else.
    pub fn should_exit_early<T: Serialize>(&self, config: &T) -> Result<bool, String> {
        match self {
            DumpConfig::Disabled => Ok(false),
            DumpConfig::Enabled(dump_path) => {
                dbg!(dump_path);
                write_to_json_file(dump_path, config)?;
                Ok(true)
            }
        }
    }
}

pub fn cli_app() -> Command {
    Command::new(CMD)
        .visible_aliases(["vm", "validator-manager"])
        .display_order(0)
        .styles(get_color_style())
        .about("Utilities for managing a Lighthouse validator client via the HTTP API.")
        .arg(
            Arg::new("help")
                .long("help")
                .short('h')
                .help("Prints help information")
                .action(ArgAction::HelpLong)
                .display_order(0)
                .help_heading(FLAG_HEADER),
        )
        .subcommand(create_validators::cli_app())
        .subcommand(import_validators::cli_app())
        .subcommand(move_validators::cli_app())
}

/// Run the account manager, returning an error if the operation did not succeed.
pub fn run<E: EthSpec>(matches: &ArgMatches, env: Environment<E>) -> Result<(), String> {
    let context = env.core_context();
    let spec = context.eth2_config.spec;
    let dump_config = clap_utils::parse_optional(matches, DUMP_CONFIGS_FLAG)?
        .map(DumpConfig::Enabled)
        .unwrap_or_else(|| DumpConfig::Disabled);

    context
        .executor
        // This `block_on_dangerous` call reasonable since it is at the very highest level of the
        // application, the rest of which is all async. All other functions below this should be
        // async and should never call `block_on_dangerous` themselves.
        .block_on_dangerous(
            async {
                match matches.subcommand() {
                    Some((create_validators::CMD, matches)) => {
                        create_validators::cli_run::<E>(matches, &spec, dump_config).await
                    }
                    Some((import_validators::CMD, matches)) => {
                        import_validators::cli_run(matches, dump_config).await
                    }
                    Some((move_validators::CMD, matches)) => {
                        move_validators::cli_run(matches, dump_config).await
                    }
                    Some((unknown, _)) => Err(format!(
                        "{} is not a valid {} command. See --help.",
                        unknown, CMD
                    )),
                    _ => Err("No command supplied. See --help.".to_string()),
                }
            },
            "validator_manager",
        )
        .ok_or("Shutting down")?
}
