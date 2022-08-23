pub mod common;
pub mod create_validators;
pub mod import_validators;
pub mod move_validators;

use crate::DumpConfig;
use clap::{App, ArgMatches};
use types::{ChainSpec, EthSpec};

pub const CMD: &str = "validators";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Provides commands for managing validators in a Lighthouse Validator Client.")
        .subcommand(create_validators::cli_app())
        .subcommand(import_validators::cli_app())
}

pub async fn cli_run<'a, T: EthSpec>(
    matches: &'a ArgMatches<'a>,
    spec: &ChainSpec,
    dump_config: DumpConfig,
) -> Result<(), String> {
    match matches.subcommand() {
        (create_validators::CMD, Some(matches)) => {
            create_validators::cli_run::<T>(matches, spec, dump_config).await
        }
        (import_validators::CMD, Some(matches)) => {
            import_validators::cli_run(matches, dump_config).await
        }
        (unknown, _) => Err(format!(
            "{} does not have a {} command. See --help",
            CMD, unknown
        )),
    }
}
