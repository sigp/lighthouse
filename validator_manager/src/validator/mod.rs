pub mod common;
pub mod create;

use clap::{App, ArgMatches};
use environment::Environment;
use types::EthSpec;

pub const CMD: &str = "validator";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Provides commands for managing validators in a Lighthouse Validator Client.")
        .subcommand(create::cli_app())
}

pub async fn cli_run<'a, T: EthSpec>(
    matches: &'a ArgMatches<'a>,
    env: Environment<T>,
) -> Result<(), String> {
    match matches.subcommand() {
        (create::CMD, Some(matches)) => create::cli_run::<T>(matches, env).await,
        (unknown, _) => Err(format!(
            "{} does not have a {} command. See --help",
            CMD, unknown
        )),
    }
}
