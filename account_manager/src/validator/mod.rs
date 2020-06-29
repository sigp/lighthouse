pub mod create;
pub mod deposit;
pub mod mv; // Not called `move` since it is a reserved keyword.

use clap::{App, ArgMatches};
use environment::Environment;
use types::EthSpec;

pub const CMD: &str = "validator";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .about("Provides commands for managing Eth2 validators.")
        .subcommand(create::cli_app())
        .subcommand(deposit::cli_app())
        .subcommand(mv::cli_app())
}

pub fn cli_run<T: EthSpec>(matches: &ArgMatches, env: Environment<T>) -> Result<(), String> {
    match matches.subcommand() {
        (create::CMD, Some(matches)) => create::cli_run::<T>(matches, env),
        (deposit::CMD, Some(matches)) => deposit::cli_run::<T>(matches, env),
        (mv::CMD, Some(matches)) => mv::cli_run::<T>(matches),
        (unknown, _) => {
            return Err(format!(
                "{} does not have a {} command. See --help",
                CMD, unknown
            ));
        }
    }
}
