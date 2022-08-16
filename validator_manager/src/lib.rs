use clap::App;
use clap::ArgMatches;
use environment::Environment;
use types::EthSpec;

mod validator;

pub const CMD: &str = "validator_manager";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .visible_aliases(&["vm", CMD])
        .about("Utilities for managing a Lighthouse validator client via the HTTP API.")
        .subcommand(validator::cli_app())
}

/// Run the account manager, returning an error if the operation did not succeed.
pub async fn run<'a, T: EthSpec>(
    matches: &'a ArgMatches<'a>,
    env: Environment<T>,
) -> Result<(), String> {
    match matches.subcommand() {
        (validator::CMD, Some(matches)) => validator::cli_run(matches, env).await?,
        (unknown, _) => {
            return Err(format!(
                "{} is not a valid {} command. See --help.",
                unknown, CMD
            ));
        }
    }

    Ok(())
}
