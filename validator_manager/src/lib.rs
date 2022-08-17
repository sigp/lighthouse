use clap::App;
use clap::ArgMatches;
use environment::Environment;
use types::EthSpec;

mod validators;

pub const CMD: &str = "validator_manager";

pub fn cli_app<'a, 'b>() -> App<'a, 'b> {
    App::new(CMD)
        .visible_aliases(&["vm", CMD])
        .about("Utilities for managing a Lighthouse validator client via the HTTP API.")
        .subcommand(validators::cli_app())
}

/// Run the account manager, returning an error if the operation did not succeed.
pub fn run<'a, T: EthSpec>(
    matches: &'a ArgMatches<'a>,
    mut env: Environment<T>,
) -> Result<(), String> {
    let context = env.core_context();

    context
        .executor
        // This `block_on_dangerous` call reasonable since it is at the very highest level of the
        // application, the rest of which is all async. All other functions below this should be
        // async and should never call `block_on_dangerous` themselves.
        .block_on_dangerous(
            async {
                match matches.subcommand() {
                    (validators::CMD, Some(matches)) => validators::cli_run(matches, env).await,
                    (unknown, _) => Err(format!(
                        "{} is not a valid {} command. See --help.",
                        unknown, CMD
                    )),
                }
            },
            "validator_manager",
        )
        .ok_or("Shutting down")?
}
