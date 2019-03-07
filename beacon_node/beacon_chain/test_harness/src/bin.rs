use clap::{App, Arg, SubCommand};
use env_logger::{Builder, Env};
use run_test::run_test;

mod beacon_chain_harness;
mod run_test;
mod test_case;
mod validator_harness;

use validator_harness::ValidatorHarness;

fn main() {
    let matches = App::new("Lighthouse Test Harness Runner")
        .version("0.0.1")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Runs `test_harness` using a YAML test_case.")
        .arg(
            Arg::with_name("log")
                .long("log-level")
                .value_name("LOG_LEVEL")
                .help("Logging level.")
                .possible_values(&["error", "warn", "info", "debug", "trace"])
                .default_value("debug")
                .required(true),
        )
        .subcommand(
            SubCommand::with_name("run_test")
                .about("Executes a YAML test specification")
                .arg(
                    Arg::with_name("yaml")
                        .long("yaml")
                        .value_name("FILE")
                        .help("YAML file test_case.")
                        .required(true),
                ),
        )
        .get_matches();

    if let Some(log_level) = matches.value_of("log") {
        Builder::from_env(Env::default().default_filter_or(log_level)).init();
    }

    if let Some(matches) = matches.subcommand_matches("run_test") {
        run_test(matches);
    }
}
