use clap::{App, Arg, SubCommand};
use env_logger::{Builder, Env};
use prepare::prepare;
use run_test::run_test;
use types::ChainSpec;

mod beacon_chain_harness;
mod prepare;
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
                .short("l")
                .value_name("LOG_LEVEL")
                .help("Logging level.")
                .possible_values(&["error", "warn", "info", "debug", "trace"])
                .default_value("debug")
                .required(true),
        )
        .arg(
            Arg::with_name("spec")
                .long("spec")
                .short("s")
                .value_name("SPECIFICATION")
                .help("ChainSpec instantiation.")
                .possible_values(&["foundation", "few_validators"])
                .default_value("foundation"),
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
                )
                .arg(
                    Arg::with_name("validators_dir")
                        .long("validators-dir")
                        .short("v")
                        .value_name("VALIDATORS_DIR")
                        .help("A directory with validator deposits and keypair YAML."),
                ),
        )
        .subcommand(
            SubCommand::with_name("prepare")
                .about("Builds validator YAML files for faster tests.")
                .arg(
                    Arg::with_name("validator_count")
                        .long("validator_count")
                        .short("n")
                        .value_name("VALIDATOR_COUNT")
                        .help("Number of validators to generate.")
                        .required(true),
                )
                .arg(
                    Arg::with_name("genesis_time")
                        .long("genesis_time")
                        .short("t")
                        .value_name("GENESIS_TIME")
                        .help("Time for validator deposits.")
                        .required(true),
                )
                .arg(
                    Arg::with_name("output_dir")
                        .long("output_dir")
                        .short("d")
                        .value_name("GENESIS_TIME")
                        .help("Output directory for generated YAML.")
                        .default_value("validators"),
                ),
        )
        .get_matches();

    if let Some(log_level) = matches.value_of("log") {
        Builder::from_env(Env::default().default_filter_or(log_level)).init();
    }

    let spec = match matches.value_of("spec") {
        Some("foundation") => ChainSpec::foundation(),
        Some("few_validators") => ChainSpec::few_validators(),
        _ => unreachable!(), // Has a default value, should always exist.
    };

    if let Some(matches) = matches.subcommand_matches("run_test") {
        run_test(matches);
    }

    if let Some(matches) = matches.subcommand_matches("prepare") {
        prepare(matches, &spec);
    }
}
