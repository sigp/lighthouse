use clap::{App, Arg, SubCommand};
use env_logger::{Builder, Env};
use gen_keys::gen_keys;
use run_test::run_test;
use std::fs;
use types::test_utils::keypairs_path;
use types::ChainSpec;

mod beacon_chain_harness;
mod gen_keys;
mod run_test;
mod test_case;
mod validator_harness;

use validator_harness::ValidatorHarness;

fn main() {
    let validator_file_path = keypairs_path();

    let _ = fs::create_dir(validator_file_path.parent().unwrap());

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
            SubCommand::with_name("gen_keys")
                .about("Builds a file of BLS keypairs for faster tests.")
                .arg(
                    Arg::with_name("validator_count")
                        .long("validator_count")
                        .short("n")
                        .value_name("VALIDATOR_COUNT")
                        .help("Number of validators to generate.")
                        .required(true),
                )
                .arg(
                    Arg::with_name("output_file")
                        .long("output_file")
                        .short("d")
                        .value_name("GENESIS_TIME")
                        .help("Output directory for generated YAML.")
                        .default_value(validator_file_path.to_str().unwrap()),
                ),
        )
        .get_matches();

    if let Some(log_level) = matches.value_of("log") {
        Builder::from_env(Env::default().default_filter_or(log_level)).init();
    }

    let _spec = match matches.value_of("spec") {
        Some("foundation") => ChainSpec::foundation(),
        Some("few_validators") => ChainSpec::few_validators(),
        _ => unreachable!(), // Has a default value, should always exist.
    };

    if let Some(matches) = matches.subcommand_matches("run_test") {
        run_test(matches);
    }

    if let Some(matches) = matches.subcommand_matches("gen_keys") {
        gen_keys(matches);
    }
}
