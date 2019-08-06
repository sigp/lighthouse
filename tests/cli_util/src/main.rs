#[macro_use]
extern crate log;

use clap::{App, Arg, SubCommand};
use std::fs::File;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use types::{test_utils::TestingBeaconStateBuilder, EthSpec, MainnetEthSpec, MinimalEthSpec};

fn main() {
    simple_logger::init().expect("logger should initialize");

    let matches = App::new("Lighthouse Testing CLI Tool")
        .version("0.1.0")
        .author("Paul Hauner <paul@sigmaprime.io>")
        .about("Performs various testing-related tasks.")
        .subcommand(
            SubCommand::with_name("genesis_yaml")
                .about("Generates a genesis YAML file")
                .version("0.1.0")
                .author("Paul Hauner <paul@sigmaprime.io>")
                .arg(
                    Arg::with_name("num_validators")
                        .short("n")
                        .value_name("INTEGER")
                        .takes_value(true)
                        .required(true)
                        .help("Number of initial validators."),
                )
                .arg(
                    Arg::with_name("genesis_time")
                        .short("g")
                        .value_name("INTEGER")
                        .takes_value(true)
                        .required(false)
                        .help("Eth2 genesis time (seconds since UNIX epoch)."),
                )
                .arg(
                    Arg::with_name("spec")
                        .short("s")
                        .value_name("STRING")
                        .takes_value(true)
                        .required(true)
                        .possible_values(&["minimal", "mainnet"])
                        .default_value("minimal")
                        .help("Eth2 genesis time (seconds since UNIX epoch)."),
                )
                .arg(
                    Arg::with_name("output_file")
                        .short("f")
                        .value_name("PATH")
                        .takes_value(true)
                        .default_value("./genesis_state.yaml")
                        .help("Output file for generated state."),
                ),
        )
        .get_matches();

    if let Some(matches) = matches.subcommand_matches("genesis_yaml") {
        let num_validators = matches
            .value_of("num_validators")
            .expect("slog requires num_validators")
            .parse::<usize>()
            .expect("num_validators must be a valid integer");

        let genesis_time = if let Some(string) = matches.value_of("genesis_time") {
            string
                .parse::<u64>()
                .expect("genesis_time must be a valid integer")
        } else {
            warn!("No genesis time supplied via CLI, using the current time.");
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("should obtain time since unix epoch")
                .as_secs()
        };

        let file = matches
            .value_of("output_file")
            .expect("slog requires output file")
            .parse::<PathBuf>()
            .expect("output_file must be a valid path");

        info!(
            "Creating genesis state with {} validators and genesis time {}.",
            num_validators, genesis_time
        );

        match matches.value_of("spec").expect("spec is required by slog") {
            "minimal" => genesis_yaml::<MinimalEthSpec>(num_validators, genesis_time, file),
            "mainnet" => genesis_yaml::<MainnetEthSpec>(num_validators, genesis_time, file),
            _ => unreachable!("guarded by slog possible_values"),
        };

        info!("Genesis state YAML file created. Exiting successfully.");
    } else {
        error!("No subcommand supplied.")
    }
}

/// Creates a genesis state and writes it to a YAML file.
fn genesis_yaml<T: EthSpec>(validator_count: usize, genesis_time: u64, output: PathBuf) {
    let spec = &T::default_spec();

    let builder: TestingBeaconStateBuilder<T> =
        TestingBeaconStateBuilder::from_default_keypairs_file_if_exists(validator_count, spec);

    let (mut state, _keypairs) = builder.build();
    state.genesis_time = genesis_time;

    info!("Generated state root: {:?}", state.canonical_root());

    info!("Writing genesis state to {:?}", output);

    let file = File::create(output.clone())
        .unwrap_or_else(|e| panic!("unable to create file: {:?}. Error: {:?}", output, e));
    serde_yaml::to_writer(file, &state).expect("should be able to serialize BeaconState");
}
