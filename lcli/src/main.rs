#[macro_use]
extern crate log;

mod deploy_deposit_contract;
mod eth1_genesis;
mod parse_hex;
mod refund_deposit_contract;
mod transition_blocks;

use clap::{App, Arg, ArgMatches, SubCommand};
use environment::EnvironmentBuilder;
use log::Level;
use parse_hex::run_parse_hex;
use std::fs::File;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use transition_blocks::run_transition_blocks;
use types::{test_utils::TestingBeaconStateBuilder, EthSpec, MainnetEthSpec, MinimalEthSpec};

fn main() {
    simple_logger::init_with_level(Level::Info).expect("logger should initialize");

    let matches = App::new("Lighthouse CLI Tool")
        .about(
            "Performs various testing-related tasks, modelled after zcli. \
             by @protolambda.",
        )
        .arg(
            Arg::with_name("spec")
                .short("s")
                .value_name("STRING")
                .takes_value(true)
                .required(true)
                .possible_values(&["minimal", "mainnet"])
                .default_value("mainnet")
        )
        .subcommand(
            SubCommand::with_name("genesis_yaml")
                .about("Generates a genesis YAML file")
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
                    Arg::with_name("output_file")
                        .short("f")
                        .value_name("PATH")
                        .takes_value(true)
                        .default_value("./genesis_state.yaml")
                        .help("Output file for generated state."),
                ),
        )
        .subcommand(
            SubCommand::with_name("transition-blocks")
                .about("Performs a state transition given a pre-state and block")
                .arg(
                    Arg::with_name("pre-state")
                        .value_name("BEACON_STATE")
                        .takes_value(true)
                        .required(true)
                        .help("Path to a SSZ file of the pre-state."),
                )
                .arg(
                    Arg::with_name("block")
                        .value_name("BEACON_BLOCK")
                        .takes_value(true)
                        .required(true)
                        .help("Path to a SSZ file of the block to apply to pre-state."),
                )
                .arg(
                    Arg::with_name("output")
                        .value_name("SSZ_FILE")
                        .takes_value(true)
                        .required(true)
                        .default_value("./output.ssz")
                        .help("Path to output a SSZ file."),
                ),
        )
        .subcommand(
            SubCommand::with_name("pretty-hex")
                .about("Parses SSZ encoded as ASCII 0x-prefixed hex")
                .arg(
                    Arg::with_name("type")
                        .value_name("TYPE")
                        .takes_value(true)
                        .required(true)
                        .possible_values(&["block"])
                        .help("The schema of the supplied SSZ."),
                )
                .arg(
                    Arg::with_name("hex_ssz")
                        .value_name("HEX")
                        .takes_value(true)
                        .required(true)
                        .help("SSZ encoded as 0x-prefixed hex"),
                ),
        )
        .subcommand(
            SubCommand::with_name("deploy-deposit-contract")
                .about(
                    "Deploy an eth1 deposit contract and create a ~/.lighthouse/testnet directory \
                    (unless another directory is specified).",
                )
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .value_name("PATH")
                        .takes_value(true)
                        .help("The output directory. Defaults to ~/.lighthouse/testnet"),
                )
                .arg(
                    Arg::with_name("min-genesis-time")
                        .short("t")
                        .long("min-genesis-time")
                        .value_name("UNIX_EPOCH_SECONDS")
                        .takes_value(true)
                        .default_value("0")
                        .help("The MIN_GENESIS_TIME constant."),
                )
                .arg(
                    Arg::with_name("min-genesis-active-validator-count")
                        .short("v")
                        .long("min-genesis-active-validator-count")
                        .value_name("INTEGER")
                        .takes_value(true)
                        .default_value("64")
                        .help("The MIN_GENESIS_ACTIVE_VALIDATOR_COUNT constant."),
                )
                .arg(
                    Arg::with_name("eth1-endpoint")
                        .short("e")
                        .long("eth1-endpoint")
                        .value_name("HTTP_SERVER")
                        .takes_value(true)
                        .default_value("http://localhost:8545")
                        .help("The URL to the eth1 JSON-RPC http API."),
                )
                .arg(
                    Arg::with_name("confirmations")
                        .value_name("INTEGER")
                        .long("confirmations")
                        .takes_value(true)
                        .default_value("3")
                        .help("The number of block confirmations before declaring the contract deployed."),
                )
                .arg(
                    Arg::with_name("password")
                        .long("password")
                        .value_name("FILE")
                        .takes_value(true)
                        .help("The password file to unlock the eth1 account (see --index)"),
                )
        )
        .subcommand(
            SubCommand::with_name("refund-deposit-contract")
                .about(
                    "Calls the steal() function on a testnet eth1 contract.",
                )
                .arg(
                    Arg::with_name("testnet-dir")
                        .short("d")
                        .long("testnet-dir")
                        .value_name("PATH")
                        .takes_value(true)
                        .help("The testnet dir. Defaults to ~/.lighthouse/testnet"),
                )
                .arg(
                    Arg::with_name("eth1-endpoint")
                        .short("e")
                        .long("eth1-endpoint")
                        .value_name("HTTP_SERVER")
                        .takes_value(true)
                        .default_value("http://localhost:8545")
                        .help("The URL to the eth1 JSON-RPC http API."),
                )
                .arg(
                    Arg::with_name("password")
                        .long("password")
                        .value_name("FILE")
                        .takes_value(true)
                        .help("The password file to unlock the eth1 account (see --index)"),
                )
                .arg(
                    Arg::with_name("account-index")
                        .short("i")
                        .long("account-index")
                        .value_name("INDEX")
                        .takes_value(true)
                        .default_value("0")
                        .help("The eth1 accounts[] index which will send the transaction"),
                )
        )
        .subcommand(
            SubCommand::with_name("eth1-genesis")
                .about(
                    "Listens to the eth1 chain and finds the genesis beacon state",
                )
                .arg(
                    Arg::with_name("testnet-dir")
                        .short("d")
                        .long("testnet-dir")
                        .value_name("PATH")
                        .takes_value(true)
                        .help("The testnet dir. Defaults to ~/.lighthouse/testnet"),
                )
                .arg(
                    Arg::with_name("eth1-endpoint")
                        .short("e")
                        .long("eth1-endpoint")
                        .value_name("HTTP_SERVER")
                        .takes_value(true)
                        .default_value("http://localhost:8545")
                        .help("The URL to the eth1 JSON-RPC http API."),
                )
        )
        .get_matches();

    macro_rules! run_with_spec {
        ($env_builder: expr) => {
            run($env_builder, &matches)
        };
    }

    match matches.value_of("spec") {
        Some("minimal") => run_with_spec!(EnvironmentBuilder::minimal()),
        Some("mainnet") => run_with_spec!(EnvironmentBuilder::mainnet()),
        Some("interop") => run_with_spec!(EnvironmentBuilder::interop()),
        spec => {
            // This path should be unreachable due to slog having a `default_value`
            unreachable!("Unknown spec configuration: {:?}", spec);
        }
    }
}

fn run<T: EthSpec>(env_builder: EnvironmentBuilder<T>, matches: &ArgMatches) {
    let env = env_builder
        .multi_threaded_tokio_runtime()
        .expect("should start tokio runtime")
        .async_logger("trace", None)
        .expect("should start null logger")
        .build()
        .expect("should build env");

    match matches.subcommand() {
        ("genesis_yaml", Some(matches)) => {
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
        }
        ("transition-blocks", Some(matches)) => run_transition_blocks::<T>(matches)
            .unwrap_or_else(|e| error!("Failed to transition blocks: {}", e)),
        ("pretty-hex", Some(matches)) => run_parse_hex::<T>(matches)
            .unwrap_or_else(|e| error!("Failed to pretty print hex: {}", e)),
        ("deploy-deposit-contract", Some(matches)) => {
            deploy_deposit_contract::run::<T>(env, matches)
                .unwrap_or_else(|e| error!("Failed to run deploy-deposit-contract command: {}", e))
        }
        ("refund-deposit-contract", Some(matches)) => {
            refund_deposit_contract::run::<T>(env, matches)
                .unwrap_or_else(|e| error!("Failed to run refund-deposit-contract command: {}", e))
        }
        ("eth1-genesis", Some(matches)) => eth1_genesis::run::<T>(env, matches)
            .unwrap_or_else(|e| error!("Failed to run eth1-genesis command: {}", e)),
        (other, _) => error!("Unknown subcommand {}. See --help.", other),
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
