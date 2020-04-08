#[macro_use]
extern crate log;

mod change_genesis_time;
mod check_deposit_data;
mod deploy_deposit_contract;
mod eth1_genesis;
mod helpers;
mod interop_genesis;
mod new_testnet;
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
                .long("spec")
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
                    "Deploy a testing eth1 deposit contract.",
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
        .subcommand(
            SubCommand::with_name("interop-genesis")
                .about(
                    "Produces an interop-compatible genesis state using deterministic keypairs",
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
                    Arg::with_name("validator-count")
                        .long("validator-count")
                        .index(1)
                        .value_name("INTEGER")
                        .takes_value(true)
                        .default_value("1024")
                        .help("The number of validators in the genesis state."),
                )
                .arg(
                    Arg::with_name("genesis-time")
                        .long("genesis-time")
                        .short("t")
                        .value_name("UNIX_EPOCH")
                        .takes_value(true)
                        .help("The value for state.genesis_time. Defaults to now."),
                )
        )
        .subcommand(
            SubCommand::with_name("change-genesis-time")
                .about(
                    "Loads a file with an SSZ-encoded BeaconState and modifies the genesis time.",
                )
                .arg(
                    Arg::with_name("ssz-state")
                        .index(1)
                        .value_name("PATH")
                        .takes_value(true)
                        .required(true)
                        .help("The path to the SSZ file"),
                )
                .arg(
                    Arg::with_name("genesis-time")
                        .index(2)
                        .value_name("UNIX_EPOCH")
                        .takes_value(true)
                        .required(true)
                        .help("The value for state.genesis_time."),
                )
        )
        .subcommand(
            SubCommand::with_name("new-testnet")
                .about(
                    "Produce a new testnet directory.",
                )
                .arg(
                    Arg::with_name("testnet-dir")
                        .long("testnet-dir")
                        .value_name("DIRECTORY")
                        .takes_value(true)
                        .help("The output path for the new testnet directory. Defaults to ~/.lighthouse/testnet"),
                )
                .arg(
                    Arg::with_name("min-genesis-time")
                        .long("min-genesis-time")
                        .value_name("UNIX_SECONDS")
                        .takes_value(true)
                        .help("The minimum permitted genesis time. For non-eth1 testnets will be
                              the genesis time. Defaults to now."),
                )
                .arg(
                    Arg::with_name("min-genesis-active-validator-count")
                        .long("min-genesis-active-validator-count")
                        .value_name("INTEGER")
                        .takes_value(true)
                        .default_value("16384")
                        .help("The number of validators required to trigger eth2 genesis."),
                )
                .arg(
                    Arg::with_name("min-genesis-delay")
                        .long("min-genesis-delay")
                        .value_name("SECONDS")
                        .takes_value(true)
                        .default_value("3600")    // 10 minutes
                        .help("The delay between sufficient eth1 deposits and eth2 genesis."),
                )
                .arg(
                    Arg::with_name("min-deposit-amount")
                        .long("min-deposit-amount")
                        .value_name("GWEI")
                        .takes_value(true)
                        .default_value("100000000")    // 0.1 Eth
                        .help("The minimum permitted deposit amount."),
                )
                .arg(
                    Arg::with_name("max-effective-balance")
                        .long("max-effective-balance")
                        .value_name("GWEI")
                        .takes_value(true)
                        .default_value("3200000000")    // 3.2 Eth
                        .help("The amount required to become a validator."),
                )
                .arg(
                    Arg::with_name("effective-balance-increment")
                        .long("effective-balance-increment")
                        .value_name("GWEI")
                        .takes_value(true)
                        .default_value("100000000")    // 0.1 Eth
                        .help("The steps in effective balance calculation."),
                )
                .arg(
                    Arg::with_name("ejection-balance")
                        .long("ejection-balance")
                        .value_name("GWEI")
                        .takes_value(true)
                        .default_value("1600000000")    // 1.6 Eth
                        .help("The balance at which a validator gets ejected."),
                )
                .arg(
                    Arg::with_name("eth1-follow-distance")
                        .long("eth1-follow-distance")
                        .value_name("ETH1_BLOCKS")
                        .takes_value(true)
                        .default_value("16")
                        .help("The distance to follow behind the eth1 chain head."),
                )
                .arg(
                    Arg::with_name("genesis-fork-version")
                        .long("genesis-fork-version")
                        .value_name("HEX")
                        .takes_value(true)
                        .default_value("0x01030307")    // [1, 3, 3, 7]
                        .help("Used to avoid reply attacks between testnets. Recommended to set to
                              non-default."),
                )
                .arg(
                    Arg::with_name("deposit-contract-address")
                        .long("deposit-contract-address")
                        .value_name("ETH1_ADDRESS")
                        .takes_value(true)
                        .default_value("0x0000000000000000000000000000000000000000")
                        .help("The address of the deposit contract."),
                )
                .arg(
                    Arg::with_name("deposit-contract-deploy-block")
                        .long("deposit-contract-deploy-block")
                        .value_name("ETH1_BLOCK_NUMBER")
                        .takes_value(true)
                        .default_value("0")
                        .help("The block the deposit contract was deployed. Setting this is a huge
                              optimization for nodes, please do it."),
                )
        )
        .subcommand(
            SubCommand::with_name("check-deposit-data")
                .about(
                    "Checks the integrity of some deposit data.",
                )
                .arg(
                    Arg::with_name("deposit-amount")
                        .index(1)
                        .value_name("GWEI")
                        .takes_value(true)
                        .required(true)
                        .help("The amount (in Gwei) that was deposited"),
                )
                .arg(
                    Arg::with_name("deposit-data")
                        .index(2)
                        .value_name("HEX")
                        .takes_value(true)
                        .required(true)
                        .help("A 0x-prefixed hex string of the deposit data. Should include the
                            function signature."),
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
        ("interop-genesis", Some(matches)) => interop_genesis::run::<T>(env, matches)
            .unwrap_or_else(|e| error!("Failed to run interop-genesis command: {}", e)),
        ("change-genesis-time", Some(matches)) => change_genesis_time::run::<T>(matches)
            .unwrap_or_else(|e| error!("Failed to run change-genesis-time command: {}", e)),
        ("new-testnet", Some(matches)) => new_testnet::run::<T>(matches)
            .unwrap_or_else(|e| error!("Failed to run new_testnet command: {}", e)),
        ("check-deposit-data", Some(matches)) => check_deposit_data::run::<T>(matches)
            .unwrap_or_else(|e| error!("Failed to run check-deposit-data command: {}", e)),
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
