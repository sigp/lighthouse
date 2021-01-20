#[macro_use]
extern crate log;
mod change_genesis_time;
mod check_deposit_data;
mod eth1_genesis;
mod generate_bootnode_enr;
mod insecure_validators;
mod interop_genesis;
mod new_testnet;
mod parse_hex;
mod replace_state_pubkeys;
mod skip_slots;
mod transition_blocks;

use clap::{App, Arg, ArgMatches, SubCommand};
use environment::EnvironmentBuilder;
use log::LevelFilter;
use parse_hex::run_parse_hex;
use std::fs::File;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use transition_blocks::run_transition_blocks;
use types::{
    test_utils::TestingBeaconStateBuilder, EthSpec, EthSpecId, MainnetEthSpec, MinimalEthSpec,
};

fn main() {
    simple_logger::SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .expect("Logger should be initialised");

    let matches = App::new("Lighthouse CLI Tool")
        .version(lighthouse_version::VERSION)
        .about("Performs various testing-related tasks, including defining testnets.")
        .arg(
            Arg::with_name("spec")
                .short("s")
                .long("spec")
                .value_name("STRING")
                .takes_value(true)
                .required(true)
                .possible_values(&["minimal", "mainnet"])
                .default_value("mainnet"),
        )
        .arg(
            Arg::with_name("testnet-dir")
                .short("d")
                .long("testnet-dir")
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("The testnet dir. Defaults to ~/.lighthouse/testnet"),
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
            SubCommand::with_name("skip-slots")
                .about(
                    "Performs a state transition from some state across some number of skip slots",
                )
                .arg(
                    Arg::with_name("pre-state")
                        .value_name("BEACON_STATE")
                        .takes_value(true)
                        .required(true)
                        .help("Path to a SSZ file of the pre-state."),
                )
                .arg(
                    Arg::with_name("slots")
                        .value_name("SLOT_COUNT")
                        .takes_value(true)
                        .required(true)
                        .help("Number of slots to skip before outputting a state.."),
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
            SubCommand::with_name("eth1-genesis")
                .about("Listens to the eth1 chain and finds the genesis beacon state")
                .arg(
                    Arg::with_name("eth1-endpoint")
                        .short("e")
                        .long("eth1-endpoint")
                        .value_name("HTTP_SERVER")
                        .takes_value(true)
                        .help("Deprecated. Use --eth1-endpoints."),
                )
                .arg(
                    Arg::with_name("eth1-endpoints")
                        .long("eth1-endpoints")
                        .value_name("HTTP_SERVER_LIST")
                        .takes_value(true)
                        .conflicts_with("eth1-endpoint")
                        .help(
                            "One or more comma-delimited URLs to eth1 JSON-RPC http APIs. \
                                If multiple endpoints are given the endpoints are used as \
                                fallback in the given order.",
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("interop-genesis")
                .about("Produces an interop-compatible genesis state using deterministic keypairs")
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
                .arg(
                    Arg::with_name("genesis-fork-version")
                        .long("genesis-fork-version")
                        .value_name("HEX")
                        .takes_value(true)
                        .help(
                            "Used to avoid reply attacks between testnets. Recommended to set to
                              non-default.",
                        ),
                ),
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
                ),
        )
        .subcommand(
            SubCommand::with_name("replace-state-pubkeys")
                .about(
                    "Loads a file with an SSZ-encoded BeaconState and replaces \
                    all the validator pubkeys with ones derived from the mnemonic \
                    such that validator indices correspond to EIP-2334 voting keypair \
                    derivation paths.",
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
                    Arg::with_name("mnemonic")
                        .index(2)
                        .value_name("BIP39_MNENMONIC")
                        .takes_value(true)
                        .required(true)
                        .default_value(
                            "replace nephew blur decorate waste convince soup column \
                            orient excite play baby",
                        )
                        .help("The mnemonic for key derivation."),
                ),
        )
        .subcommand(
            SubCommand::with_name("new-testnet")
                .about(
                    "Produce a new testnet directory. If any of the optional flags are not
                    supplied the values will remain the default for the --spec flag",
                )
                .arg(
                    Arg::with_name("force")
                        .long("force")
                        .short("f")
                        .takes_value(false)
                        .help("Overwrites any previous testnet configurations"),
                )
                .arg(
                    Arg::with_name("min-genesis-time")
                        .long("min-genesis-time")
                        .value_name("UNIX_SECONDS")
                        .takes_value(true)
                        .help(
                            "The minimum permitted genesis time. For non-eth1 testnets will be
                              the genesis time. Defaults to now.",
                        ),
                )
                .arg(
                    Arg::with_name("min-genesis-active-validator-count")
                        .long("min-genesis-active-validator-count")
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The number of validators required to trigger eth2 genesis."),
                )
                .arg(
                    Arg::with_name("genesis-delay")
                        .long("genesis-delay")
                        .value_name("SECONDS")
                        .takes_value(true)
                        .help("The delay between sufficient eth1 deposits and eth2 genesis."),
                )
                .arg(
                    Arg::with_name("min-deposit-amount")
                        .long("min-deposit-amount")
                        .value_name("GWEI")
                        .takes_value(true)
                        .help("The minimum permitted deposit amount."),
                )
                .arg(
                    Arg::with_name("max-effective-balance")
                        .long("max-effective-balance")
                        .value_name("GWEI")
                        .takes_value(true)
                        .help("The amount required to become a validator."),
                )
                .arg(
                    Arg::with_name("effective-balance-increment")
                        .long("effective-balance-increment")
                        .value_name("GWEI")
                        .takes_value(true)
                        .help("The steps in effective balance calculation."),
                )
                .arg(
                    Arg::with_name("ejection-balance")
                        .long("ejection-balance")
                        .value_name("GWEI")
                        .takes_value(true)
                        .help("The balance at which a validator gets ejected."),
                )
                .arg(
                    Arg::with_name("eth1-follow-distance")
                        .long("eth1-follow-distance")
                        .value_name("ETH1_BLOCKS")
                        .takes_value(true)
                        .help("The distance to follow behind the eth1 chain head."),
                )
                .arg(
                    Arg::with_name("genesis-fork-version")
                        .long("genesis-fork-version")
                        .value_name("HEX")
                        .takes_value(true)
                        .help(
                            "Used to avoid reply attacks between testnets. Recommended to set to
                              non-default.",
                        ),
                )
                .arg(
                    Arg::with_name("deposit-contract-address")
                        .long("deposit-contract-address")
                        .value_name("ETH1_ADDRESS")
                        .takes_value(true)
                        .required(true)
                        .help("The address of the deposit contract."),
                )
                .arg(
                    Arg::with_name("deposit-contract-deploy-block")
                        .long("deposit-contract-deploy-block")
                        .value_name("ETH1_BLOCK_NUMBER")
                        .takes_value(true)
                        .default_value("0")
                        .help(
                            "The block the deposit contract was deployed. Setting this is a huge
                              optimization for nodes, please do it.",
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("check-deposit-data")
                .about("Checks the integrity of some deposit data.")
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
                        .help(
                            "A 0x-prefixed hex string of the deposit data. Should include the
                            function signature.",
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("generate-bootnode-enr")
                .about("Generates an ENR address to be used as a pre-genesis boot node.")
                .arg(
                    Arg::with_name("ip")
                        .long("ip")
                        .value_name("IP_ADDRESS")
                        .takes_value(true)
                        .required(true)
                        .help("The IP address to be included in the ENR and used for discovery"),
                )
                .arg(
                    Arg::with_name("udp-port")
                        .long("udp-port")
                        .value_name("UDP_PORT")
                        .takes_value(true)
                        .required(true)
                        .help("The UDP port to be included in the ENR and used for discovery"),
                )
                .arg(
                    Arg::with_name("tcp-port")
                        .long("tcp-port")
                        .value_name("TCP_PORT")
                        .takes_value(true)
                        .required(true)
                        .help(
                            "The TCP port to be included in the ENR and used for application comms",
                        ),
                )
                .arg(
                    Arg::with_name("output-dir")
                        .long("output-dir")
                        .value_name("OUTPUT_DIRECTORY")
                        .takes_value(true)
                        .required(true)
                        .help("The directory in which to create the network dir"),
                )
                .arg(
                    Arg::with_name("genesis-fork-version")
                        .long("genesis-fork-version")
                        .value_name("HEX")
                        .takes_value(true)
                        .required(true)
                        .help(
                            "Used to avoid reply attacks between testnets. Recommended to set to
                              non-default.",
                        ),
                ),
        )
        .subcommand(
            SubCommand::with_name("insecure-validators")
                .about("Produces validator directories with INSECURE, deterministic keypairs.")
                .arg(
                    Arg::with_name("count")
                        .long("count")
                        .value_name("COUNT")
                        .takes_value(true)
                        .help("Produces validators in the range of 0..count."),
                )
                .arg(
                    Arg::with_name("validators-dir")
                        .long("validators-dir")
                        .value_name("VALIDATOR_DIR")
                        .takes_value(true)
                        .help("The directory for storing validators."),
                )
                .arg(
                    Arg::with_name("secrets-dir")
                        .long("secrets-dir")
                        .value_name("SECRETS_DIR")
                        .takes_value(true)
                        .help("The directory for storing secrets."),
                ),
        )
        .get_matches();

    let result = matches
        .value_of("spec")
        .ok_or_else(|| "Missing --spec flag".to_string())
        .and_then(FromStr::from_str)
        .and_then(|eth_spec_id| match eth_spec_id {
            EthSpecId::Minimal => run(EnvironmentBuilder::minimal(), &matches),
            EthSpecId::Mainnet => run(EnvironmentBuilder::mainnet(), &matches),
            EthSpecId::V012Legacy => run(EnvironmentBuilder::v012_legacy(), &matches),
        });

    match result {
        Ok(()) => process::exit(0),
        Err(e) => {
            println!("Failed to run lcli: {}", e);
            process::exit(1)
        }
    }
}

fn run<T: EthSpec>(
    env_builder: EnvironmentBuilder<T>,
    matches: &ArgMatches<'_>,
) -> Result<(), String> {
    let env = env_builder
        .multi_threaded_tokio_runtime()
        .map_err(|e| format!("should start tokio runtime: {:?}", e))?
        .async_logger("trace", None)
        .map_err(|e| format!("should start null logger: {:?}", e))?
        .build()
        .map_err(|e| format!("should build env: {:?}", e))?;

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
            Ok(())
        }
        ("transition-blocks", Some(matches)) => run_transition_blocks::<T>(matches)
            .map_err(|e| format!("Failed to transition blocks: {}", e)),
        ("skip-slots", Some(matches)) => {
            skip_slots::run::<T>(matches).map_err(|e| format!("Failed to skip slots: {}", e))
        }
        ("pretty-hex", Some(matches)) => {
            run_parse_hex::<T>(matches).map_err(|e| format!("Failed to pretty print hex: {}", e))
        }
        ("eth1-genesis", Some(matches)) => eth1_genesis::run::<T>(env, matches)
            .map_err(|e| format!("Failed to run eth1-genesis command: {}", e)),
        ("interop-genesis", Some(matches)) => interop_genesis::run::<T>(env, matches)
            .map_err(|e| format!("Failed to run interop-genesis command: {}", e)),
        ("change-genesis-time", Some(matches)) => change_genesis_time::run::<T>(matches)
            .map_err(|e| format!("Failed to run change-genesis-time command: {}", e)),
        ("replace-state-pubkeys", Some(matches)) => replace_state_pubkeys::run::<T>(matches)
            .map_err(|e| format!("Failed to run replace-state-pubkeys command: {}", e)),
        ("new-testnet", Some(matches)) => new_testnet::run::<T>(matches)
            .map_err(|e| format!("Failed to run new_testnet command: {}", e)),
        ("check-deposit-data", Some(matches)) => check_deposit_data::run::<T>(matches)
            .map_err(|e| format!("Failed to run check-deposit-data command: {}", e)),
        ("generate-bootnode-enr", Some(matches)) => generate_bootnode_enr::run::<T>(matches)
            .map_err(|e| format!("Failed to run generate-bootnode-enr command: {}", e)),
        ("insecure-validators", Some(matches)) => insecure_validators::run(matches)
            .map_err(|e| format!("Failed to run insecure-validators command: {}", e)),
        (other, _) => Err(format!("Unknown subcommand {}. See --help.", other)),
    }
}

/// Creates a genesis state and writes it to a YAML file.
fn genesis_yaml<T: EthSpec>(validator_count: usize, genesis_time: u64, output: PathBuf) {
    let spec = &T::default_spec();

    let builder: TestingBeaconStateBuilder<T> =
        TestingBeaconStateBuilder::from_deterministic_keypairs(validator_count, spec);

    let (mut state, _keypairs) = builder.build();
    state.genesis_time = genesis_time;

    info!("Generated state root: {:?}", state.canonical_root());

    info!("Writing genesis state to {:?}", output);

    let file = File::create(output.clone())
        .unwrap_or_else(|e| panic!("unable to create file: {:?}. Error: {:?}", output, e));
    serde_yaml::to_writer(file, &state).expect("should be able to serialize BeaconState");
}
