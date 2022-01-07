#[macro_use]
extern crate log;

use std::collections::HashMap;
use clap::{Arg, ArgMatches};
use clap_utils::{DefaultConfigApp as App, parse_path_with_default_in_home_dir, parse_required};
use environment::{EnvironmentBuilder, LoggerConfig};
use std::path::PathBuf;
use types::{EthSpec, EthSpecId};
use crate::parse_ssz::run_parse_ssz;
use crate::transition_blocks::run_transition_blocks;

pub mod change_genesis_time;
pub mod check_deposit_data;
pub mod create_payload_header;
pub mod deploy_deposit_contract;
pub mod etl;
pub mod eth1_genesis;
pub mod generate_bootnode_enr;
pub mod insecure_validators;
pub mod interop_genesis;
pub mod new_testnet;
pub mod parse_ssz;
pub mod replace_state_pubkeys;
pub mod skip_slots;
pub mod transition_blocks;

pub fn new_app<'a>(default_config: Option<&'a HashMap<&'a str, &'a str>>,) -> App<'a> {
    App::new("Lighthouse CLI Tool", default_config)
        .version(lighthouse_version::VERSION)
        .about("Performs various testing-related tasks, including defining testnets.")
        .arg(
            Arg::new("spec")
                .short('s')
                .long("spec")
                .value_name("STRING")
                .takes_value(true)
                .required(true)
                .possible_values(&["minimal", "mainnet"])
                .default_value("mainnet")
                .global(true),
        )
        .arg(
            Arg::new("testnet-dir")
                .short('d')
                .long("testnet-dir")
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("The testnet dir. Defaults to ~/.lighthouse/testnet"),
        )
        .subcommand(
            App::new("skip-slots", default_config)
                .about(
                    "Performs a state transition from some state across some number of skip slots",
                )
                .arg(
                    Arg::new("pre-state")
                        .value_name("BEACON_STATE")
                        .takes_value(true)
                        .required(true)
                        .help("Path to a SSZ file of the pre-state."),
                )
                .arg(
                    Arg::new("slots")
                        .value_name("SLOT_COUNT")
                        .takes_value(true)
                        .required(true)
                        .help("Number of slots to skip before outputting a state.."),
                )
                .arg(
                    Arg::new("output")
                        .value_name("SSZ_FILE")
                        .takes_value(true)
                        .required(true)
                        .default_value("./output.ssz")
                        .help("Path to output a SSZ file."),
                ),
        )
        .subcommand(
            App::new("transition-blocks", default_config)
                .about("Performs a state transition given a pre-state and block")
                .arg(
                    Arg::new("pre-state")
                        .value_name("BEACON_STATE")
                        .takes_value(true)
                        .required(true)
                        .help("Path to a SSZ file of the pre-state."),
                )
                .arg(
                    Arg::new("block")
                        .value_name("BEACON_BLOCK")
                        .takes_value(true)
                        .required(true)
                        .help("Path to a SSZ file of the block to apply to pre-state."),
                )
                .arg(
                    Arg::new("output")
                        .value_name("SSZ_FILE")
                        .takes_value(true)
                        .required(true)
                        .default_value("./output.ssz")
                        .help("Path to output a SSZ file."),
                ),
        )
        .subcommand(
            App::new("pretty-ssz", default_config)
                .about("Parses SSZ-encoded data from a file")
                .arg(
                    Arg::new("format")
                        .short('f')
                        .long("format")
                        .value_name("FORMAT")
                        .takes_value(true)
                        .required(true)
                        .default_value("json")
                        .possible_values(&["json", "yaml"])
                        .help("Output format to use")
                )
                .arg(
                    Arg::new("type")
                        .value_name("TYPE")
                        .takes_value(true)
                        .required(true)
                        .help("Type to decode"),
                )
                .arg(
                    Arg::new("ssz-file")
                        .value_name("FILE")
                        .takes_value(true)
                        .required(true)
                        .help("Path to SSZ bytes"),
                )
        )
        .subcommand(
            App::new("deploy-deposit-contract", default_config)
                .about(
                    "Deploy a testing eth1 deposit contract.",
                )
                .arg(
                    Arg::new("eth1-http")
                        .long("eth1-http")
                        .short('e')
                        .value_name("ETH1_HTTP_PATH")
                        .help("Path to an Eth1 JSON-RPC IPC endpoint")
                        .takes_value(true)
                        .required(true)
                )
                .arg(
                    Arg::new("confirmations")
                        .value_name("INTEGER")
                        .long("confirmations")
                        .takes_value(true)
                        .default_value("3")
                        .help("The number of block confirmations before declaring the contract deployed."),
                )
                .arg(
                    Arg::new("validator-count")
                        .value_name("VALIDATOR_COUNT")
                        .long("validator-count")
                        .takes_value(true)
                        .help("If present, makes `validator_count` number of INSECURE deterministic deposits after \
                                deploying the deposit contract."
                        ),
                )
        )
        .subcommand(
            App::new("eth1-genesis", default_config)
                .about("Listens to the eth1 chain and finds the genesis beacon state")
                .arg(
                    Arg::new("eth1-endpoint")
                        .short('e')
                        .long("eth1-endpoint")
                        .value_name("HTTP_SERVER")
                        .takes_value(true)
                        .help("Deprecated. Use --eth1-endpoints."),
                )
                .arg(
                    Arg::new("eth1-endpoints")
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
            App::new("interop-genesis", default_config)
                .about("Produces an interop-compatible genesis state using deterministic keypairs")
                .arg(
                    Arg::new("validator-count")
                        .long("validator-count")
                        .index(1)
                        .value_name("INTEGER")
                        .takes_value(true)
                        .default_value("1024")
                        .help("The number of validators in the genesis state."),
                )
                .arg(
                    Arg::new("genesis-time")
                        .long("genesis-time")
                        .short('t')
                        .value_name("UNIX_EPOCH")
                        .takes_value(true)
                        .help("The value for state.genesis_time. Defaults to now."),
                )
                .arg(
                    Arg::new("genesis-fork-version")
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
            App::new("change-genesis-time", default_config)
                .about(
                    "Loads a file with an SSZ-encoded BeaconState and modifies the genesis time.",
                )
                .arg(
                    Arg::new("ssz-state")
                        .index(1)
                        .value_name("PATH")
                        .takes_value(true)
                        .required(true)
                        .help("The path to the SSZ file"),
                )
                .arg(
                    Arg::new("genesis-time")
                        .index(2)
                        .value_name("UNIX_EPOCH")
                        .takes_value(true)
                        .required(true)
                        .help("The value for state.genesis_time."),
                ),
        )
        .subcommand(
            App::new("replace-state-pubkeys", default_config)
                .about(
                    "Loads a file with an SSZ-encoded BeaconState and replaces \
                    all the validator pubkeys with ones derived from the mnemonic \
                    such that validator indices correspond to EIP-2334 voting keypair \
                    derivation paths.",
                )
                .arg(
                    Arg::new("ssz-state")
                        .index(1)
                        .value_name("PATH")
                        .takes_value(true)
                        .required(true)
                        .help("The path to the SSZ file"),
                )
                .arg(
                    Arg::new("mnemonic")
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
            App::new("create-payload-header", default_config)
                .about("Generates an SSZ file containing bytes for an `ExecutionPayloadHeader`. \
                Useful as input for `lcli new-testnet --execution-payload-header FILE`. ")
                .arg(
                    Arg::new("execution-block-hash")
                        .long("execution-block-hash")
                        .value_name("BLOCK_HASH")
                        .takes_value(true)
                        .help("The block hash used when generating an execution payload. This \
                            value is used for `execution_payload_header.block_hash` as well as \
                            `execution_payload_header.random`")
                        .required(true)
                        .default_value(
                            "0x0000000000000000000000000000000000000000000000000000000000000000",
                        ),
                )
                .arg(
                    Arg::new("genesis-time")
                        .long("genesis-time")
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The genesis time when generating an execution payload.")
                )
                .arg(
                    Arg::new("base-fee-per-gas")
                        .long("base-fee-per-gas")
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The base fee per gas field in the execution payload generated.")
                        .required(true)
                        .default_value("1000000000"),
                )
                .arg(
                    Arg::new("gas-limit")
                        .long("gas-limit")
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The gas limit field in the execution payload generated.")
                        .required(true)
                        .default_value("30000000"),
                )
                .arg(
                    Arg::new("file")
                        .long("file")
                        .value_name("FILE")
                        .takes_value(true)
                        .required(true)
                        .help("Output file"),
                )
        )
        .subcommand(
            App::new("new-testnet", default_config)
                .about(
                    "Produce a new testnet directory. If any of the optional flags are not
                    supplied the values will remain the default for the --spec flag",
                )
                .arg(
                    Arg::new("force")
                        .long("force")
                        .short('f')
                        .takes_value(false)
                        .help("Overwrites any previous testnet configurations"),
                )
                .arg(
                    Arg::new("interop-genesis-state")
                        .long("interop-genesis-state")
                        .takes_value(false)
                        .help(
                            "If present, a interop-style genesis.ssz file will be generated.",
                        ),
                )
                .arg(
                    Arg::new("min-genesis-time")
                        .long("min-genesis-time")
                        .value_name("UNIX_SECONDS")
                        .takes_value(true)
                        .help(
                            "The minimum permitted genesis time. For non-eth1 testnets will be
                              the genesis time. Defaults to now.",
                        ),
                )
                .arg(
                    Arg::new("min-genesis-active-validator-count")
                        .long("min-genesis-active-validator-count")
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The number of validators required to trigger eth2 genesis."),
                )
                .arg(
                    Arg::new("genesis-delay")
                        .long("genesis-delay")
                        .value_name("SECONDS")
                        .takes_value(true)
                        .help("The delay between sufficient eth1 deposits and eth2 genesis."),
                )
                .arg(
                    Arg::new("min-deposit-amount")
                        .long("min-deposit-amount")
                        .value_name("GWEI")
                        .takes_value(true)
                        .help("The minimum permitted deposit amount."),
                )
                .arg(
                    Arg::new("max-effective-balance")
                        .long("max-effective-balance")
                        .value_name("GWEI")
                        .takes_value(true)
                        .help("The amount required to become a validator."),
                )
                .arg(
                    Arg::new("effective-balance-increment")
                        .long("effective-balance-increment")
                        .value_name("GWEI")
                        .takes_value(true)
                        .help("The steps in effective balance calculation."),
                )
                .arg(
                    Arg::new("ejection-balance")
                        .long("ejection-balance")
                        .value_name("GWEI")
                        .takes_value(true)
                        .help("The balance at which a validator gets ejected."),
                )
                .arg(
                    Arg::new("eth1-follow-distance")
                        .long("eth1-follow-distance")
                        .value_name("ETH1_BLOCKS")
                        .takes_value(true)
                        .help("The distance to follow behind the eth1 chain head."),
                )
                .arg(
                    Arg::new("genesis-fork-version")
                        .long("genesis-fork-version")
                        .value_name("HEX")
                        .takes_value(true)
                        .help(
                            "Used to avoid reply attacks between testnets. Recommended to set to
                              non-default.",
                        ),
                )
                .arg(
                    Arg::new("seconds-per-slot")
                        .long("seconds-per-slot")
                        .value_name("SECONDS")
                        .takes_value(true)
                        .help("Eth2 slot time"),
                )
                .arg(
                    Arg::new("seconds-per-eth1-block")
                        .long("seconds-per-eth1-block")
                        .value_name("SECONDS")
                        .takes_value(true)
                        .help("Eth1 block time"),
                )
                .arg(
                    Arg::new("eth1-id")
                        .long("eth1-id")
                        .value_name("ETH1_ID")
                        .takes_value(true)
                        .help("The chain id and network id for the eth1 testnet."),
                )
                .arg(
                    Arg::new("deposit-contract-address")
                        .long("deposit-contract-address")
                        .value_name("ETH1_ADDRESS")
                        .takes_value(true)
                        .required(true)
                        .help("The address of the deposit contract."),
                )
                .arg(
                    Arg::new("deposit-contract-deploy-block")
                        .long("deposit-contract-deploy-block")
                        .value_name("ETH1_BLOCK_NUMBER")
                        .takes_value(true)
                        .default_value("0")
                        .help(
                            "The block the deposit contract was deployed. Setting this is a huge
                              optimization for nodes, please do it.",
                        ),
                )
                .arg(
                    Arg::new("altair-fork-epoch")
                        .long("altair-fork-epoch")
                        .value_name("EPOCH")
                        .takes_value(true)
                        .help(
                            "The epoch at which to enable the Altair hard fork",
                        ),
                )
                .arg(
                    Arg::new("merge-fork-epoch")
                        .long("merge-fork-epoch")
                        .value_name("EPOCH")
                        .takes_value(true)
                        .help(
                            "The epoch at which to enable the Merge hard fork",
                        ),
                )
                .arg(
                    Arg::new("eth1-block-hash")
                        .long("eth1-block-hash")
                        .value_name("BLOCK_HASH")
                        .takes_value(true)
                        .help("The eth1 block hash used when generating a genesis state."),
                )
                .arg(
                    Arg::new("execution-payload-header")
                        .long("execution-payload-header")
                        .value_name("FILE")
                        .takes_value(true)
                        .required(false)
                        .help("Path to file containing `ExecutionPayloadHeader` SSZ bytes to be \
                            used in the genesis state."),
                )
                .arg(
                    Arg::new("validator-count")
                        .long("validator-count")
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The number of validators when generating a genesis state."),
                )
                .arg(
                    Arg::new("genesis-time")
                        .long("genesis-time")
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The genesis time when generating a genesis state."),
                )
        )
        .subcommand(
            App::new("check-deposit-data", default_config)
                .about("Checks the integrity of some deposit data.")
                .arg(
                    Arg::new("deposit-amount")
                        .index(1)
                        .value_name("GWEI")
                        .takes_value(true)
                        .required(true)
                        .help("The amount (in Gwei) that was deposited"),
                )
                .arg(
                    Arg::new("deposit-data")
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
            App::new("generate-bootnode-enr", default_config)
                .about("Generates an ENR address to be used as a pre-genesis boot node.")
                .arg(
                    Arg::new("ip")
                        .long("ip")
                        .value_name("IP_ADDRESS")
                        .takes_value(true)
                        .required(true)
                        .help("The IP address to be included in the ENR and used for discovery"),
                )
                .arg(
                    Arg::new("udp-port")
                        .long("udp-port")
                        .value_name("UDP_PORT")
                        .takes_value(true)
                        .required(true)
                        .help("The UDP port to be included in the ENR and used for discovery"),
                )
                .arg(
                    Arg::new("tcp-port")
                        .long("tcp-port")
                        .value_name("TCP_PORT")
                        .takes_value(true)
                        .required(true)
                        .help(
                            "The TCP port to be included in the ENR and used for application comms",
                        ),
                )
                .arg(
                    Arg::new("output-dir")
                        .long("output-dir")
                        .value_name("OUTPUT_DIRECTORY")
                        .takes_value(true)
                        .required(true)
                        .help("The directory in which to create the network dir"),
                )
                .arg(
                    Arg::new("genesis-fork-version")
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
            App::new("insecure-validators", default_config)
                .about("Produces validator directories with INSECURE, deterministic keypairs.")
                .arg(
                    Arg::new("count")
                        .long("count")
                        .value_name("COUNT")
                        .takes_value(true)
                        .help("Produces validators in the range of 0..count."),
                )
                .arg(
                    Arg::new("base-dir")
                        .long("base-dir")
                        .value_name("BASE_DIR")
                        .takes_value(true)
                        .help("The base directory where validator keypairs and secrets are stored"),
                )
                .arg(
                    Arg::new("node-count")
                        .long("node-count")
                        .value_name("NODE_COUNT")
                        .takes_value(true)
                        .help("The number of nodes to divide the validator keys to"),
                )
        )
        .subcommand(
            App::new("etl-block-efficiency", default_config)
                .about(
                    "Performs ETL analysis of block efficiency. Requires a Beacon Node API to \
                    extract data from.",
                )
                .arg(
                    Arg::new("endpoint")
                        .long("endpoint")
                        .short('e')
                        .takes_value(true)
                        .default_value("http://localhost:5052")
                        .help(
                            "The endpoint of the Beacon Node API."
                        ),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .takes_value(true)
                        .help("The path of the output data in CSV file.")
                        .required(true),
                )
                .arg(
                    Arg::new("start-epoch")
                        .long("start-epoch")
                        .takes_value(true)
                        .help(
                            "The first epoch in the range of epochs to be evaluated. Use with \
                            --end-epoch.",
                        )
                        .required(true),
                )
                .arg(
                    Arg::new("end-epoch")
                        .long("end-epoch")
                        .takes_value(true)
                        .help(
                            "The last epoch in the range of epochs to be evaluated. Use with \
                            --start-epoch.",
                        )
                        .required(true),
                )
                .arg(
                    Arg::new("offline-window")
                        .long("offline-window")
                        .takes_value(true)
                        .default_value("3")
                        .help(
                            "If a validator does not submit an attestion within this many epochs, \
                            they are deemed offline. For example, for a offline window of 3, if a \
                            validator does not attest in epochs 4, 5 or 6, it is deemed offline \
                            during epoch 6. A value of 0 will skip these checks."
                        )
                )
        )
}
pub fn run(matches: &ArgMatches) -> Result<(),String> {
    parse_required::<EthSpecId>(&matches, "spec")
        .and_then(|eth_spec_id| match eth_spec_id {
            EthSpecId::Minimal => run_with_env(EnvironmentBuilder::minimal(), &matches),
            EthSpecId::Mainnet => run_with_env(EnvironmentBuilder::mainnet(), &matches),
        })
}

fn run_with_env<T: EthSpec>(env_builder: EnvironmentBuilder<T>, matches: &ArgMatches) -> Result<(), String> {
    let env = env_builder
        .multi_threaded_tokio_runtime()
        .map_err(|e| format!("should start tokio runtime: {:?}", e))?
        .initialize_logger(LoggerConfig {
            path: None,
            debug_level: "trace",
            logfile_debug_level: "trace",
            log_format: None,
            max_log_size: 0,
            max_log_number: 0,
            compression: false,
        })
        .map_err(|e| format!("should start logger: {:?}", e))?
        .build()
        .map_err(|e| format!("should build env: {:?}", e))?;

    let testnet_dir = parse_path_with_default_in_home_dir(
        matches,
        "testnet-dir",
        PathBuf::from(directory::DEFAULT_ROOT_DIR).join("testnet"),
    )?;

    match matches.subcommand() {
        Some(("transition-blocks", matches)) => run_transition_blocks::<T>(testnet_dir, matches)
            .map_err(|e| format!("Failed to transition blocks: {}", e)),
        Some(("skip-slots", matches)) => skip_slots::run::<T>(testnet_dir, matches)
            .map_err(|e| format!("Failed to skip slots: {}", e)),
        Some(("pretty-ssz", matches)) => {
            run_parse_ssz::<T>(matches).map_err(|e| format!("Failed to pretty print hex: {}", e))
        }
        Some(("deploy-deposit-contract", matches)) => {
            deploy_deposit_contract::run::<T>(env, matches)
                .map_err(|e| format!("Failed to run deploy-deposit-contract command: {}", e))
        }
        Some(("eth1-genesis", matches)) => eth1_genesis::run::<T>(env, testnet_dir, matches)
            .map_err(|e| format!("Failed to run eth1-genesis command: {}", e)),
        Some(("interop-genesis", matches)) => interop_genesis::run::<T>(testnet_dir, matches)
            .map_err(|e| format!("Failed to run interop-genesis command: {}", e)),
        Some(("change-genesis-time", matches)) => {
            change_genesis_time::run::<T>(testnet_dir, matches)
                .map_err(|e| format!("Failed to run change-genesis-time command: {}", e))
        }
        Some(("create-payload-header", matches)) => create_payload_header::run::<T>(matches)
            .map_err(|e| format!("Failed to run create-payload-header command: {}", e)),
        Some(("replace-state-pubkeys", matches)) => {
            replace_state_pubkeys::run::<T>(testnet_dir, matches)
                .map_err(|e| format!("Failed to run replace-state-pubkeys command: {}", e))
        }
        Some(("new-testnet", matches)) => new_testnet::run::<T>(testnet_dir, matches)
            .map_err(|e| format!("Failed to run new_testnet command: {}", e)),
        Some(("check-deposit-data", matches)) => check_deposit_data::run::<T>(matches)
            .map_err(|e| format!("Failed to run check-deposit-data command: {}", e)),
        Some(("generate-bootnode-enr", matches)) => generate_bootnode_enr::run::<T>(matches)
            .map_err(|e| format!("Failed to run generate-bootnode-enr command: {}", e)),
        Some(("insecure-validators", matches)) => insecure_validators::run(matches)
            .map_err(|e| format!("Failed to run insecure-validators command: {}", e)),
        Some(("etl-block-efficiency", matches)) => env
            .runtime()
            .block_on(etl::block_efficiency::run::<T>(matches))
            .map_err(|e| format!("Failed to run etl-block_efficiency: {}", e)),
        Some((other, _)) => Err(format!("Unknown subcommand {}. See --help.", other)),
        None => Err("No subcommand. See --help".to_string()),
    }
}