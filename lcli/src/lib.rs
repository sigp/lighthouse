#[macro_use]
extern crate log;

use crate::parse_ssz::run_parse_ssz;
use crate::transition_blocks::run_transition_blocks;
use clap::{App, Arg, ArgMatches};
use clap_utils::lcli_flags::*;
use clap_utils::{parse_path_with_default_in_home_dir, parse_required};
use environment::{EnvironmentBuilder, LoggerConfig};
use std::path::PathBuf;
use types::{EthSpec, EthSpecId};

pub mod change_genesis_time;
pub mod check_deposit_data;
pub mod create_payload_header;
pub mod deploy_deposit_contract;
pub mod eth1_genesis;
pub mod etl;
pub mod generate_bootnode_enr;
pub mod insecure_validators;
pub mod interop_genesis;
pub mod new_testnet;
pub mod parse_ssz;
pub mod replace_state_pubkeys;
pub mod skip_slots;
pub mod transition_blocks;

pub fn new_app<'a>() -> App<'a> {
    App::new("Lighthouse CLI Tool")
        .version(lighthouse_version::VERSION)
        .about("Performs various testing-related tasks, including defining testnets.")
        .arg(
            Arg::new(SPEC_FLAG)
                .short('s')
                .long(SPEC_FLAG)
                .value_name("STRING")
                .takes_value(true)
                .required(true)
                .possible_values(&["minimal", "mainnet"])
                .default_value("mainnet")
                .global(true),
        )
        .arg(
            Arg::new(TESTNET_DIR_FLAG)
                .short('d')
                .long(TESTNET_DIR_FLAG)
                .value_name("PATH")
                .takes_value(true)
                .global(true)
                .help("The testnet dir. Defaults to ~/.lighthouse/testnet"),
        )
        .subcommand(
            App::new(SKIP_SLOTS_CMD)
                .about(
                    "Performs a state transition from some state across some number of skip slots",
                )
                .arg(
                    Arg::new(PRE_STATE_FLAG)
                        .value_name("BEACON_STATE")
                        .takes_value(true)
                        .required(true)
                        .help("Path to a SSZ file of the pre-state."),
                )
                .arg(
                    Arg::new(SLOTS_FLAG)
                        .value_name("SLOT_COUNT")
                        .takes_value(true)
                        .required(true)
                        .help("Number of slots to skip before outputting a state.."),
                )
                .arg(
                    Arg::new(OUTPUT_FLAG)
                                        .value_name("SSZ_FILE")
                        .takes_value(true)
                        .required(true)
                        .default_value("./output.ssz")
                        .help("Path to output a SSZ file."),
                ),
        )
        .subcommand(
            App::new(TRANSITION_BLOCKS_CMD)
                .about("Performs a state transition given a pre-state and block")
                .arg(
                    Arg::new(PRE_STATE_FLAG)
                        .value_name("BEACON_STATE")
                        .takes_value(true)
                        .required(true)
                        .help("Path to a SSZ file of the pre-state."),
                )
                .arg(
                    Arg::new(BLOCK_FLAG)
                        .value_name("BEACON_BLOCK")                        .takes_value(true)
                        .required(true)
                        .help("Path to a SSZ file of the block to apply to pre-state."),
                )
                .arg(
                    Arg::new(OUTPUT_FLAG)
                        .value_name("SSZ_FILE")                        .takes_value(true)
                        .required(true)
                        .default_value("./output.ssz")
                        .help("Path to output a SSZ file."),
                ),
        )
        .subcommand(
            App::new(PRETTY_SSZ_CMD)
                .about("Parses SSZ-encoded data from a file")
                .arg(
                    Arg::new(FORMAT_FLAG)
                        .short('f')                        .long("format")
                        .value_name("FORMAT")
                        .takes_value(true)
                        .required(true)
                        .default_value("json")
                        .possible_values(&["json", "yaml"])
                        .help("Output format to use")
                )
                .arg(
                    Arg::new(TYPE_FLAG)
                        .value_name("TYPE")                        .takes_value(true)
                        .required(true)
                        .help("Type to decode")
                        .possible_values(&["signed_block_base",
                                         "signed_block_altair",
                                         "block_base",
                                         "block_altair",
                                         "state_base",
                                         "state_altair"]),
                )
                .arg(
                    Arg::new(SSZ_FILE_FLAG)
                        .value_name("FILE")                        .takes_value(true)
                        .required(true)
                        .help("Path to SSZ bytes"),
                )
        )
        .subcommand(
            App::new(DEPLOY_DEPOSIT_CONTRACT_CMD)
                .about(
                    "Deploy a testing eth1 deposit contract.",
                )
                .arg(
                    Arg::new(ETH1_HTTP_FLAG)
                        .long(ETH1_HTTP_FLAG)
                        .short('e')
                        .value_name("ETH1_HTTP_PATH")
                        .help("Path to an Eth1 JSON-RPC IPC endpoint")
                        .takes_value(true)
                        .required(true)
                )
                .arg(
                    Arg::new(CONFIRMATIONS_FLAG)
                        .value_name("INTEGER")                        .long(CONFIRMATIONS_FLAG)
                        .takes_value(true)
                        .default_value("3")
                        .help("The number of block confirmations before declaring the contract deployed."),
                )
                .arg(
                    Arg::new(VALIDATOR_COUNT_FLAG)
                        .value_name("VALIDATOR_COUNT")                        .long(VALIDATOR_COUNT_FLAG)
                        .takes_value(true)
                        .help("If present, makes `validator_count` number of INSECURE deterministic deposits after \
                                deploying the deposit contract."
                        ),
                )
        )
        .subcommand(
            App::new(ETH1_GENESIS_CMD)
                .about("Listens to the eth1 chain and finds the genesis beacon state")
                .arg(
                    Arg::new(ETH1_ENDPOINT_FLAG)
                        .short('e')                        .long(ETH1_ENDPOINT_FLAG)
                        .value_name("HTTP_SERVER")
                        .takes_value(true)
                        .help("Deprecated. Use --eth1-endpoints."),
                )
                .arg(
                    Arg::new(ETH1_ENDPOINTS_FLAG)
                        .long(ETH1_ENDPOINTS_FLAG)
                        .value_name("HTTP_SERVER_LIST")
                        .takes_value(true)
                        .conflicts_with(ETH1_ENDPOINT_FLAG)
                        .help(
                            "One or more comma-delimited URLs to eth1 JSON-RPC http APIs. \
                                If multiple endpoints are given the endpoints are used as \
                                fallback in the given order.",
                        ),
                ),
        )
        .subcommand(
            App::new(INTEROP_GENESIS_CMD)
                .about("Produces an interop-compatible genesis state using deterministic keypairs")
                .arg(
                    Arg::new(VALIDATOR_COUNT_FLAG)
                        .long(VALIDATOR_COUNT_FLAG)
                        .index(1)
                        .value_name("INTEGER")
                        .takes_value(true)
                        .default_value("1024")
                        .help("The number of validators in the genesis state."),
                )
                .arg(
                    Arg::new(GENESIS_TIME_FLAG)
                        .long(GENESIS_TIME_FLAG)
                        .short('t')
                        .value_name("UNIX_EPOCH")
                        .takes_value(true)
                        .help("The value for state.genesis_time. Defaults to now."),
                )
                .arg(
                    Arg::new(GENESIS_FORK_VERSION_FLAG)
                        .long(GENESIS_FORK_VERSION_FLAG)
                        .value_name("HEX")
                        .takes_value(true)
                        .help(
                            "Used to avoid reply attacks between testnets. Recommended to set to
                              non-default.",
                        ),
                ),
        )
        .subcommand(
            App::new(CHANGE_GENESIS_TIME_CMD)
                .about(
                    "Loads a file with an SSZ-encoded BeaconState and modifies the genesis time.",
                )
                .arg(
                    Arg::new(SSZ_STATE_FLAG)
                        .index(1)                        .value_name("PATH")
                        .takes_value(true)
                        .required(true)
                        .help("The path to the SSZ file"),
                )
                .arg(
                    Arg::new(GENESIS_TIME_FLAG)
                        .index(2)                        .value_name("UNIX_EPOCH")
                        .takes_value(true)
                        .required(true)
                        .help("The value for state.genesis_time."),
                ),
        )
        .subcommand(
            App::new(REPLACE_STATE_PUBKEYS_CMD)
                .about(
                    "Loads a file with an SSZ-encoded BeaconState and replaces \
                    all the validator pubkeys with ones derived from the mnemonic \
                    such that validator indices correspond to EIP-2334 voting keypair \
                    derivation paths.",
                )
                .arg(
                    Arg::new(SSZ_STATE_FLAG)
                        .index(1)                        .value_name("PATH")
                        .takes_value(true)
                        .required(true)
                        .help("The path to the SSZ file"),
                )
                .arg(
                    Arg::new(MNEMONIC_FLAG)
                        .index(2)                        .value_name("BIP39_MNENMONIC")
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
            App::new(CREATE_PAYLOAD_HEADER_CMD)
                .about("Generates an SSZ file containing bytes for an `ExecutionPayloadHeader`. \
                Useful as input for `lcli new-testnet --execution-payload-header FILE`. ")
                .arg(
                    Arg::new(EXECUTION_BLOCK_HASH_FLAG)
                        .long(EXECUTION_BLOCK_HASH_FLAG)
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
                    Arg::new(GENESIS_TIME_FLAG)
                        .long(GENESIS_TIME_FLAG)
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The genesis time when generating an execution payload.")
                )
                .arg(
                    Arg::new(BASE_FEE_PER_GAS_FLAG)
                        .long(BASE_FEE_PER_GAS_FLAG)
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The base fee per gas field in the execution payload generated.")
                        .required(true)
                        .default_value("1000000000"),
                )
                .arg(
                    Arg::new(GAS_LIMIT_FLAG)
                        .long(GAS_LIMIT_FLAG)
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The gas limit field in the execution payload generated.")
                        .required(true)
                        .default_value("30000000"),
                )
                .arg(
                    Arg::new(FILE_FLAG)
                        .long(FILE_FLAG)
                        .value_name("FILE")
                        .takes_value(true)
                        .required(true)
                        .help("Output file"),
                )
        )
        .subcommand(
            App::new(NEW_TESTNET_CMD)
                .about(
                    "Produce a new testnet directory. If any of the optional flags are not
                    supplied the values will remain the default for the --spec flag",
                )
                .arg(
                    Arg::new(FORCE_FLAG)
                        .long(FORCE_FLAG)
                        .short('f')
                        .takes_value(false)
                        .help("Overwrites any previous testnet configurations"),
                )
                .arg(
                    Arg::new(INTEROP_GENESIS_STATE_FLAG)
                        .long(INTEROP_GENESIS_STATE_FLAG)
                        .takes_value(false)
                        .help(
                            "If present, a interop-style genesis.ssz file will be generated.",
                        ),
                )
                .arg(
                    Arg::new(MIN_GENESIS_TIME_FLAG)
                        .long(MIN_GENESIS_TIME_FLAG)
                        .value_name("UNIX_SECONDS")
                        .takes_value(true)
                        .help(
                            "The minimum permitted genesis time. For non-eth1 testnets will be
                              the genesis time. Defaults to now.",
                        ),
                )
                .arg(
                    Arg::new(MIN_GENESIS_ACTIVE_VALIDATOR_COUNT_FLAG)
                        .long(MIN_GENESIS_ACTIVE_VALIDATOR_COUNT_FLAG)
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The number of validators required to trigger eth2 genesis."),
                )
                .arg(
                    Arg::new(GENESIS_DELAY_FLAG)
                        .long(GENESIS_DELAY_FLAG)
                        .value_name("SECONDS")
                        .takes_value(true)
                        .help("The delay between sufficient eth1 deposits and eth2 genesis."),
                )
                .arg(
                    Arg::new(MIN_DEPOSIT_AMOUNT_FLAG)
                        .long(MIN_DEPOSIT_AMOUNT_FLAG)
                        .value_name("GWEI")
                        .takes_value(true)
                        .help("The minimum permitted deposit amount."),
                )
                .arg(
                    Arg::new(MAX_EFFECTIVE_BALANCE_FLAG)
                        .long(MAX_EFFECTIVE_BALANCE_FLAG)
                        .value_name("GWEI")
                        .takes_value(true)
                        .help("The amount required to become a validator."),
                )
                .arg(
                    Arg::new(EFFECTIVE_BALANCE_INCREMENT_FLAG)
                        .long(EFFECTIVE_BALANCE_INCREMENT_FLAG)
                        .value_name("GWEI")
                        .takes_value(true)
                        .help("The steps in effective balance calculation."),
                )
                .arg(
                    Arg::new(EJECTION_BALANCE_FLAG)
                        .long(EJECTION_BALANCE_FLAG)
                        .value_name("GWEI")
                        .takes_value(true)
                        .help("The balance at which a validator gets ejected."),
                )
                .arg(
                    Arg::new(ETH1_FOLLOW_DISTANCE_FLAG)
                        .long(ETH1_FOLLOW_DISTANCE_FLAG)
                        .value_name("ETH1_BLOCKS")
                        .takes_value(true)
                        .help("The distance to follow behind the eth1 chain head."),
                )
                .arg(
                    Arg::new(GENESIS_FORK_VERSION_FLAG)
                        .long(GENESIS_FORK_VERSION_FLAG)
                        .value_name("HEX")
                        .takes_value(true)
                        .help(
                            "Used to avoid reply attacks between testnets. Recommended to set to
                              non-default.",
                        ),
                )
                .arg(
                    Arg::new(SECONDS_PER_SLOT_FLAG)
                        .long(SECONDS_PER_SLOT_FLAG)
                        .value_name("SECONDS")
                        .takes_value(true)
                        .help("Eth2 slot time"),
                )
                .arg(
                    Arg::new(SECONDS_PER_ETH1_BLOCK_FLAG)
                        .long(SECONDS_PER_ETH1_BLOCK_FLAG)
                        .value_name("SECONDS")
                        .takes_value(true)
                        .help("Eth1 block time"),
                )
                .arg(
                    Arg::new(ETH1_ID_FLAG)
                        .long(ETH1_ID_FLAG)
                        .value_name("ETH1_ID")
                        .takes_value(true)
                        .help("The chain id and network id for the eth1 testnet."),
                )
                .arg(
                    Arg::new(DEPOSIT_CONTRACT_ADDRESS_FLAG)
                        .long(DEPOSIT_CONTRACT_ADDRESS_FLAG)
                        .value_name("ETH1_ADDRESS")
                        .takes_value(true)
                        .required(true)
                        .help("The address of the deposit contract."),
                )
                .arg(
                    Arg::new(DEPOSIT_CONTRACT_DEPLOY_BLOCK_FLAG)
                        .long(DEPOSIT_CONTRACT_DEPLOY_BLOCK_FLAG)
                        .value_name("ETH1_BLOCK_NUMBER")
                        .takes_value(true)
                        .default_value("0")
                        .help(
                            "The block the deposit contract was deployed. Setting this is a huge
                              optimization for nodes, please do it.",
                        ),
                )
                .arg(
                    Arg::new(ALTAIR_FORK_EPOCH_FLAG)
                        .long(ALTAIR_FORK_EPOCH_FLAG)
                        .value_name("EPOCH")
                        .takes_value(true)
                        .help(
                            "The epoch at which to enable the Altair hard fork",
                        ),
                )
                .arg(
                    Arg::new(MERGE_FORK_EPOCH_FLAG)
                        .long(MERGE_FORK_EPOCH_FLAG)
                        .value_name("EPOCH")
                        .takes_value(true)
                        .help(
                            "The epoch at which to enable the Merge hard fork",
                        ),
                )
                .arg(
                    Arg::new(ETH1_BLOCK_HASH_FLAG)
                        .long(ETH1_BLOCK_HASH_FLAG)
                        .value_name("BLOCK_HASH")
                        .takes_value(true)
                        .help("The eth1 block hash used when generating a genesis state."),
                )
                .arg(
                    Arg::new(EXECUTION_PAYLOAD_HEADER_FLAG)
                        .long(EXECUTION_PAYLOAD_HEADER_FLAG)
                        .value_name("FILE")
                        .takes_value(true)
                        .required(false)
                        .help("Path to file containing `ExecutionPayloadHeader` SSZ bytes to be \
                            used in the genesis state."),
                )
                .arg(
                    Arg::new(VALIDATOR_COUNT_FLAG)
                        .long(VALIDATOR_COUNT_FLAG)
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The number of validators when generating a genesis state."),
                )
                .arg(
                    Arg::new(GENESIS_TIME_FLAG)
                        .long(GENESIS_TIME_FLAG)
                        .value_name("INTEGER")
                        .takes_value(true)
                        .help("The genesis time when generating a genesis state."),
                )
                .arg(
                    Arg::new(BOOT_ADDRESS_FLAG)
                        .long(BOOT_ADDRESS_FLAG)
                        .value_name("IP-ADDRESS")
                        .takes_value(true)
                        .required(false)
                        .requires(BOOT_DIR_FLAG)
                        .help("A boot node ENR will be generated for the provided IP address and \
                            added to the `boot_enr.yaml` file. Example: 127.0.0.1:7000"),
                )
                .arg(
                    Arg::new(BOOT_DIR_FLAG)
                        .long(BOOT_DIR_FLAG)
                        .value_name("PATH")
                        .takes_value(true)
                        .required(false)
                        .requires(BOOT_ADDRESS_FLAG)
                        .help("The output directory of the generated boot node files."),
                )
        )
        .subcommand(
            App::new(CHECK_DEPOSIT_DATA_CMD)
                .about("Checks the integrity of some deposit data.")
                .arg(
                    Arg::new(DEPOSIT_AMOUNT_FLAG)
                        .index(1)                        .value_name("GWEI")
                        .takes_value(true)
                        .required(true)
                        .help("The amount (in Gwei) that was deposited"),
                )
                .arg(
                    Arg::new(DEPOSIT_DATA_FLAG)
                        .index(2)                        .value_name("HEX")
                        .takes_value(true)
                        .required(true)
                        .help(
                            "A 0x-prefixed hex string of the deposit data. Should include the
                            function signature.",
                        ),
                ),
        )
        .subcommand(
            App::new(GENERATE_BOOTNODE_ENR_CMD)
                .about("Generates an ENR address to be used as a pre-genesis boot node.")
                .arg(
                    Arg::new(IP_FLAG)
                        .long(IP_FLAG)
                        .value_name("IP_ADDRESS")
                        .takes_value(true)
                        .required(true)
                        .help("The IP address to be included in the ENR and used for discovery"),
                )
                .arg(
                    Arg::new(UDP_PORT_FLAG)
                        .long(UDP_PORT_FLAG)
                        .value_name("UDP_PORT")
                        .takes_value(true)
                        .required(true)
                        .help("The UDP port to be included in the ENR and used for discovery"),
                )
                .arg(
                    Arg::new(TCP_PORT_FLAG)
                        .long(TCP_PORT_FLAG)
                        .value_name("TCP_PORT")
                        .takes_value(true)
                        .required(true)
                        .help(
                            "The TCP port to be included in the ENR and used for application comms",
                        ),
                )
                .arg(
                    Arg::new(OUTPUT_DIR_FLAG)
                        .long(OUTPUT_DIR_FLAG)
                        .value_name("OUTPUT_DIRECTORY")
                        .takes_value(true)
                        .required(true)
                        .help("The directory in which to create the network dir"),
                )
                .arg(
                    Arg::new(GENESIS_FORK_VERSION_FLAG)
                        .long(GENESIS_FORK_VERSION_FLAG)
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
            App::new(INSECURE_VALIDATORS_CMD)
                .about("Produces validator directories with INSECURE, deterministic keypairs.")
                .arg(
                    Arg::new(COUNT_FLAG)
                        .long(COUNT_FLAG)
                        .value_name("COUNT")
                        .takes_value(true)
                        .help("Produces validators in the range of 0..count."),
                )
                .arg(
                    Arg::new(BASE_DIR_FLAG)
                        .long(BASE_DIR_FLAG)
                        .value_name("BASE_DIR")
                        .takes_value(true)
                        .help("The base directory where validator keypairs and secrets are stored"),
                )
                .arg(
                    Arg::new(NODE_COUNT_FLAG)
                        .long(NODE_COUNT_FLAG)
                        .value_name("NODE_COUNT")
                        .takes_value(true)
                        .help("The number of nodes to divide the validator keys to"),
                )
        )
        .subcommand(
            App::new(ETL_BLOCK_EFFICIENCY_CMD)
                .about(
                    "Performs ETL analysis of block efficiency. Requires a Beacon Node API to \
                    extract data from.",
                )
                .arg(
                    Arg::new(ENDPOINT_FLAG)
                        .long(ENDPOINT_FLAG)
                        .short('e')
                        .takes_value(true)
                        .default_value("http://localhost:5052")
                        .help(
                            "The endpoint of the Beacon Node API."
                        ),
                )
                .arg(
                    Arg::new(OUTPUT_FLAG)
                        .long(OUTPUT_FLAG)
                        .short('o')
                        .takes_value(true)
                        .help("The path of the output data in CSV file.")
                        .required(true),
                )
                .arg(
                    Arg::new(START_EPOCH_FLAG)
                        .long(START_EPOCH_FLAG)
                        .takes_value(true)
                        .help(
                            "The first epoch in the range of epochs to be evaluated. Use with \
                            --end-epoch.",
                        )
                        .required(true),
                )
                .arg(
                    Arg::new(END_EPOCH_FLAG)
                        .long(END_EPOCH_FLAG)
                        .takes_value(true)
                        .help(
                            "The last epoch in the range of epochs to be evaluated. Use with \
                            --start-epoch.",
                        )
                        .required(true),
                )
                .arg(
                    Arg::new(OFFLINE_WINDOW_FLAG)
                        .long(OFFLINE_WINDOW_FLAG)
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
pub fn run(matches: &ArgMatches) -> Result<(), String> {
    parse_required::<EthSpecId>(matches, SPEC_FLAG).and_then(|eth_spec_id| match eth_spec_id {
        EthSpecId::Minimal => run_with_env(EnvironmentBuilder::minimal(), matches),
        EthSpecId::Mainnet => run_with_env(EnvironmentBuilder::mainnet(), matches),
    })
}

fn run_with_env<T: EthSpec>(
    env_builder: EnvironmentBuilder<T>,
    matches: &ArgMatches,
) -> Result<(), String> {
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
        TESTNET_DIR_FLAG,
        PathBuf::from(directory::DEFAULT_ROOT_DIR).join("testnet"),
    )?;

    match matches.subcommand() {
        Some((TRANSITION_BLOCKS_CMD, matches)) => run_transition_blocks::<T>(testnet_dir, matches)
            .map_err(|e| format!("Failed to transition blocks: {}", e)),
        Some((SKIP_SLOTS_CMD, matches)) => skip_slots::run::<T>(testnet_dir, matches)
            .map_err(|e| format!("Failed to skip slots: {}", e)),
        Some((PRETTY_SSZ_CMD, matches)) => {
            run_parse_ssz::<T>(matches).map_err(|e| format!("Failed to pretty print hex: {}", e))
        }
        Some((DEPLOY_DEPOSIT_CONTRACT_CMD, matches)) => {
            deploy_deposit_contract::run::<T>(env, matches)
                .map_err(|e| format!("Failed to run deploy-deposit-contract command: {}", e))
        }
        Some((ETH1_GENESIS_CMD, matches)) => eth1_genesis::run::<T>(env, testnet_dir, matches)
            .map_err(|e| format!("Failed to run eth1-genesis command: {}", e)),
        Some((INTEROP_GENESIS_CMD, matches)) => interop_genesis::run::<T>(testnet_dir, matches)
            .map_err(|e| format!("Failed to run interop-genesis command: {}", e)),
        Some((CHANGE_GENESIS_TIME_CMD, matches)) => {
            change_genesis_time::run::<T>(testnet_dir, matches)
                .map_err(|e| format!("Failed to run change-genesis-time command: {}", e))
        }
        Some((CREATE_PAYLOAD_HEADER_CMD, matches)) => create_payload_header::run::<T>(matches)
            .map_err(|e| format!("Failed to run create-payload-header command: {}", e)),
        Some((REPLACE_STATE_PUBKEYS_CMD, matches)) => {
            replace_state_pubkeys::run::<T>(testnet_dir, matches)
                .map_err(|e| format!("Failed to run replace-state-pubkeys command: {}", e))
        }
        Some((NEW_TESTNET_CMD, matches)) => new_testnet::run::<T>(testnet_dir, matches)
            .map_err(|e| format!("Failed to run new-testnet command: {}", e)),
        Some((CHECK_DEPOSIT_DATA_CMD, matches)) => check_deposit_data::run::<T>(matches)
            .map_err(|e| format!("Failed to run check-deposit-data command: {}", e)),
        Some((GENERATE_BOOTNODE_ENR_CMD, matches)) => generate_bootnode_enr::run::<T>(matches)
            .map_err(|e| format!("Failed to run generate-bootnode-enr command: {}", e)),
        Some((INSECURE_VALIDATORS_CMD, matches)) => insecure_validators::run(matches)
            .map_err(|e| format!("Failed to run insecure-validators command: {}", e)),
        Some((ETL_BLOCK_EFFICIENCY_CMD, matches)) => env
            .runtime()
            .block_on(etl::block_efficiency::run::<T>(matches))
            .map_err(|e| format!("Failed to run etl-block_efficiency: {}", e)),
        Some((other, _)) => Err(format!("Unknown subcommand {}. See --help.", other)),
        None => Err("No subcommand. See --help".to_string()),
    }
}
