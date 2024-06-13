mod block_root;
mod check_deposit_data;
mod generate_bootnode_enr;
mod indexed_attestations;
mod mnemonic_validators;
mod mock_el;
mod parse_ssz;
mod skip_slots;
mod state_root;
mod transition_blocks;

use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_utils::{parse_optional, FLAG_HEADER};
use environment::{EnvironmentBuilder, LoggerConfig};
use eth2_network_config::Eth2NetworkConfig;
use parse_ssz::run_parse_ssz;
use std::path::PathBuf;
use std::process;
use std::str::FromStr;
use types::{EthSpec, EthSpecId};

fn main() {
    env_logger::init();

    let matches = Command::new("Lighthouse CLI Tool")
        .version(lighthouse_version::VERSION)
        .display_order(0)
        .about("Performs various testing-related tasks, including defining testnets.")
        .arg(
            Arg::new("spec")
                .short('s')
                .long("spec")
                .value_name("STRING")
                .action(ArgAction::Set)
                .value_parser(["minimal", "mainnet", "gnosis"])
                .default_value("mainnet")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("testnet-dir")
                .short('d')
                .long("testnet-dir")
                .value_name("PATH")
                .action(ArgAction::Set)
                .global(true)
                .help("The testnet dir.")
                .display_order(0)
        )
        .arg(
            Arg::new("network")
                .long("network")
                .value_name("NAME")
                .action(ArgAction::Set)
                .global(true)
                .help("The network to use. Defaults to mainnet.")
                .conflicts_with("testnet-dir")
                .display_order(0)
        )
        .subcommand(
            Command::new("skip-slots")
                .about(
                    "Performs a state transition from some state across some number of skip slots",
                )
                .arg(
                    Arg::new("output-path")
                        .long("output-path")
                        .value_name("PATH")
                        .action(ArgAction::Set)
                        .help("Path to output a SSZ file.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("pre-state-path")
                        .long("pre-state-path")
                        .value_name("PATH")
                        .action(ArgAction::Set)
                        .conflicts_with("beacon-url")
                        .help("Path to a SSZ file of the pre-state.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("beacon-url")
                        .long("beacon-url")
                        .value_name("URL")
                        .action(ArgAction::Set)
                        .help("URL to a beacon-API provider.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("state-id")
                        .long("state-id")
                        .value_name("STATE_ID")
                        .action(ArgAction::Set)
                        .requires("beacon-url")
                        .help("Identifier for a state as per beacon-API standards (slot, root, etc.)")
                        .display_order(0)
                )
                .arg(
                    Arg::new("runs")
                        .long("runs")
                        .value_name("INTEGER")
                        .action(ArgAction::Set)
                        .default_value("1")
                        .help("Number of repeat runs, useful for benchmarking.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("state-root")
                        .long("state-root")
                        .value_name("HASH256")
                        .action(ArgAction::Set)
                        .help("Tree hash root of the provided state, to avoid computing it.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("slots")
                        .long("slots")
                        .value_name("INTEGER")
                        .action(ArgAction::Set)
                        .help("Number of slots to skip forward.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("partial-state-advance")
                        .long("partial-state-advance")
                        .action(ArgAction::SetTrue)
                        .help_heading(FLAG_HEADER)
                        .help("If present, don't compute state roots when skipping forward.")
                        .display_order(0)
                )
        )
        .subcommand(
            Command::new("transition-blocks")
                .about("Performs a state transition given a pre-state and block")
                .arg(
                    Arg::new("pre-state-path")
                        .long("pre-state-path")
                        .value_name("PATH")
                        .action(ArgAction::Set)
                        .conflicts_with("beacon-url")
                        .requires("block-path")
                        .help("Path to load a BeaconState from as SSZ.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("block-path")
                        .long("block-path")
                        .value_name("PATH")
                        .action(ArgAction::Set)
                        .conflicts_with("beacon-url")
                        .requires("pre-state-path")
                        .help("Path to load a SignedBeaconBlock from as SSZ.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("post-state-output-path")
                        .long("post-state-output-path")
                        .value_name("PATH")
                        .action(ArgAction::Set)
                        .help("Path to output the post-state.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("pre-state-output-path")
                        .long("pre-state-output-path")
                        .value_name("PATH")
                        .action(ArgAction::Set)
                        .help("Path to output the pre-state, useful when used with --beacon-url.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("block-output-path")
                        .long("block-output-path")
                        .value_name("PATH")
                        .action(ArgAction::Set)
                        .help("Path to output the block, useful when used with --beacon-url.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("beacon-url")
                        .long("beacon-url")
                        .value_name("URL")
                        .action(ArgAction::Set)
                        .help("URL to a beacon-API provider.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("block-id")
                        .long("block-id")
                        .value_name("BLOCK_ID")
                        .action(ArgAction::Set)
                        .requires("beacon-url")
                        .help("Identifier for a block as per beacon-API standards (slot, root, etc.)")
                        .display_order(0)
                )
                .arg(
                    Arg::new("runs")
                        .long("runs")
                        .value_name("INTEGER")
                        .action(ArgAction::Set)
                        .default_value("1")
                        .help("Number of repeat runs, useful for benchmarking.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("no-signature-verification")
                        .long("no-signature-verification")
                        .action(ArgAction::SetTrue)
                        .help_heading(FLAG_HEADER)
                        .help("Disable signature verification.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("exclude-cache-builds")
                        .long("exclude-cache-builds")
                        .action(ArgAction::SetTrue)
                        .help_heading(FLAG_HEADER)
                        .help("If present, pre-build the committee and tree-hash caches without \
                            including them in the timings.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("exclude-post-block-thc")
                        .long("exclude-post-block-thc")
                        .action(ArgAction::SetTrue)
                        .help_heading(FLAG_HEADER)
                        .help("If present, don't rebuild the tree-hash-cache after applying \
                            the block.")
                        .display_order(0)
                )
        )
        .subcommand(
            Command::new("pretty-ssz")
                .about("Parses SSZ-encoded data from a file")
                .arg(
                    Arg::new("format")
                        .short('f')
                        .long("format")
                        .value_name("FORMAT")
                        .action(ArgAction::Set)
                        .required(false)
                        .default_value("json")
                        .value_parser(["json", "yaml"])
                        .help("Output format to use")
                        .display_order(0)
                )
                .arg(
                    Arg::new("type")
                        .value_name("TYPE")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("Type to decode")
                        .display_order(0)
                )
                .arg(
                    Arg::new("ssz-file")
                        .value_name("FILE")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("Path to SSZ bytes")
                        .display_order(0)
                )
        )
        .subcommand(
            Command::new("check-deposit-data")
                .about("Checks the integrity of some deposit data.")
                .arg(
                    Arg::new("deposit-amount")
                        .index(1)
                        .value_name("GWEI")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("The amount (in Gwei) that was deposited")
                        .display_order(0)
                )
                .arg(
                    Arg::new("deposit-data")
                        .index(2)
                        .value_name("HEX")
                        .action(ArgAction::Set)
                        .required(true)
                        .help(
                            "A 0x-prefixed hex string of the deposit data. Should include the
                            function signature.",
                        )
                        .display_order(0)
                ),
        )
        .subcommand(
            Command::new("generate-bootnode-enr")
                .about("Generates an ENR address to be used as a pre-genesis boot node.")
                .arg(
                    Arg::new("ip")
                        .long("ip")
                        .value_name("IP_ADDRESS")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("The IP address to be included in the ENR and used for discovery")
                        .display_order(0)
                )
                .arg(
                    Arg::new("udp-port")
                        .long("udp-port")
                        .value_name("UDP_PORT")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("The UDP port to be included in the ENR and used for discovery")
                        .display_order(0)
                )
                .arg(
                    Arg::new("tcp-port")
                        .long("tcp-port")
                        .value_name("TCP_PORT")
                        .action(ArgAction::Set)
                        .required(true)
                        .help(
                            "The TCP port to be included in the ENR and used for application comms",
                        )
                        .display_order(0)
                )
                .arg(
                    Arg::new("output-dir")
                        .long("output-dir")
                        .value_name("OUTPUT_DIRECTORY")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("The directory in which to create the network dir")
                        .display_order(0)
                )
                .arg(
                    Arg::new("genesis-fork-version")
                        .long("genesis-fork-version")
                        .value_name("HEX")
                        .action(ArgAction::Set)
                        .required(true)
                        .help(
                            "Used to avoid reply attacks between testnets. Recommended to set to
                              non-default.",
                        )
                        .display_order(0)
                ),
        )
        .subcommand(
            Command::new("mnemonic-validators")
                .about("Produces validator directories by deriving the keys from \
                        a mnemonic. For testing purposes only, DO NOT USE IN \
                        PRODUCTION!")
                .arg(
                    Arg::new("count")
                        .long("count")
                        .value_name("COUNT")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("Produces validators in the range of 0..count.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("base-dir")
                        .long("base-dir")
                        .value_name("BASE_DIR")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("The base directory where validator keypairs and secrets are stored")
                        .display_order(0)
                )
                .arg(
                    Arg::new("node-count")
                        .long("node-count")
                        .value_name("NODE_COUNT")
                        .action(ArgAction::Set)
                        .help("The number of nodes to divide the validator keys to")
                        .display_order(0)
                )
                .arg(
                    Arg::new("mnemonic-phrase")
                        .long("mnemonic-phrase")
                        .value_name("MNEMONIC_PHRASE")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("The mnemonic with which we generate the validator keys")
                        .display_order(0)
                )
        )
        .subcommand(
            Command::new("indexed-attestations")
                .about("Convert attestations to indexed form, using the committees from a state.")
                .arg(
                    Arg::new("state")
                        .long("state")
                        .value_name("SSZ_STATE")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("BeaconState to generate committees from (SSZ)")
                        .display_order(0)
                )
                .arg(
                    Arg::new("attestations")
                        .long("attestations")
                        .value_name("JSON_ATTESTATIONS")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("List of Attestations to convert to indexed form (JSON)")
                        .display_order(0)
                )
        )
        .subcommand(
            Command::new("block-root")
                .about("Computes the block root of some block.")
                .arg(
                    Arg::new("block-path")
                        .long("block-path")
                        .value_name("PATH")
                        .action(ArgAction::Set)
                        .conflicts_with("beacon-url")
                        .help("Path to load a SignedBeaconBlock from as SSZ.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("beacon-url")
                        .long("beacon-url")
                        .value_name("URL")
                        .action(ArgAction::Set)
                        .help("URL to a beacon-API provider.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("block-id")
                        .long("block-id")
                        .value_name("BLOCK_ID")
                        .action(ArgAction::Set)
                        .requires("beacon-url")
                        .help("Identifier for a block as per beacon-API standards (slot, root, etc.)")
                        .display_order(0)
                )
                .arg(
                    Arg::new("runs")
                        .long("runs")
                        .value_name("INTEGER")
                        .action(ArgAction::Set)
                        .default_value("1")
                        .help("Number of repeat runs, useful for benchmarking.")
                        .display_order(0)
                )
        )
        .subcommand(
            Command::new("state-root")
                .about("Computes the state root of some state.")
                .arg(
                    Arg::new("state-path")
                        .long("state-path")
                        .value_name("PATH")
                        .action(ArgAction::Set)
                        .conflicts_with("beacon-url")
                        .help("Path to load a BeaconState from as SSZ.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("beacon-url")
                        .long("beacon-url")
                        .value_name("URL")
                        .action(ArgAction::Set)
                        .help("URL to a beacon-API provider.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("state-id")
                        .long("state-id")
                        .value_name("BLOCK_ID")
                        .action(ArgAction::Set)
                        .requires("beacon-url")
                        .help("Identifier for a state as per beacon-API standards (slot, root, etc.)")
                        .display_order(0)
                )
                .arg(
                    Arg::new("runs")
                        .long("runs")
                        .value_name("INTEGER")
                        .action(ArgAction::Set)
                        .default_value("1")
                        .help("Number of repeat runs, useful for benchmarking.")
                        .display_order(0)
                )
        )
        .subcommand(
            Command::new("mock-el")
                .about("Creates a mock execution layer server. This is NOT SAFE and should only \
                be used for testing and development on testnets. Do not use in production. Do not \
                use on mainnet. It cannot perform validator duties.")
                .arg(
                    Arg::new("jwt-output-path")
                        .long("jwt-output-path")
                        .value_name("PATH")
                        .action(ArgAction::Set)
                        .required(true)
                        .help("Path to write the JWT secret.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("listen-address")
                        .long("listen-address")
                        .value_name("IP_ADDRESS")
                        .action(ArgAction::Set)
                        .help("The server will listen on this address.")
                        .default_value("127.0.0.1")
                        .display_order(0)
                )
                .arg(
                    Arg::new("listen-port")
                        .long("listen-port")
                        .value_name("PORT")
                        .action(ArgAction::Set)
                        .help("The server will listen on this port.")
                        .default_value("8551")
                        .display_order(0)
                )
                .arg(
                    Arg::new("all-payloads-valid")
                        .long("all-payloads-valid")
                        .action(ArgAction::Set)
                        .help("Controls the response to newPayload and forkchoiceUpdated. \
                            Set to 'true' to return VALID. Set to 'false' to return SYNCING.")
                        .default_value("false")
                        .hide(true)
                        .display_order(0)
                )
                .arg(
                    Arg::new("shanghai-time")
                        .long("shanghai-time")
                        .value_name("UNIX_TIMESTAMP")
                        .action(ArgAction::Set)
                        .help("The payload timestamp that enables Shanghai. Defaults to the mainnet value.")
                        .default_value("1681338479")
                        .display_order(0)
                )
                .arg(
                    Arg::new("cancun-time")
                        .long("cancun-time")
                        .value_name("UNIX_TIMESTAMP")
                        .action(ArgAction::Set)
                        .help("The payload timestamp that enables Cancun. No default is provided \
                                until Cancun is triggered on mainnet.")
                        .display_order(0)
                )
                .arg(
                    Arg::new("prague-time")
                        .long("prague-time")
                        .value_name("UNIX_TIMESTAMP")
                        .action(ArgAction::Set)
                        .help("The payload timestamp that enables Prague. No default is provided \
                                until Prague is triggered on mainnet.")
                        .display_order(0)
                )
        )
        .get_matches();

    let result = matches
        .get_one::<String>("spec")
        .ok_or_else(|| "Missing --spec flag".to_string())
        .and_then(|s| FromStr::from_str(s))
        .and_then(|eth_spec_id| match eth_spec_id {
            EthSpecId::Minimal => run(EnvironmentBuilder::minimal(), &matches),
            EthSpecId::Mainnet => run(EnvironmentBuilder::mainnet(), &matches),
            EthSpecId::Gnosis => run(EnvironmentBuilder::gnosis(), &matches),
        });

    match result {
        Ok(()) => process::exit(0),
        Err(e) => {
            println!("Failed to run lcli: {}", e);
            process::exit(1)
        }
    }
}

fn run<E: EthSpec>(env_builder: EnvironmentBuilder<E>, matches: &ArgMatches) -> Result<(), String> {
    let env = env_builder
        .multi_threaded_tokio_runtime()
        .map_err(|e| format!("should start tokio runtime: {:?}", e))?
        .initialize_logger(LoggerConfig {
            path: None,
            debug_level: String::from("trace"),
            logfile_debug_level: String::from("trace"),
            log_format: None,
            logfile_format: None,
            log_color: false,
            disable_log_timestamp: false,
            max_log_size: 0,
            max_log_number: 0,
            compression: false,
            is_restricted: true,
            sse_logging: false, // No SSE Logging in LCLI
        })
        .map_err(|e| format!("should start logger: {:?}", e))?
        .build()
        .map_err(|e| format!("should build env: {:?}", e))?;

    // Determine testnet-dir path or network name depending on CLI flags.
    let (testnet_dir, network_name) =
        if let Some(testnet_dir) = parse_optional::<PathBuf>(matches, "testnet-dir")? {
            (Some(testnet_dir), None)
        } else {
            let network_name =
                parse_optional(matches, "network")?.unwrap_or_else(|| "mainnet".to_string());
            (None, Some(network_name))
        };

    let get_network_config = || {
        if let Some(testnet_dir) = &testnet_dir {
            Eth2NetworkConfig::load(testnet_dir.clone()).map_err(|e| {
                format!(
                    "Unable to open testnet dir at {}: {}",
                    testnet_dir.display(),
                    e
                )
            })
        } else {
            let network_name = network_name.ok_or("no network name or testnet-dir provided")?;
            Eth2NetworkConfig::constant(&network_name)?.ok_or("invalid network name".into())
        }
    };

    match matches.subcommand() {
        Some(("transition-blocks", matches)) => {
            let network_config = get_network_config()?;
            transition_blocks::run::<E>(env, network_config, matches)
                .map_err(|e| format!("Failed to transition blocks: {}", e))
        }
        Some(("skip-slots", matches)) => {
            let network_config = get_network_config()?;
            skip_slots::run::<E>(env, network_config, matches)
                .map_err(|e| format!("Failed to skip slots: {}", e))
        }
        Some(("pretty-ssz", matches)) => {
            let network_config = get_network_config()?;
            run_parse_ssz::<E>(network_config, matches)
                .map_err(|e| format!("Failed to pretty print hex: {}", e))
        }
        Some(("check-deposit-data", matches)) => check_deposit_data::run(matches)
            .map_err(|e| format!("Failed to run check-deposit-data command: {}", e)),
        Some(("generate-bootnode-enr", matches)) => generate_bootnode_enr::run::<E>(matches)
            .map_err(|e| format!("Failed to run generate-bootnode-enr command: {}", e)),
        Some(("mnemonic-validators", matches)) => mnemonic_validators::run(matches)
            .map_err(|e| format!("Failed to run mnemonic-validators command: {}", e)),
        Some(("indexed-attestations", matches)) => indexed_attestations::run::<E>(matches)
            .map_err(|e| format!("Failed to run indexed-attestations command: {}", e)),
        Some(("block-root", matches)) => {
            let network_config = get_network_config()?;
            block_root::run::<E>(env, network_config, matches)
                .map_err(|e| format!("Failed to run block-root command: {}", e))
        }
        Some(("state-root", matches)) => {
            let network_config = get_network_config()?;
            state_root::run::<E>(env, network_config, matches)
                .map_err(|e| format!("Failed to run state-root command: {}", e))
        }
        Some(("mock-el", matches)) => mock_el::run::<E>(env, matches)
            .map_err(|e| format!("Failed to run mock-el command: {}", e)),
        Some((other, _)) => Err(format!("Unknown subcommand {}. See --help.", other)),
        _ => Err("No subcommand provided. See --help.".to_string()),
    }
}
