mod attestation_producer;
mod block_producer;
mod config;
mod duties;
pub mod error;
mod service;
mod signer;

use crate::config::{
    Config as ClientConfig, KeySource, DEFAULT_SERVER, DEFAULT_SERVER_GRPC_PORT,
    DEFAULT_SERVER_HTTP_PORT,
};
use crate::service::Service as ValidatorService;
use clap::{App, Arg, ArgMatches, SubCommand};
use eth2_config::Eth2Config;
use lighthouse_bootstrap::Bootstrapper;
use protos::services_grpc::ValidatorServiceClient;
use slog::{crit, error, info, o, Drain, Level, Logger};
use std::path::PathBuf;
use types::{InteropEthSpec, Keypair, MainnetEthSpec, MinimalEthSpec};

pub const DEFAULT_SPEC: &str = "minimal";
pub const DEFAULT_DATA_DIR: &str = ".lighthouse-validator";
pub const CLIENT_CONFIG_FILENAME: &str = "validator-client.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";

type Result<T> = core::result::Result<T, String>;

fn main() {
    // Logging
    let decorator = slog_term::TermDecorator::new().build();
    let decorator = logging::AlignedTermDecorator::new(decorator, logging::MAX_MESSAGE_WIDTH);
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();

    // CLI
    let matches = App::new("Lighthouse Validator Client")
        .version("0.0.1")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Validator Client")
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .short("d")
                .value_name("DIR")
                .help("Data directory for keys and databases.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("logfile")
                .long("logfile")
                .value_name("logfile")
                .help("File path where output will be written.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("spec")
                .long("spec")
                .value_name("TITLE")
                .help("Specifies the default eth2 spec type.")
                .takes_value(true)
                .possible_values(&["mainnet", "minimal", "interop"])
                .conflicts_with("eth2-config")
                .global(true)
        )
        .arg(
            Arg::with_name("eth2-config")
                .long("eth2-config")
                .short("e")
                .value_name("TOML_FILE")
                .help("Path to Ethereum 2.0 config and specification file (e.g., eth2_spec.toml).")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("server")
                .long("server")
                .value_name("NETWORK_ADDRESS")
                .help("Address to connect to BeaconNode.")
                .default_value(DEFAULT_SERVER)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("server-grpc-port")
                .long("server-grpc-port")
                .short("g")
                .value_name("PORT")
                .help("Port to use for gRPC API connection to the server.")
                .default_value(DEFAULT_SERVER_GRPC_PORT)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("server-http-port")
                .long("server-http-port")
                .short("h")
                .value_name("PORT")
                .help("Port to use for HTTP API connection to the server.")
                .default_value(DEFAULT_SERVER_HTTP_PORT)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("debug-level")
                .long("debug-level")
                .value_name("LEVEL")
                .short("s")
                .help("The title of the spec constants for chain config.")
                .takes_value(true)
                .possible_values(&["info", "debug", "trace", "warn", "error", "crit"])
                .default_value("trace"),
        )
        /*
         * The "testnet" sub-command.
         *
         * Used for starting testnet validator clients.
         */
        .subcommand(SubCommand::with_name("testnet")
            .about("Starts a testnet validator using INSECURE, predicatable private keys, based off the canonical \
                   validator index. ONLY USE FOR TESTING PURPOSES!")
            .arg(
                Arg::with_name("bootstrap")
                    .short("b")
                    .long("bootstrap")
                    .help("Connect to the RPC server to download the eth2_config via the HTTP API.")
            )
            .subcommand(SubCommand::with_name("insecure")
                .about("Uses the standard, predicatable `interop` keygen method to produce a range \
                        of predicatable private keys and starts performing their validator duties.")
                .arg(Arg::with_name("first_validator")
                    .value_name("VALIDATOR_INDEX")
                    .required(true)
                    .help("The first validator public key to be generated for this client."))
                .arg(Arg::with_name("validator_count")
                    .value_name("COUNT")
                    .required(true)
                    .help("The number of validators."))
            )
            .subcommand(SubCommand::with_name("interop-yaml")
                .about("Loads plain-text secret keys from YAML files. Expects the interop format defined
                       in the ethereum/eth2.0-pm repo.")
                .arg(Arg::with_name("path")
                    .value_name("PATH")
                    .required(true)
                    .help("Path to a YAML file."))
            )
        )
        .subcommand(SubCommand::with_name("sign_block")
            .about("Connects to the beacon server, requests a new block (after providing reveal),\
            and prints the signed block to standard out")
            .arg(Arg::with_name("validator")
                .value_name("VALIDATOR")
                .required(true)
                .help("The pubkey of the validator that should sign the block.")
            )
        )
        .get_matches();

    let drain = match matches.value_of("debug-level") {
        Some("info") => drain.filter_level(Level::Info),
        Some("debug") => drain.filter_level(Level::Debug),
        Some("trace") => drain.filter_level(Level::Trace),
        Some("warn") => drain.filter_level(Level::Warning),
        Some("error") => drain.filter_level(Level::Error),
        Some("crit") => drain.filter_level(Level::Critical),
        _ => unreachable!("guarded by clap"),
    };

    let mut log = slog::Logger::root(drain.fuse(), o!());

    if std::mem::size_of::<usize>() != 8 {
        crit!(
            log,
            "Lighthouse only supports 64bit CPUs";
            "detected" => format!("{}bit", std::mem::size_of::<usize>() * 8)
        );
    }

    let (client_config, eth2_config) = match get_configs(&matches, &mut log) {
        Ok(tuple) => tuple,
        Err(e) => {
            crit!(
                log,
                "Unable to initialize configuration";
                "error" => e
            );
            return;
        }
    };

    info!(
        log,
        "Starting validator client";
        "datadir" => client_config.full_data_dir().expect("Unable to find datadir").to_str(),
    );

    let result = match eth2_config.spec_constants.as_str() {
        "mainnet" => ValidatorService::<ValidatorServiceClient, Keypair, MainnetEthSpec>::start(
            client_config,
            eth2_config,
            log.clone(),
        ),
        "minimal" => ValidatorService::<ValidatorServiceClient, Keypair, MinimalEthSpec>::start(
            client_config,
            eth2_config,
            log.clone(),
        ),
        "interop" => ValidatorService::<ValidatorServiceClient, Keypair, InteropEthSpec>::start(
            client_config,
            eth2_config,
            log.clone(),
        ),
        other => {
            crit!(log, "Unknown spec constants"; "title" => other);
            return;
        }
    };

    // start the validator service.
    // this specifies the GRPC and signer type to use as the duty manager beacon node.
    match result {
        Ok(_) => info!(log, "Validator client shutdown successfully."),
        Err(e) => crit!(log, "Validator client exited with error"; "error" => e.to_string()),
    }
}

/// Parses the CLI arguments and attempts to load the client and eth2 configuration.
///
/// This is not a pure function, it reads from disk and may contact network servers.
pub fn get_configs(
    cli_args: &ArgMatches,
    mut log: &mut Logger,
) -> Result<(ClientConfig, Eth2Config)> {
    let mut client_config = ClientConfig::default();

    client_config.apply_cli_args(&cli_args, &mut log)?;

    if let Some(server) = cli_args.value_of("server") {
        client_config.server = server.to_string();
    }

    if let Some(port) = cli_args.value_of("server-http-port") {
        client_config.server_http_port = port
            .parse::<u16>()
            .map_err(|e| format!("Unable to parse HTTP port: {:?}", e))?;
    }

    if let Some(port) = cli_args.value_of("server-grpc-port") {
        client_config.server_grpc_port = port
            .parse::<u16>()
            .map_err(|e| format!("Unable to parse gRPC port: {:?}", e))?;
    }

    info!(
        *log,
        "Beacon node connection info";
        "grpc_port" => client_config.server_grpc_port,
        "http_port" => client_config.server_http_port,
        "server" => &client_config.server,
    );

    let (client_config, eth2_config) = match cli_args.subcommand() {
        ("testnet", Some(sub_cli_args)) => {
            if cli_args.is_present("eth2-config") && sub_cli_args.is_present("bootstrap") {
                return Err(
                    "Cannot specify --eth2-config and --bootstrap as it may result \
                     in ambiguity."
                        .into(),
                );
            }
            process_testnet_subcommand(sub_cli_args, client_config, log)
        }
        _ => return Err("You must use the testnet command. See '--help'.".into()),
    }?;

    Ok((client_config, eth2_config))
}

/// Parses the `testnet` CLI subcommand.
///
/// This is not a pure function, it reads from disk and may contact network servers.
fn process_testnet_subcommand(
    cli_args: &ArgMatches,
    mut client_config: ClientConfig,
    log: &Logger,
) -> Result<(ClientConfig, Eth2Config)> {
    let eth2_config = if cli_args.is_present("bootstrap") {
        info!(log, "Connecting to bootstrap server");
        let bootstrapper = Bootstrapper::connect(
            format!(
                "http://{}:{}",
                client_config.server, client_config.server_http_port
            ),
            &log,
        )?;

        let eth2_config = bootstrapper.eth2_config()?;

        info!(
            log,
            "Bootstrapped eth2 config via HTTP";
            "slot_time_millis" => eth2_config.spec.milliseconds_per_slot,
            "spec" => &eth2_config.spec_constants,
        );

        eth2_config
    } else {
        match cli_args.value_of("spec") {
            Some("mainnet") => Eth2Config::mainnet(),
            Some("minimal") => Eth2Config::minimal(),
            Some("interop") => Eth2Config::interop(),
            _ => return Err("No --spec flag provided. See '--help'.".into()),
        }
    };

    client_config.key_source = match cli_args.subcommand() {
        ("insecure", Some(sub_cli_args)) => {
            let first = sub_cli_args
                .value_of("first_validator")
                .ok_or_else(|| "No first validator supplied")?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse first validator: {:?}", e))?;
            let count = sub_cli_args
                .value_of("validator_count")
                .ok_or_else(|| "No validator count supplied")?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse validator count: {:?}", e))?;

            info!(
                log,
                "Generating unsafe testing keys";
                "first_validator" => first,
                "count" => count
            );

            KeySource::TestingKeypairRange(first..first + count)
        }
        ("interop-yaml", Some(sub_cli_args)) => {
            let path = sub_cli_args
                .value_of("path")
                .ok_or_else(|| "No yaml path supplied")?
                .parse::<PathBuf>()
                .map_err(|e| format!("Unable to parse yaml path: {:?}", e))?;

            info!(
                log,
                "Loading keypairs from interop YAML format";
                "path" => format!("{:?}", path),
            );

            KeySource::YamlKeypairs(path)
        }
        _ => KeySource::Disk,
    };

    Ok((client_config, eth2_config))
}
