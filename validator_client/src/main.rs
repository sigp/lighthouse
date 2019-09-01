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
use eth2_config::{read_from_file, write_to_file, Eth2Config};
use lighthouse_bootstrap::Bootstrapper;
use protos::services_grpc::ValidatorServiceClient;
use slog::{crit, error, info, o, warn, Drain, Level, Logger};
use std::fs;
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
                .long("g")
                .value_name("PORT")
                .help("Port to use for gRPC API connection to the server.")
                .default_value(DEFAULT_SERVER_GRPC_PORT)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("server-http-port")
                .long("h")
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
                .default_value("info"),
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
            .subcommand(SubCommand::with_name("range")
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
    let log = slog::Logger::root(drain.fuse(), o!());

    /*
    let data_dir = match matches
        .value_of("datadir")
        .and_then(|v| Some(PathBuf::from(v)))
    {
        Some(v) => v,
        None => {
            // use the default
            let mut default_dir = match dirs::home_dir() {
                Some(v) => v,
                None => {
                    crit!(log, "Failed to find a home directory");
                    return;
                }
            };
            default_dir.push(DEFAULT_DATA_DIR);
            default_dir
        }
    };

    // create the directory if needed
    match fs::create_dir_all(&data_dir) {
        Ok(_) => {}
        Err(e) => {
            crit!(log, "Failed to initialize data dir"; "error" => format!("{}", e));
            return;
        }
    }

    let client_config_path = data_dir.join(CLIENT_CONFIG_FILENAME);

    // Attempt to load the `ClientConfig` from disk.
    //
    // If file doesn't exist, create a new, default one.
    let mut client_config = match read_from_file::<ClientConfig>(client_config_path.clone()) {
        Ok(Some(c)) => c,
        Ok(None) => {
            let default = ClientConfig::default();
            if let Err(e) = write_to_file(client_config_path.clone(), &default) {
                crit!(log, "Failed to write default ClientConfig to file"; "error" => format!("{:?}", e));
                return;
            }
            default
        }
        Err(e) => {
            crit!(log, "Failed to load a ChainConfig file"; "error" => format!("{:?}", e));
            return;
        }
    };

    // Ensure the `data_dir` in the config matches that supplied to the CLI.
    client_config.data_dir = data_dir.clone();

    // Update the client config with any CLI args.
    match client_config.apply_cli_args(&matches, &mut log) {
        Ok(()) => (),
        Err(s) => {
            crit!(log, "Failed to parse ClientConfig CLI arguments"; "error" => s);
            return;
        }
    };

    let eth2_config_path: PathBuf = matches
        .value_of("eth2-spec")
        .and_then(|s| Some(PathBuf::from(s)))
        .unwrap_or_else(|| data_dir.join(ETH2_CONFIG_FILENAME));

    // Initialise the `Eth2Config`.
    //
    // If a CLI parameter is set, overwrite any config file present.
    // If a parameter is not set, use either the config file present or default to minimal.
    let cli_config = match matches.value_of("default-spec") {
        Some("mainnet") => Some(Eth2Config::mainnet()),
        Some("minimal") => Some(Eth2Config::minimal()),
        Some("interop") => Some(Eth2Config::interop()),
        _ => None,
    };
    // if a CLI flag is specified, write the new config if it doesn't exist,
    // otherwise notify the user that the file will not be written.
    let eth2_config_from_file = match read_from_file::<Eth2Config>(eth2_config_path.clone()) {
        Ok(config) => config,
        Err(e) => {
            crit!(log, "Failed to read the Eth2Config from file"; "error" => format!("{:?}", e));
            return;
        }
    };

    let mut eth2_config = {
        if let Some(cli_config) = cli_config {
            if eth2_config_from_file.is_none() {
                // write to file if one doesn't exist
                if let Err(e) = write_to_file(eth2_config_path, &cli_config) {
                    crit!(log, "Failed to write default Eth2Config to file"; "error" => format!("{:?}", e));
                    return;
                }
            } else {
                warn!(
                    log,
                    "Eth2Config file exists. Configuration file is ignored, using default"
                );
            }
            cli_config
        } else {
            // CLI config not specified, read from disk
            match eth2_config_from_file {
                Some(config) => config,
                None => {
                    // set default to minimal
                    let eth2_config = Eth2Config::minimal();
                    if let Err(e) = write_to_file(eth2_config_path, &eth2_config) {
                        crit!(log, "Failed to write default Eth2Config to file"; "error" => format!("{:?}", e));
                        return;
                    }
                    eth2_config
                }
            }
        }
    };

    // Update the eth2 config with any CLI flags.
    match eth2_config.apply_cli_args(&matches) {
        Ok(()) => (),
        Err(s) => {
            crit!(log, "Failed to parse Eth2Config CLI arguments"; "error" => s);
            return;
        }
    };
    */
    let (client_config, eth2_config) = match get_configs(&matches, &log) {
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
pub fn get_configs(cli_args: &ArgMatches, log: &Logger) -> Result<(ClientConfig, Eth2Config)> {
    let mut client_config = ClientConfig::default();

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
        log,
        "Beacon node connection info";
        "grpc_port" => client_config.server_grpc_port,
        "http_port" => client_config.server_http_port,
        "server" => &client_config.server,
    );

    match cli_args.subcommand() {
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
        _ => {
            unimplemented!("Resuming (not starting a testnet)");
        }
    }
}

fn process_testnet_subcommand(
    cli_args: &ArgMatches,
    mut client_config: ClientConfig,
    log: &Logger,
) -> Result<(ClientConfig, Eth2Config)> {
    let eth2_config = if cli_args.is_present("bootstrap") {
        let bootstrapper = Bootstrapper::from_server_string(format!(
            "http://{}:{}",
            client_config.server, client_config.server_http_port
        ))?;

        let eth2_config = bootstrapper.eth2_config()?;

        info!(
            log,
            "Bootstrapped eth2 config via HTTP";
            "slot_time_millis" => eth2_config.spec.milliseconds_per_slot,
            "spec" => &eth2_config.spec_constants,
        );

        eth2_config
    } else {
        return Err("Starting without bootstrap is not implemented".into());
    };

    client_config.key_source = match cli_args.subcommand() {
        ("range", Some(sub_cli_args)) => {
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
        _ => KeySource::Disk,
    };

    Ok((client_config, eth2_config))
}
