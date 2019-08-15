mod run;

use clap::{App, Arg};
use client::{ClientConfig, Eth2Config};
use env_logger::{Builder, Env};
use eth2_config::{read_from_file, write_to_file};
use slog::{crit, o, warn, Drain, Level};
use std::fs;
use std::path::PathBuf;

pub const DEFAULT_DATA_DIR: &str = ".lighthouse";

pub const CLIENT_CONFIG_FILENAME: &str = "beacon-node.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";
pub const TESTNET_CONFIG_FILENAME: &str = "testnet.toml";

fn main() {
    // debugging output for libp2p and external crates
    Builder::from_env(Env::default()).init();

    let matches = App::new("Lighthouse")
        .version(version::version().as_str())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Client")
        /*
         * Configuration directory locations.
         */
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .value_name("DIR")
                .help("Data directory for keys and databases.")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("logfile")
                .long("logfile")
                .value_name("logfile")
                .help("File path where output will be written.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("network-dir")
                .long("network-dir")
                .value_name("NETWORK-DIR")
                .help("Data directory for network keys.")
                .takes_value(true)
        )
        /*
         * Network parameters.
         */
        .arg(
            Arg::with_name("listen-address")
                .long("listen-address")
                .value_name("ADDRESS")
                .help("The address lighthouse will listen for UDP and TCP connections. (default 127.0.0.1).")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("The TCP/UDP port to listen on. The UDP port can be modified by the --discovery-port flag.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("maxpeers")
                .long("maxpeers")
                .help("The maximum number of peers (default 10).")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("boot-nodes")
                .long("boot-nodes")
                .allow_hyphen_values(true)
                .value_name("BOOTNODES")
                .help("One or more comma-delimited base64-encoded ENR's to bootstrap the p2p network.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("discovery-port")
                .long("disc-port")
                .value_name("PORT")
                .help("The discovery UDP port.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("discovery-address")
                .long("discovery-address")
                .value_name("ADDRESS")
                .help("The IP address to broadcast to other peers on how to reach this node.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("topics")
                .long("topics")
                .value_name("STRING")
                .help("One or more comma-delimited gossipsub topic strings to subscribe to.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("libp2p-addresses")
                .long("libp2p-addresses")
                .value_name("MULTIADDR")
                .help("One or more comma-delimited multiaddrs to manually connect to a libp2p peer without an ENR.")
                .takes_value(true),
        )
        /*
         * gRPC parameters.
         */
        .arg(
            Arg::with_name("rpc")
                .long("rpc")
                .value_name("RPC")
                .help("Enable the RPC server.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("rpc-address")
                .long("rpc-address")
                .value_name("Address")
                .help("Listen address for RPC endpoint.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("rpc-port")
                .long("rpc-port")
                .help("Listen port for RPC endpoint.")
                .takes_value(true),
        )
        /* Client related arguments */
        .arg(
            Arg::with_name("api")
                .long("api")
                .value_name("API")
                .help("Enable the RESTful HTTP API server.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("api-address")
                .long("api-address")
                .value_name("APIADDRESS")
                .help("Set the listen address for the RESTful HTTP API server.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("api-port")
                .long("api-port")
                .value_name("APIPORT")
                .help("Set the listen TCP port for the RESTful HTTP API server.")
                .takes_value(true),
        )

        /*
         * Database parameters.
         */
        .arg(
            Arg::with_name("db")
                .long("db")
                .value_name("DB")
                .help("Type of database to use.")
                .takes_value(true)
                .possible_values(&["disk", "memory"])
                .default_value("memory"),
        )
        /*
         * Specification/testnet params.
         */
        .arg(
            Arg::with_name("default-spec")
                .long("default-spec")
                .value_name("TITLE")
                .short("default-spec")
                .help("Specifies the default eth2 spec to be used. This will override any spec written to disk and will therefore be used by default in future instances.")
                .takes_value(true)
                .possible_values(&["mainnet", "minimal", "interop"])
        )
        .arg(
            Arg::with_name("recent-genesis")
                .long("recent-genesis")
                .short("r")
                .help("When present, genesis will be within 30 minutes prior. Only for testing"),
        )
        /*
         * Logging.
         */
        .arg(
            Arg::with_name("debug-level")
                .long("debug-level")
                .value_name("LEVEL")
                .help("The title of the spec constants for chain config.")
                .takes_value(true)
                .possible_values(&["info", "debug", "trace", "warn", "error", "crit"])
                .default_value("trace"),
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Sets the verbosity level")
                .takes_value(true),
        )
        /*
         * Bootstrap.
         */
        .arg(
            Arg::with_name("bootstrap")
                .long("bootstrap")
                .value_name("HTTP_SERVER")
                .help("Load the genesis state and libp2p address from the HTTP API of another Lighthouse node.")
                .takes_value(true)
        )
        .get_matches();

    // build the initial logger
    let decorator = slog_term::TermDecorator::new().build();
    let decorator = logging::AlignedTermDecorator::new(decorator, logging::MAX_MESSAGE_WIDTH);
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build();

    let drain = match matches.value_of("debug-level") {
        Some("info") => drain.filter_level(Level::Info),
        Some("debug") => drain.filter_level(Level::Debug),
        Some("trace") => drain.filter_level(Level::Trace),
        Some("warn") => drain.filter_level(Level::Warning),
        Some("error") => drain.filter_level(Level::Error),
        Some("crit") => drain.filter_level(Level::Critical),
        _ => unreachable!("guarded by clap"),
    };

    let drain = match matches.occurrences_of("verbosity") {
        0 => drain.filter_level(Level::Info),
        1 => drain.filter_level(Level::Debug),
        2 => drain.filter_level(Level::Trace),
        _ => drain.filter_level(Level::Trace),
    };

    let mut log = slog::Logger::root(drain.fuse(), o!());

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
            if let Err(e) = write_to_file(client_config_path, &default) {
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

    let eth2_config_path = data_dir.join(ETH2_CONFIG_FILENAME);

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

    // check to ensure the spec constants between the client and eth2_config match
    if eth2_config.spec_constants != client_config.spec_constants {
        crit!(log, "Specification constants do not match."; "client_config" => format!("{}", client_config.spec_constants), "eth2_config" => format!("{}", eth2_config.spec_constants));
        return;
    }

    // Start the node using a `tokio` executor.
    match run::run_beacon_node(client_config, eth2_config, &log) {
        Ok(_) => {}
        Err(e) => crit!(log, "Beacon node failed to start"; "reason" => format!("{:}", e)),
    }
}
