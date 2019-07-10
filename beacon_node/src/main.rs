mod run;

use clap::{App, Arg};
use client::{ClientConfig, Eth2Config};
use env_logger::{Builder, Env};
use eth2_config::{read_from_file, write_to_file};
use slog::{crit, o, Drain, Level};
use std::fs;
use std::path::PathBuf;

pub const DEFAULT_DATA_DIR: &str = ".lighthouse";

pub const CLIENT_CONFIG_FILENAME: &str = "beacon-node.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";

fn main() {
    // debugging output for libp2p and external crates
    Builder::from_env(Env::default()).init();

    let matches = App::new("Lighthouse")
        .version(version::version().as_str())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Client")
        // file system related arguments
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
        // network related arguments
        .arg(
            Arg::with_name("listen-address")
                .long("listen-address")
                .value_name("Address")
                .help("The address lighthouse will listen for UDP and TCP connections. (default 127.0.0.1).")
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
            Arg::with_name("port")
                .long("port")
                .value_name("Lighthouse Port")
                .help("The TCP/UDP port to listen on. The UDP port can be modified by the --discovery-port flag.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("discovery-port")
                .long("disc-port")
                .value_name("DiscoveryPort")
                .help("The discovery UDP port.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("discovery-address")
                .long("discovery-address")
                .value_name("Address")
                .help("The IP address to broadcast to other peers on how to reach this node.")
                .takes_value(true),
        )
        // rpc related arguments
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
        // HTTP related arguments
        .arg(
            Arg::with_name("http")
                .long("http")
                .help("Enable the HTTP server.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("http-address")
                .long("http-address")
                .value_name("Address")
                .help("Listen address for the HTTP server.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("http-port")
                .long("http-port")
                .help("Listen port for the HTTP server.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("db")
                .long("db")
                .value_name("DB")
                .help("Type of database to use.")
                .takes_value(true)
                .possible_values(&["disk", "memory"])
                .default_value("memory"),
        )
        .arg(
            Arg::with_name("spec-constants")
                .long("spec-constants")
                .value_name("TITLE")
                .short("s")
                .help("The title of the spec constants for chain config.")
                .takes_value(true)
                .possible_values(&["mainnet", "minimal"])
                .default_value("minimal"),
        )
        .arg(
            Arg::with_name("recent-genesis")
                .long("recent-genesis")
                .short("r")
                .help("When present, genesis will be within 30 minutes prior. Only for testing"),
        )
        .arg(
            Arg::with_name("verbosity")
                .short("v")
                .multiple(true)
                .help("Sets the verbosity level")
                .takes_value(true),
        )
        .get_matches();

    // build the initial logger
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build();

    let drain = match matches.occurrences_of("verbosity") {
        0 => drain.filter_level(Level::Info),
        1 => drain.filter_level(Level::Debug),
        2 => drain.filter_level(Level::Trace),
        _ => drain.filter_level(Level::Info),
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
            PathBuf::from(default_dir)
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

    // Attempt to load the `Eth2Config` from file.
    //
    // If the file doesn't exist, create a default one depending on the CLI flags.
    let mut eth2_config = match read_from_file::<Eth2Config>(eth2_config_path.clone()) {
        Ok(Some(c)) => c,
        Ok(None) => {
            let default = match matches.value_of("spec-constants") {
                Some("mainnet") => Eth2Config::mainnet(),
                Some("minimal") => Eth2Config::minimal(),
                _ => unreachable!(), // Guarded by slog.
            };
            if let Err(e) = write_to_file(eth2_config_path, &default) {
                crit!(log, "Failed to write default Eth2Config to file"; "error" => format!("{:?}", e));
                return;
            }
            default
        }
        Err(e) => {
            crit!(log, "Failed to load/generate an Eth2Config"; "error" => format!("{:?}", e));
            return;
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

    match run::run_beacon_node(client_config, eth2_config, &log) {
        Ok(_) => {}
        Err(e) => crit!(log, "Beacon node failed to start"; "reason" => format!("{:}", e)),
    }
}
