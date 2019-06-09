extern crate slog;

mod run;

use clap::{App, Arg};
use client::{ClientConfig, Eth2Config};
use eth2_config::{get_data_dir, read_from_file, write_to_file};
use slog::{crit, o, Drain};
use std::path::PathBuf;

pub const DEFAULT_DATA_DIR: &str = ".lighthouse";

pub const CLIENT_CONFIG_FILENAME: &str = "beacon-node.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";

fn main() {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let logger = slog::Logger::root(drain, o!());

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
                .default_value(DEFAULT_DATA_DIR),
        )
        // network related arguments
        .arg(
            Arg::with_name("listen-address")
                .long("listen-address")
                .value_name("Listen Address")
                .help("One or more comma-delimited multi-addresses to listen for p2p connections.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("boot-nodes")
                .long("boot-nodes")
                .value_name("BOOTNODES")
                .help("One or more comma-delimited multi-addresses to bootstrap the p2p network.")
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
                .value_name("RPCADDRESS")
                .help("Listen address for RPC endpoint.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("rpc-port")
                .long("rpc-port")
                .value_name("RPCPORT")
                .help("Listen port for RPC endpoint.")
                .takes_value(true),
        )
        // HTTP related arguments
        .arg(
            Arg::with_name("http")
                .long("http")
                .value_name("HTTP")
                .help("Enable the HTTP server.")
                .takes_value(false),
        )
        .arg(
            Arg::with_name("http-address")
                .long("http-address")
                .value_name("HTTPADDRESS")
                .help("Listen address for the HTTP server.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("http-port")
                .long("http-port")
                .value_name("HTTPPORT")
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
        .get_matches();

    let data_dir = match get_data_dir(&matches, PathBuf::from(DEFAULT_DATA_DIR)) {
        Ok(dir) => dir,
        Err(e) => {
            crit!(logger, "Failed to initialize data dir"; "error" => format!("{:?}", e));
            return;
        }
    };

    let client_config_path = data_dir.join(CLIENT_CONFIG_FILENAME);

    // Attempt to lead the `ClientConfig` from disk.
    //
    // If file doesn't exist, create a new, default one.
    let mut client_config = match read_from_file::<ClientConfig>(client_config_path.clone()) {
        Ok(Some(c)) => c,
        Ok(None) => {
            let default = ClientConfig::default();
            if let Err(e) = write_to_file(client_config_path, &default) {
                crit!(logger, "Failed to write default ClientConfig to file"; "error" => format!("{:?}", e));
                return;
            }
            default
        }
        Err(e) => {
            crit!(logger, "Failed to load a ChainConfig file"; "error" => format!("{:?}", e));
            return;
        }
    };

    // Ensure the `data_dir` in the config matches that supplied to the CLI.
    client_config.data_dir = data_dir.clone();

    // Update the client config with any CLI args.
    match client_config.apply_cli_args(&matches) {
        Ok(()) => (),
        Err(s) => {
            crit!(logger, "Failed to parse ClientConfig CLI arguments"; "error" => s);
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
                crit!(logger, "Failed to write default Eth2Config to file"; "error" => format!("{:?}", e));
                return;
            }
            default
        }
        Err(e) => {
            crit!(logger, "Failed to load/generate an Eth2Config"; "error" => format!("{:?}", e));
            return;
        }
    };

    // Update the eth2 config with any CLI flags.
    match eth2_config.apply_cli_args(&matches) {
        Ok(()) => (),
        Err(s) => {
            crit!(logger, "Failed to parse Eth2Config CLI arguments"; "error" => s);
            return;
        }
    };

    match run::run_beacon_node(client_config, eth2_config, &logger) {
        Ok(_) => {}
        Err(e) => crit!(logger, "Beacon node failed to start"; "reason" => format!("{:}", e)),
    }
}
