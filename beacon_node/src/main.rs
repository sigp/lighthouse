extern crate slog;

mod run;

use clap::{App, Arg};
use client::ClientConfig;
use slog::{crit, o, Drain};
use std::fs;
use std::fs::File;
use std::io::prelude::*;

pub const SAMPLE_CONFIG_FILENAME: &str = "beacon_node_config.sample.toml";
pub const CONFIG_FILENAME: &str = "beacon_node_config.toml";
pub const DEFAULT_DATA_DIR: &str = ".lighthouse";

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
        .get_matches();

    let mut config = match load_config(matches.value_of("data_dir")) {
        Ok(c) => c,
        Err(e) => {
            crit!(logger, "Failed to load/generate a ChainConfig"; "error" => format!("{:?}", e));
            return;
        }
    };

    match config.apply_cli_args(&matches) {
        Ok(()) => (),
        Err(s) => {
            crit!(logger, "Failed to parse CLI arguments"; "error" => s);
            return;
        }
    };

    match run::run_beacon_node(config, &logger) {
        Ok(_) => {}
        Err(e) => crit!(logger, "Beacon node failed to start"; "reason" => format!("{:}", e)),
    }
}

/// Loads a `ClientConfig` from file. If unable to load from file, generates a default
/// configuration and saves that as a sample file.
fn load_config(data_dir: Option<&str>) -> Result<ClientConfig, String> {
    let data_dir = data_dir.unwrap_or_else(|| DEFAULT_DATA_DIR);

    let path = dirs::home_dir()
        .ok_or_else(|| "Unable to locate home directory")?
        .join(&data_dir);
    fs::create_dir_all(&path).map_err(|_| "Unable to open data_dir")?;

    if let Ok(mut file) = File::open(path.join(CONFIG_FILENAME)) {
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| {
            format!(
                "Unable to read existing {}. Error: {:?}",
                CONFIG_FILENAME, e
            )
        })?;

        toml::from_str(&contents).map_err(|_| format!("Unable to parse {}", CONFIG_FILENAME))
    } else {
        let mut config = ClientConfig::default();
        config.data_dir = data_dir.to_string();

        if let Ok(mut file) = File::create(path.join(SAMPLE_CONFIG_FILENAME)) {
            let toml_encoded = toml::to_string(&config).map_err(|e| {
                format!(
                    "Failed to write configuration to {}. Error: {:?}",
                    SAMPLE_CONFIG_FILENAME, e
                )
            })?;
            file.write_all(toml_encoded.as_bytes())
                .expect(&format!("Unable to write to {}", SAMPLE_CONFIG_FILENAME));
        }

        Ok(config)
    }
}
