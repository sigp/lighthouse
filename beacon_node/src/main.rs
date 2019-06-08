extern crate slog;

mod run;

use clap::{App, Arg};
use client::{ClientConfig, Eth2Config};
use slog::{crit, o, Drain};
use std::fs;
use std::fs::File;
use std::io::prelude::*;

pub const DEFAULT_DATA_DIR: &str = ".lighthouse";

pub const CLIENT_CONFIG_FILENAME: &str = "client_config.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2_config.toml";

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
                .help("The title of the spec constants for chain config..")
                .takes_value(true)
                .possible_values(&["mainnet", "minimal"])
                .default_value("minimal"),
        )
        .arg(
            Arg::with_name("recent-genesis")
                .long("recent-genesis")
                .help("When present, genesis will be within 30 minutes prior. Only for testing"),
        )
        .get_matches();

    // Attempt to lead the `ClientConfig` from disk. If it fails, write
    let mut client_config = match read_from_file::<ClientConfig>(
        matches.value_of("data_dir"),
        CLIENT_CONFIG_FILENAME,
    ) {
        Ok(Some(c)) => c,
        Ok(None) => {
            let default = ClientConfig::default();
            if let Err(e) = write_to_file(matches.value_of("data_dir"), CLIENT_CONFIG_FILENAME, &default) {
                crit!(logger, "Failed to write default ClientConfig to file"; "error" => format!("{:?}", e));
                return;
            }
            default
        },
        Err(e) => {
            crit!(logger, "Failed to load a ChainConfig file"; "error" => format!("{:?}", e));
            return;
        }
    };

    if let Some(data_dir) = matches.value_of("data_dir") {
        client_config.data_dir = data_dir.to_string();
    }

    match client_config.apply_cli_args(&matches) {
        Ok(()) => (),
        Err(s) => {
            crit!(logger, "Failed to parse ClientConfig CLI arguments"; "error" => s);
            return;
        }
    };

    let mut eth2_config = match read_from_file::<Eth2Config>(
        matches.value_of("data_dir"),
        ETH2_CONFIG_FILENAME,
    ) {
        Ok(Some(c)) => c,
        Ok(None) => {
            let default = match matches.value_of("spec-constants") {
                Some("mainnet") => Eth2Config::mainnet(),
                Some("minimal") => Eth2Config::minimal(),
                _ => unreachable!(), // Guarded by slog.
            };
            if let Err(e) = write_to_file(matches.value_of("data_dir"), ETH2_CONFIG_FILENAME, &default) {
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

/// Write a configuration to file.
fn write_to_file<T>(data_dir: Option<&str>, config_filename: &str, config: &T) -> Result<(), String>
where
    T: Default + serde::de::DeserializeOwned + serde::Serialize,
{
    let data_dir = data_dir.unwrap_or_else(|| DEFAULT_DATA_DIR);

    let path = dirs::home_dir()
        .ok_or_else(|| "Unable to locate home directory")?
        .join(&data_dir);
    fs::create_dir_all(&path).map_err(|_| "Unable to open data_dir")?;

    if let Ok(mut file) = File::create(path.join(config_filename)) {
        let toml_encoded = toml::to_string(&config).map_err(|e| {
            format!(
                "Failed to write configuration to {}. Error: {:?}",
                config_filename, e
            )
        })?;
        file.write_all(toml_encoded.as_bytes())
            .expect(&format!("Unable to write to {}", config_filename));
    }

    Ok(())
}

/// Loads a `ClientConfig` from file. If unable to load from file, generates a default
/// configuration and saves that as a sample file.
fn read_from_file<T>(data_dir: Option<&str>, config_filename: &str) -> Result<Option<T>, String>
where
    T: Default + serde::de::DeserializeOwned + serde::Serialize,
{
    let data_dir = data_dir.unwrap_or_else(|| DEFAULT_DATA_DIR);

    let path = dirs::home_dir()
        .ok_or_else(|| "Unable to locate home directory")?
        .join(&data_dir);
    fs::create_dir_all(&path).map_err(|_| "Unable to open data_dir")?;

    if let Ok(mut file) = File::open(path.join(config_filename)) {
        let mut contents = String::new();
        file.read_to_string(&mut contents).map_err(|e| {
            format!(
                "Unable to read existing {}. Error: {:?}",
                config_filename, e
            )
        })?;

        let config = toml::from_str(&contents)
            .map_err(|e| format!("Unable to parse {}: {:?}", config_filename, e))?;

        Ok(Some(config))
    } else {
        Ok(None)
    }
}
