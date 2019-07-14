mod attestation_producer;
mod block_producer;
mod config;
mod duties;
pub mod error;
mod service;
mod signer;

use crate::config::Config as ValidatorClientConfig;
use crate::service::Service as ValidatorService;
use clap::{App, Arg};
use eth2_config::{read_from_file, write_to_file, Eth2Config};
use protos::services_grpc::ValidatorServiceClient;
use slog::{crit, error, info, o, Drain};
use std::fs;
use std::path::PathBuf;
use types::{Keypair, MainnetEthSpec, MinimalEthSpec};

pub const DEFAULT_SPEC: &str = "minimal";
pub const DEFAULT_DATA_DIR: &str = ".lighthouse-validator";
pub const CLIENT_CONFIG_FILENAME: &str = "validator-client.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";

fn main() {
    // Logging
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let mut log = slog::Logger::root(drain, o!());

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
            Arg::with_name("eth2-spec")
                .long("eth2-spec")
                .short("e")
                .value_name("TOML_FILE")
                .help("Path to Ethereum 2.0 specifications file.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("server")
                .long("server")
                .value_name("server")
                .help("Address to connect to BeaconNode.")
                .takes_value(true),
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
        .get_matches();

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

    // Attempt to lead the `ClientConfig` from disk.
    //
    // If file doesn't exist, create a new, default one.
    let mut client_config = match read_from_file::<ValidatorClientConfig>(
        client_config_path.clone(),
    ) {
        Ok(Some(c)) => c,
        Ok(None) => {
            let default = ValidatorClientConfig::default();
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
            crit!(log, "Failed to instantiate an Eth2Config"; "error" => format!("{:?}", e));
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

    info!(
        log,
        "Starting validator client";
        "datadir" => client_config.data_dir.to_str(),
        "spec_constants" => &eth2_config.spec_constants,
    );

    let result = match eth2_config.spec_constants.as_str() {
        "mainnet" => ValidatorService::<ValidatorServiceClient, Keypair>::start::<MainnetEthSpec>(
            client_config,
            eth2_config,
            log.clone(),
        ),
        "minimal" => ValidatorService::<ValidatorServiceClient, Keypair>::start::<MinimalEthSpec>(
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
