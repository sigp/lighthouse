mod attestation_producer;
mod block_producer;
mod config;
mod duties;
pub mod error;
mod service;
mod signer;

use crate::config::Config as ValidatorClientConfig;
use clap::{App, Arg};
use protos::services_grpc::ValidatorServiceClient;
use service::Service as ValidatorService;
use slog::{error, info, o, Drain};
use types::Keypair;

fn main() {
    // Logging
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::CompactFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build().fuse();
    let log = slog::Logger::root(drain, o!());

    // CLI
    let matches = App::new("Lighthouse Validator Client")
        .version("0.0.1")
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Validator Client")
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .value_name("DIR")
                .help("Data directory for keys and databases.")
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
            Arg::with_name("spec")
                .long("spec")
                .value_name("spec")
                .short("s")
                .help("Configuration of Beacon Chain")
                .takes_value(true)
                .possible_values(&["foundation", "few_validators", "lighthouse_testnet"])
                .default_value("lighthouse_testnet"),
        )
        .get_matches();

    let config = ValidatorClientConfig::parse_args(&matches, &log)
        .expect("Unable to build a configuration for the validator client.");

    // start the validator service.
    // this specifies the GRPC and signer type to use as the duty manager beacon node.
    match ValidatorService::<ValidatorServiceClient, Keypair>::start(config, log.clone()) {
        Ok(_) => info!(log, "Validator client shutdown successfully."),
        Err(e) => error!(log, "Validator exited due to: {}", e.to_string()),
    }
}
