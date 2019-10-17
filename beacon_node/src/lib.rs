#[macro_use]
extern crate clap;

mod cli;
mod config;
mod run;

pub use beacon_chain;
pub use cli::cli_app;
pub use client::{Client, ClientBuilder, ClientConfig};
pub use eth2_config::Eth2Config;

use beacon_chain::BeaconChainTypes;
use clap::ArgMatches;
use config::get_configs;
use environment::Environment;
use std::path::PathBuf;
use types::EthSpec;

/// Starts a new beacon node `Client` in the given `environment`.
///
/// Identical to `start_from_client_config`, however the `client_config` is generated from the
/// given `matches` and potentially configuration files on the local filesystem or other
/// configurations hosted remotely.
pub fn start_from_cli<'a, E: EthSpec>(
    matches: &ArgMatches<'a>,
    environment: &Environment<E>,
) -> Result<Client<impl BeaconChainTypes>, String> {
    let log = environment.beacon_node_log();

    // TODO: tidy this, split out eth2 config.
    let (client_config, eth2_config, _log) = get_configs(&matches, log)?;

    start_from_client_config(environment, client_config, eth2_config)
}

/// Starts a new beacon node `Client` in the given `environment`.
///
/// Client behaviour is defined by the given `client_config`.
pub fn start_from_client_config<E: EthSpec>(
    environment: &Environment<E>,
    client_config: ClientConfig,
    eth2_config: Eth2Config,
) -> Result<Client<impl BeaconChainTypes>, String> {
    let log = environment.beacon_node_log();

    let db_path: PathBuf = client_config
        .db_path()
        .ok_or_else(|| "Unable to access database path".to_string())?;

    let client = ClientBuilder::new(environment.eth_spec_instance().clone())
        .logger(log.clone())
        .disk_store(&db_path)?
        .executor(environment.executor())
        .beacon_checkpoint(&client_config.beacon_chain_start_method)?
        .system_time_slot_clock()?
        .dummy_eth1_backend()
        .websocket_event_handler(client_config.websocket_server.clone())?
        .beacon_chain()?
        .libp2p_network(&client_config.network)?
        .http_server(&client_config, &eth2_config)?
        .grpc_server(&client_config.rpc)?
        .peer_count_notifier()?
        .slot_notifier()?
        .build();

    Ok(client)
}
