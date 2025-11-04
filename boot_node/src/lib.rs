//! Creates a simple DISCV5 server which can be used to bootstrap an Eth2 network.
use clap::ArgMatches;

use eth2_network_config::Eth2NetworkConfig;
mod cli;
pub mod config;
mod server;
pub use cli::cli_app;
use config::BootNodeConfig;
use tracing_subscriber::EnvFilter;
use types::{EthSpec, EthSpecId};

/// Run the bootnode given the CLI configuration.
pub fn run(
    lh_matches: &ArgMatches,
    bn_matches: &ArgMatches,
    eth_spec_id: EthSpecId,
    eth2_network_config: &Eth2NetworkConfig,
    debug_level: String,
) {
    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(debug_level.to_string().to_lowercase()))
        .unwrap();

    tracing_subscriber::fmt()
        .with_env_filter(filter_layer)
        .init();

    // Run the main function emitting any errors
    if let Err(e) = match eth_spec_id {
        EthSpecId::Minimal => {
            main::<types::MinimalEthSpec>(lh_matches, bn_matches, eth2_network_config)
        }
        EthSpecId::Mainnet => {
            main::<types::MainnetEthSpec>(lh_matches, bn_matches, eth2_network_config)
        }
        EthSpecId::Gnosis => {
            main::<types::GnosisEthSpec>(lh_matches, bn_matches, eth2_network_config)
        }
    } {
        logging::crit!(?e);
    }
}

fn main<E: EthSpec>(
    lh_matches: &ArgMatches,
    bn_matches: &ArgMatches,
    eth2_network_config: &Eth2NetworkConfig,
) -> Result<(), String> {
    // Builds a custom executor for the bootnode
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to build runtime: {}", e))?;

    // Run the boot node
    runtime.block_on(server::run::<E>(
        lh_matches,
        bn_matches,
        eth2_network_config,
    ))?;

    Ok(())
}
