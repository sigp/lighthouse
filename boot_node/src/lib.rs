//! Creates a simple DISCV5 server which can be used to bootstrap an Eth2 network.
use clap::ArgMatches;
use clap_utils::GlobalConfig;
use cli::BootNode;
use slog::{o, Drain, Level, Logger};

use eth2_network_config::Eth2NetworkConfig;
mod cli;
pub mod config;
mod server;
use config::BootNodeConfig;
use types::{EthSpec, EthSpecId};

const LOG_CHANNEL_SIZE: usize = 2048;

/// Run the bootnode given the CLI configuration.
pub fn run(
    global_config: &GlobalConfig,
    boot_node_config: &BootNode,
    eth_spec_id: EthSpecId,
    eth2_network_config: &Eth2NetworkConfig,
    debug_level: String,
) {
    let debug_level = match debug_level.as_str() {
        "trace" => log::Level::Trace,
        "debug" => log::Level::Debug,
        "info" => log::Level::Info,
        "warn" => log::Level::Warn,
        "error" => log::Level::Error,
        "crit" => log::Level::Error,
        _ => unreachable!(),
    };

    // Setting up the initial logger format and building it.
    let drain = {
        let decorator = slog_term::TermDecorator::new().build();
        let decorator = logging::AlignedTermDecorator::new(decorator, logging::MAX_MESSAGE_WIDTH);
        let drain = slog_term::FullFormat::new(decorator).build().fuse();
        slog_async::Async::new(drain)
            .chan_size(LOG_CHANNEL_SIZE)
            .build()
    };

    let drain = match debug_level {
        log::Level::Info => drain.filter_level(Level::Info),
        log::Level::Debug => drain.filter_level(Level::Debug),
        log::Level::Trace => drain.filter_level(Level::Trace),
        log::Level::Warn => drain.filter_level(Level::Warning),
        log::Level::Error => drain.filter_level(Level::Error),
    };

    let log = Logger::root(drain.fuse(), o!());

    // Run the main function emitting any errors
    if let Err(e) = match eth_spec_id {
        EthSpecId::Minimal => {
            main::<types::MinimalEthSpec>(global_config, boot_node_config, eth2_network_config, log)
        }
        EthSpecId::Mainnet => {
            main::<types::MainnetEthSpec>(global_config, boot_node_config, eth2_network_config, log)
        }
        EthSpecId::Gnosis => {
            main::<types::GnosisEthSpec>(global_config, boot_node_config, eth2_network_config, log)
        }
    } {
        slog::crit!(slog_scope::logger(), "{}", e);
    }
}

fn main<T: EthSpec>(
    global_config: &GlobalConfig,
    boot_node_config: &BootNode,
    eth2_network_config: &Eth2NetworkConfig,
    log: slog::Logger,
) -> Result<(), String> {
    // Builds a custom executor for the bootnode
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to build runtime: {}", e))?;

    // Run the boot node
    runtime.block_on(server::run::<T>(
        global_config,
        boot_node_config,
        eth2_network_config,
        log,
    ))?;

    Ok(())
}
