//! Creates a simple DISCV5 server which can be used to bootstrap an Eth2 network.
use clap::ArgMatches;
use slog::{o, Drain, Level, Logger};

use eth2_network_config::Eth2NetworkConfig;
mod cli;
pub mod config;
mod server;
pub use cli::cli_app;
use config::BootNodeConfig;
use types::{EthSpec, EthSpecId};

const LOG_CHANNEL_SIZE: usize = 2048;

/// Run the bootnode given the CLI configuration.
pub fn run(
    lh_matches: &ArgMatches<'_>,
    bn_matches: &ArgMatches<'_>,
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

    let logger = Logger::root(drain.fuse(), o!());
    let _scope_guard = slog_scope::set_global_logger(logger);
    slog_stdlog::init_with_level(debug_level).unwrap();

    let log = slog_scope::logger();
    // Run the main function emitting any errors
    if let Err(e) = match eth_spec_id {
        EthSpecId::Minimal => {
            main::<types::MinimalEthSpec>(lh_matches, bn_matches, eth2_network_config, log)
        }
        EthSpecId::Mainnet => {
            main::<types::MainnetEthSpec>(lh_matches, bn_matches, eth2_network_config, log)
        }
        EthSpecId::Gnosis => {
            main::<types::GnosisEthSpec>(lh_matches, bn_matches, eth2_network_config, log)
        }
    } {
        slog::crit!(slog_scope::logger(), "{}", e);
    }
}

fn main<T: EthSpec>(
    lh_matches: &ArgMatches<'_>,
    bn_matches: &ArgMatches<'_>,
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
        lh_matches,
        bn_matches,
        eth2_network_config,
        log,
    ))?;

    Ok(())
}
