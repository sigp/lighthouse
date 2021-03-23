//! Creates a simple DISCV5 server which can be used to bootstrap an Eth2 network.
use clap::ArgMatches;
use slog::{o, Drain, Level, Logger};

use std::convert::TryFrom;
mod cli;
mod config;
mod server;
pub use cli::cli_app;
use config::BootNodeConfig;
use types::{EthSpec, EthSpecId};

const LOG_CHANNEL_SIZE: usize = 2048;

/// Run the bootnode given the CLI configuration.
pub fn run(matches: &ArgMatches<'_>, eth_spec_id: EthSpecId, debug_level: String) {
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
    let _log_guard = slog_stdlog::init_with_level(debug_level).unwrap();

    let log = slog_scope::logger();
    // Run the main function emitting any errors
    if let Err(e) = match eth_spec_id {
        EthSpecId::Minimal => main::<types::MinimalEthSpec>(matches, log),
        EthSpecId::Mainnet => main::<types::MainnetEthSpec>(matches, log),
    } {
        slog::crit!(slog_scope::logger(), "{}", e);
    }
}

fn main<T: EthSpec>(matches: &ArgMatches<'_>, log: slog::Logger) -> Result<(), String> {
    // Builds a custom executor for the bootnode
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("Failed to build runtime: {}", e))?;

    // parse the CLI args into a useable config
    let config: BootNodeConfig<T> = BootNodeConfig::try_from(matches)?;

    // Run the boot node
    runtime.block_on(server::run(config, log));
    Ok(())
}
