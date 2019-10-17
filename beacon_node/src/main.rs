#[macro_use]
extern crate clap;

mod cli;
mod config;
mod run;

use clap::{App, Arg, SubCommand};
use cli::cli_app;
use config::get_configs;
use env_logger::{Builder, Env};
use slog::{crit, o, warn, Drain, Level};

pub const DEFAULT_DATA_DIR: &str = ".lighthouse";
pub const CLIENT_CONFIG_FILENAME: &str = "beacon-node.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";
pub const TESTNET_CONFIG_FILENAME: &str = "testnet.toml";

fn main() {
    // debugging output for libp2p and external crates
    Builder::from_env(Env::default()).init();

    // Parse the CLI arguments.
    let matches = cli_app().get_matches();

    // build the initial logger
    let decorator = slog_term::TermDecorator::new().build();
    let decorator = logging::AlignedTermDecorator::new(decorator, logging::MAX_MESSAGE_WIDTH);
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_async::Async::new(drain).build();

    let drain = match matches.value_of("debug-level") {
        Some("info") => drain.filter_level(Level::Info),
        Some("debug") => drain.filter_level(Level::Debug),
        Some("trace") => drain.filter_level(Level::Trace),
        Some("warn") => drain.filter_level(Level::Warning),
        Some("error") => drain.filter_level(Level::Error),
        Some("crit") => drain.filter_level(Level::Critical),
        _ => unreachable!("guarded by clap"),
    };

    let log = slog::Logger::root(drain.fuse(), o!());

    if std::mem::size_of::<usize>() != 8 {
        crit!(
            log,
            "Lighthouse only supports 64bit CPUs";
            "detected" => format!("{}bit", std::mem::size_of::<usize>() * 8)
        );
    }

    warn!(
        log,
        "Ethereum 2.0 is pre-release. This software is experimental."
    );

    let log_clone = log.clone();

    // Load the process-wide configuration.
    //
    // May load this from disk or create a new configuration, depending on the CLI flags supplied.
    let (client_config, eth2_config, log) = match get_configs(&matches, log) {
        Ok(configs) => configs,
        Err(e) => {
            crit!(log_clone, "Failed to load configuration. Exiting"; "error" => e);
            return;
        }
    };

    // Start the node using a `tokio` executor.
    match run::run_beacon_node(client_config, eth2_config, log.clone()) {
        Ok(_) => {}
        Err(e) => crit!(log, "Beacon node failed to start"; "reason" => format!("{:}", e)),
    }
}
