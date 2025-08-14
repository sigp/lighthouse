use crate::{EnvironmentBuilder, LoggerConfig};
use clap::ArgMatches;
use logging::Libp2pDiscv5TracingLayer;
use logging::{
    SSELoggingComponents, create_libp2p_discv5_tracing_layer, tracing_logging_layer::LoggingLayer,
};
use std::process;

use tracing_subscriber::filter::LevelFilter;
use types::EthSpec;

/// Constructs all logging layers including both Lighthouse-specific and
/// dependency logging.
///
/// The `Layer`s are as follows:
/// - A `Layer` which logs to `stdout`
/// - An `Option<Layer>` which logs to a log file
/// - An `Option<Layer>` which emits logs to an SSE stream
/// - An `Option<Layer>` which logs relevant dependencies to their
///   own log files. (Currently only `libp2p` and `discv5`)
pub fn construct_logger<E: EthSpec>(
    logger_config: LoggerConfig,
    matches: &ArgMatches,
    environment_builder: EnvironmentBuilder<E>,
) -> (
    EnvironmentBuilder<E>,
    LoggerConfig,
    LoggingLayer,
    Option<LoggingLayer>,
    Option<SSELoggingComponents>,
    Option<Libp2pDiscv5TracingLayer>,
) {
    let subcommand_name = matches.subcommand_name();
    let logfile_prefix = subcommand_name.unwrap_or("lighthouse");

    let file_mode = if logger_config.is_restricted {
        0o600
    } else {
        0o644
    };

    let (builder, stdout_logging_layer, file_logging_layer, sse_logging_layer_opt) =
        environment_builder.init_tracing(logger_config.clone(), logfile_prefix, file_mode);

    let libp2p_discv5_layer = if let Some(subcommand_name) = subcommand_name {
        if subcommand_name == "beacon_node"
            || subcommand_name == "boot_node"
            || subcommand_name == "basic-sim"
            || subcommand_name == "fallback-sim"
        {
            if logger_config.max_log_size == 0 || logger_config.max_log_number == 0 {
                // User has explicitly disabled logging to file.
                None
            } else {
                create_libp2p_discv5_tracing_layer(
                    logger_config.path.clone(),
                    logger_config.max_log_size,
                    file_mode,
                )
            }
        } else {
            // Disable libp2p and discv5 logs when running other subcommands.
            None
        }
    } else {
        None
    };

    (
        builder,
        logger_config,
        stdout_logging_layer,
        file_logging_layer,
        sse_logging_layer_opt,
        libp2p_discv5_layer,
    )
}

pub fn parse_level(level: &str) -> LevelFilter {
    match level.to_lowercase().as_str() {
        "error" => LevelFilter::ERROR,
        "warn" => LevelFilter::WARN,
        "info" => LevelFilter::INFO,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        _ => {
            eprintln!("Unsupported log level");
            process::exit(1)
        }
    }
}
