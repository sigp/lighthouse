use crate::{EnvironmentBuilder, LoggerConfig};
use clap::ArgMatches;
use logging::Libp2pDiscv5TracingLayer;
use logging::{tracing_logging_layer::LoggingLayer, SSELoggingComponents};
use std::process;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use types::EthSpec;

pub fn construct_logger<E: EthSpec>(
    logger_config: LoggerConfig,
    matches: &ArgMatches,
    environment_builder: EnvironmentBuilder<E>,
) -> (
    EnvironmentBuilder<E>,
    EnvFilter,
    Libp2pDiscv5TracingLayer,
    LoggingLayer,
    LoggingLayer,
    Option<SSELoggingComponents>,
    LevelFilter,
    LevelFilter,
    LoggerConfig,
) {
    let libp2p_discv5_layer =
        logging::create_libp2p_discv5_tracing_layer(logger_config.path.clone());

    let logfile_prefix = match matches.subcommand_name() {
        Some(subcommand) => subcommand,
        None => "lighthouse",
    };

    let (builder, file_logging_layer, stdout_logging_layer, sse_logging_layer_opt) =
        environment_builder.init_tracing(logger_config.clone(), logfile_prefix);

    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(logger_config.debug_level.to_lowercase().as_str()))
        .unwrap();

    let stdout_level = match logger_config.debug_level.to_lowercase().as_str() {
        "error" => LevelFilter::ERROR,
        "warn" => LevelFilter::WARN,
        "info" => LevelFilter::INFO,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        _ => {
            eprintln!("Unsupported log level");
            process::exit(1)
        }
    };

    let file_level = match logger_config.logfile_debug_level.to_lowercase().as_str() {
        "error" => LevelFilter::ERROR,
        "warn" => LevelFilter::WARN,
        "info" => LevelFilter::INFO,
        "debug" => LevelFilter::DEBUG,
        "trace" => LevelFilter::TRACE,
        _ => {
            eprintln!("Unsupported log level");
            process::exit(1)
        }
    };
    (
        builder,
        filter_layer,
        libp2p_discv5_layer,
        file_logging_layer,
        stdout_logging_layer,
        sse_logging_layer_opt,
        stdout_level,
        file_level,
        logger_config,
    )
}
