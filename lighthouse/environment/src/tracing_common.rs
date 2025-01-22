use crate::{EnvironmentBuilder, LoggerConfig};
use clap::ArgMatches;
use logging::Libp2pDiscv5TracingLayer;
use logging::{tracing_logging_layer::LoggingLayer, SSELoggingComponents};
use std::process;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::filter::Targets;
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
    LoggerConfig,
    Targets,
    Targets,
) {
    let libp2p_discv5_layer =
        logging::create_libp2p_discv5_tracing_layer(logger_config.path.clone());

    let logfile_prefix = matches.subcommand_name().unwrap_or("lighthouse");

    let (builder, file_logging_layer, stdout_logging_layer, sse_logging_layer_opt) =
        environment_builder.init_tracing(logger_config.clone(), logfile_prefix);

    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(logger_config.debug_level.to_string().to_lowercase()))
        .unwrap();

    let discv5_logs_off = Targets::new()
        .with_target("discv5", tracing::level_filters::LevelFilter::OFF)
        .with_default(logger_config.debug_level);
    let discv5_file_logs_off = Targets::new()
        .with_target("discv5", tracing::level_filters::LevelFilter::OFF)
        .with_default(logger_config.logfile_debug_level);

    (
        builder,
        filter_layer,
        libp2p_discv5_layer,
        file_logging_layer,
        stdout_logging_layer,
        sse_logging_layer_opt,
        logger_config,
        discv5_logs_off,
        discv5_file_logs_off,
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
