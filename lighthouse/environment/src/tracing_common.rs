use crate::{EnvironmentBuilder, LoggerConfig};
use clap::ArgMatches;
use logging::Libp2pDiscv5TracingLayer;
use logging::{tracing_logging_layer::LoggingLayer, SSELoggingComponents};
use std::process;
use tracing_subscriber::filter::{EnvFilter, FilterFn, LevelFilter};
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
    FilterFn,
) {
    let libp2p_discv5_layer = logging::create_libp2p_discv5_tracing_layer(
        logger_config.path.clone(),
        logger_config.max_log_size,
        logger_config.compression,
        logger_config.max_log_number,
    );

    let logfile_prefix = matches.subcommand_name().unwrap_or("lighthouse");

    let (builder, file_logging_layer, stdout_logging_layer, sse_logging_layer_opt) =
        environment_builder.init_tracing(logger_config.clone(), logfile_prefix);

    let filter_layer = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(logger_config.debug_level.to_string().to_lowercase()))
        .unwrap();

    let dependency_log_filter =
        FilterFn::new(filter_dependency_log as fn(&tracing::Metadata<'_>) -> bool);

    (
        builder,
        filter_layer,
        libp2p_discv5_layer,
        file_logging_layer,
        stdout_logging_layer,
        sse_logging_layer_opt,
        logger_config,
        dependency_log_filter,
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

fn filter_dependency_log(meta: &tracing::Metadata<'_>) -> bool {
    if let Some(file) = meta.file() {
        let target = meta.target();
        if file.contains("/.cargo/") {
            return target.contains("discv5") || target.contains("libp2p");
        } else {
            return !file.contains("gossipsub") && !target.contains("hyper");
        }
    }
    true
}
