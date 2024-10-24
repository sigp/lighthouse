use env_logger::Builder;
use tracing::info;
use tracing::log::LevelFilter;
use std::process;

pub fn init_logger(log_level: &str) {
    let log_level = match log_level.to_lowercase().as_str() {
        "error" => LevelFilter::Error,
        "warn" => LevelFilter::Warn,
        "info" => LevelFilter::Info,
        "debug" => LevelFilter::Debug,
        "trace" => LevelFilter::Trace,
        _ => {
            eprintln!("Unsupported log level");
            process::exit(1)
        }
    };

    let mut builder = Builder::new();
    builder.filter(Some("watch"), log_level);

    builder.init();

    info!("Logger initialized with log-level: {log_level}");
}
