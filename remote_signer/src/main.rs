use clap::{App, Arg, ArgMatches};
use client::Client;
use environment::EnvironmentBuilder;
use slog::info;
use std::path::PathBuf;
use std::process::exit;
use types::EthSpec;
use version::VERSION;

fn bls_library_name() -> &'static str {
    if cfg!(feature = "portable") {
        "blst-portable"
    } else if cfg!(feature = "milagro") {
        "milagro"
    } else {
        "blst"
    }
}

fn main() {
    // Parse the CLI parameters.
    let matches = App::new("Remote_Signer")
        .version(VERSION.replace("Remote_Signer/", "").as_str())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .setting(clap::AppSettings::ColoredHelp)
        .about(
            "Simple HTTP BLS signer service. \
            This service is designed to be consumed by Ethereum 2.0 clients, \
            looking for a more secure avenue to store their BLS12-381 secret keys, \
            while running their validators in more permisive and/or scalable environments.",
        )
        .long_version(
            format!(
                "{}\n\
                 BLS Library: {}",
                VERSION.replace("Remote_Signer/", ""),
                bls_library_name()
            )
            .as_str(),
        )
        .arg(
            Arg::with_name("spec")
                .long("spec")
                .value_name("TITLE")
                .help("Specifies the default eth2 spec type.")
                .takes_value(true)
                .possible_values(&["mainnet", "minimal", "interop"])
                .global(true)
                .default_value("mainnet"),
        )
        .arg(
            Arg::with_name("storage-raw-dir")
                .long("storage-raw-dir")
                .value_name("DIR")
                .help("Data directory for secret keys in raw files."),
        )
        .arg(
            Arg::with_name("logfile")
                .long("logfile")
                .value_name("FILE")
                .help("File path where output will be written.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("log-format")
                .long("log-format")
                .value_name("FORMAT")
                .help("Specifies the format used for logging.")
                .possible_values(&["JSON"])
                .takes_value(true),
        )
        .arg(
            Arg::with_name("debug-level")
                .long("debug-level")
                .value_name("LEVEL")
                .help("The verbosity level for emitting logs.")
                .takes_value(true)
                .possible_values(&["info", "debug", "trace", "warn", "error", "crit"])
                .global(true)
                .default_value("info"),
        )
        .arg(
            Arg::with_name("listen-address")
                .long("listen-address")
                .value_name("ADDRESS")
                .help("The address to listen for TCP connections.")
                .default_value("0.0.0.0")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("port")
                .long("port")
                .value_name("PORT")
                .help("The TCP port to listen on.")
                .default_value("9000")
                .takes_value(true),
        )
        .get_matches();

    macro_rules! run_with_spec {
        ($env_builder: expr) => {
            run($env_builder, &matches)
        };
    }

    let result = match matches.value_of("spec") {
        Some("minimal") => run_with_spec!(EnvironmentBuilder::minimal()),
        Some("mainnet") => run_with_spec!(EnvironmentBuilder::mainnet()),
        spec => {
            // This path should be unreachable due to slog having a `default_value`
            unreachable!("Unknown spec configuration: {:?}", spec);
        }
    };

    // `std::process::exit` does not run destructors so we drop manually.
    drop(matches);

    // Return the appropriate error code.
    match result {
        Ok(()) => exit(0),
        Err(e) => {
            eprintln!("{}", e);
            drop(e);
            exit(1)
        }
    }
}

fn run<E: EthSpec>(
    environment_builder: EnvironmentBuilder<E>,
    matches: &ArgMatches,
) -> Result<(), String> {
    let debug_level = matches
        .value_of("debug-level")
        .ok_or_else(|| "Expected --debug-level flag".to_string())?;

    let log_format = matches.value_of("log-format");

    let builder = if let Some(log_path) = matches.value_of("logfile") {
        let path = log_path
            .parse::<PathBuf>()
            .map_err(|e| format!("Failed to parse log path: {:?}", e))?;
        environment_builder.log_to_file(path, debug_level, log_format)?
    } else {
        environment_builder.async_logger(debug_level, log_format)?
    };

    let mut environment = builder.multi_threaded_tokio_runtime()?.build()?;

    let log = environment.core_context().log().clone();

    info!(log, "Remote Signer started"; "version" => VERSION);

    let runtime_context = environment.core_context();

    let client = environment
        .runtime()
        .block_on(Client::new(runtime_context, matches))
        .map_err(|e| format!("Failed to init Rest API: {}", e))?;

    // Block this thread until we get a ctrl-c or a task sends a shutdown signal.
    environment.block_until_shutdown_requested()?;
    info!(log, "Shutting down..");

    // Shut down all spawned services
    environment.fire_signal();
    drop(client);

    Ok(())
}
