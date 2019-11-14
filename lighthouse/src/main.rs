#[macro_use]
extern crate clap;

use beacon_node::ProductionBeaconNode;
use clap::{App, Arg, ArgMatches};
use env_logger::{Builder, Env};
use environment::EnvironmentBuilder;
use slog::{crit, info, warn};
use std::path::PathBuf;
use std::process::exit;
use types::EthSpec;
use validator_client::ProductionValidatorClient;

pub const DEFAULT_DATA_DIR: &str = ".lighthouse";
pub const CLIENT_CONFIG_FILENAME: &str = "beacon-node.toml";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";

fn main() {
    // Debugging output for libp2p and external crates.
    Builder::from_env(Env::default()).init();

    // Parse the CLI parameters.
    let matches = App::new("Lighthouse")
        .version(crate_version!())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .about("Eth 2.0 Client")
        .arg(
            Arg::with_name("spec")
                .short("s")
                .long("spec")
                .value_name("TITLE")
                .help("Specifies the default eth2 spec type. Only effective when creating a new datadir.")
                .takes_value(true)
                .required(true)
                .possible_values(&["mainnet", "minimal", "interop"])
                .global(true)
                .default_value("minimal")
        )
        .arg(
            Arg::with_name("logfile")
                .long("logfile")
                .value_name("FILE")
                .help("File path where output will be written.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("debug-level")
                .long("debug-level")
                .value_name("LEVEL")
                .help("The title of the spec constants for chain config.")
                .takes_value(true)
                .possible_values(&["info", "debug", "trace", "warn", "error", "crit"])
                .default_value("trace"),
        )
        .subcommand(beacon_node::cli_app())
        .subcommand(validator_client::cli_app())
        .subcommand(account_manager::cli_app())
        .get_matches();

    macro_rules! run_with_spec {
        ($env_builder: expr) => {
            match run($env_builder, &matches) {
                Ok(()) => exit(0),
                Err(e) => {
                    println!("Failed to start Lighthouse: {}", e);
                    exit(1)
                }
            }
        };
    }

    match matches.value_of("spec") {
        Some("minimal") => run_with_spec!(EnvironmentBuilder::minimal()),
        Some("mainnet") => run_with_spec!(EnvironmentBuilder::mainnet()),
        Some("interop") => run_with_spec!(EnvironmentBuilder::interop()),
        spec => {
            // This path should be unreachable due to slog having a `default_value`
            unreachable!("Unknown spec configuration: {:?}", spec);
        }
    }
}

fn run<E: EthSpec>(
    environment_builder: EnvironmentBuilder<E>,
    matches: &ArgMatches,
) -> Result<(), String> {
    let mut environment = environment_builder
        .async_logger(
            matches
                .value_of("debug-level")
                .ok_or_else(|| "Expected --debug-level flag".to_string())?,
        )?
        .multi_threaded_tokio_runtime()?
        .build()?;

    let log = environment.core_context().log;

    if let Some(log_path) = matches.value_of("logfile") {
        let path = log_path
            .parse::<PathBuf>()
            .map_err(|e| format!("Failed to parse log path: {:?}", e))?;
        environment.log_to_json_file(path)?;
    }

    if std::mem::size_of::<usize>() != 8 {
        crit!(
            log,
            "Lighthouse only supports 64bit CPUs";
            "detected" => format!("{}bit", std::mem::size_of::<usize>() * 8)
        );
        return Err("Invalid CPU architecture".into());
    }

    warn!(
        log,
        "Ethereum 2.0 is pre-release. This software is experimental."
    );

    // Note: the current code technically allows for starting a beacon node _and_ a validator
    // client at the same time.
    //
    // Whilst this is possible, the mutual-exclusivity of `clap` sub-commands prevents it from
    // actually happening.
    //
    // Creating a command which can run both might be useful future works.

    if let Some(sub_matches) = matches.subcommand_matches("Account Manager") {
        let runtime_context = environment.core_context();

        account_manager::run(sub_matches, runtime_context);

        // Exit early if the account manager was run. It does not used the tokio executor, so no
        // need to wait for it to shutdown.
        return Ok(());
    }

    let beacon_node = if let Some(sub_matches) = matches.subcommand_matches("Beacon Node") {
        let runtime_context = environment.core_context();

        let beacon = environment
            .runtime()
            .block_on(ProductionBeaconNode::new_from_cli(
                runtime_context,
                sub_matches,
            ))
            .map_err(|e| format!("Failed to start beacon node: {}", e))?;

        Some(beacon)
    } else {
        None
    };

    let validator_client = if let Some(sub_matches) = matches.subcommand_matches("Validator Client")
    {
        let runtime_context = environment.core_context();

        let validator = ProductionValidatorClient::new_from_cli(runtime_context, sub_matches)
            .map_err(|e| format!("Failed to init validator client: {}", e))?;

        validator
            .start_service()
            .map_err(|e| format!("Failed to start validator client service: {}", e))?;

        Some(validator)
    } else {
        None
    };

    if beacon_node.is_none() && validator_client.is_none() {
        crit!(log, "No subcommand supplied. See --help .");
        return Err("No subcommand supplied.".into());
    }

    // Block this thread until Crtl+C is pressed.
    environment.block_until_ctrl_c()?;

    info!(log, "Shutting down..");

    drop(beacon_node);
    drop(validator_client);

    // Shutdown the environment once all tasks have completed.
    environment.shutdown_on_idle()
}
