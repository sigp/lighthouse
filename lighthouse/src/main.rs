use beacon_node::ProductionBeaconNode;
use clap::{App, Arg, ArgMatches};
use env_logger::{Builder, Env};
use environment::EnvironmentBuilder;
use eth2_testnet_config::{Eth2TestnetConfig, DEFAULT_HARDCODED_TESTNET};
use lighthouse_version::VERSION;
use slog::{crit, info, warn};
use std::path::PathBuf;
use std::process::exit;
use types::EthSpec;
use validator_client::ProductionValidatorClient;

pub const DEFAULT_DATA_DIR: &str = ".lighthouse";
pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";

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
    let matches = App::new("Lighthouse")
        .version(VERSION.replace("Lighthouse/", "").as_str())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .setting(clap::AppSettings::ColoredHelp)
        .about(
            "Ethereum 2.0 client by Sigma Prime. Provides a full-featured beacon \
             node, a validator client and utilities for managing validator accounts.",
        )
        .long_version(
            format!(
                "{}\n\
                 BLS Library: {}",
                 VERSION.replace("Lighthouse/", ""), bls_library_name()
            ).as_str()
        )
        .arg(
            Arg::with_name("spec")
                .short("s")
                .long("spec")
                .value_name("TITLE")
                .help("Specifies the default eth2 spec type.")
                .takes_value(true)
                .possible_values(&["mainnet", "minimal", "interop"])
                .global(true)
                .default_value("mainnet"),
        )
        .arg(
            Arg::with_name("env_log")
                .short("l")
                .help("Enables environment logging giving access to sub-protocol logs such as discv5 and libp2p",
                )
                .takes_value(false),
        )
        .arg(
            Arg::with_name("logfile")
                .long("logfile")
                .value_name("FILE")
                .help(
                    "File path where output will be written.",
                )
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
            Arg::with_name("datadir")
                .long("datadir")
                .short("d")
                .value_name("DIR")
                .global(true)
                .help("Data directory for lighthouse keys and databases.")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("testnet-dir")
                .short("t")
                .long("testnet-dir")
                .value_name("DIR")
                .help(
                    "Path to directory containing eth2_testnet specs. Defaults to \
                      a hard-coded Lighthouse testnet. Only effective if there is no \
                      existing database.",
                )
                .takes_value(true)
                .global(true),
        )
        .arg(
            Arg::with_name("testnet")
                .long("testnet")
                .value_name("testnet")
                .help("Name of network lighthouse will connect to")
                .possible_values(&["medalla", "altona", "spadina"])
                .conflicts_with("testnet-dir")
                .takes_value(true)
                .global(true)

        )
        .subcommand(beacon_node::cli_app())
        .subcommand(boot_node::cli_app())
        .subcommand(validator_client::cli_app())
        .subcommand(account_manager::cli_app())
        .get_matches();

    // boot node subcommand circumvents the environment
    if let Some(bootnode_matches) = matches.subcommand_matches("boot_node") {
        // The bootnode uses the main debug-level flag
        let debug_info = matches
            .value_of("debug-level")
            .expect("Debug-level must be present")
            .into();
        boot_node::run(bootnode_matches, debug_info);
        return;
    }

    // Debugging output for libp2p and external crates.
    if matches.is_present("env_log") {
        Builder::from_env(Env::default()).init();
    }

    macro_rules! run_with_spec {
        ($env_builder: expr) => {
            run($env_builder, &matches)
        };
    }

    let result = match matches.value_of("spec") {
        Some("minimal") => run_with_spec!(EnvironmentBuilder::minimal()),
        Some("mainnet") => run_with_spec!(EnvironmentBuilder::mainnet()),
        Some("interop") => run_with_spec!(EnvironmentBuilder::interop()),
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
    if std::mem::size_of::<usize>() != 8 {
        return Err(format!(
            "{}bit architecture is not supported (64bit only).",
            std::mem::size_of::<usize>() * 8
        ));
    }

    let debug_level = matches
        .value_of("debug-level")
        .ok_or_else(|| "Expected --debug-level flag".to_string())?;

    let log_format = matches.value_of("log-format");

    // Parse testnet config from the `testnet` and `testnet-dir` flag in that order
    // else, use the default
    let mut optional_testnet_config = None;
    if matches.is_present("testnet") {
        optional_testnet_config = clap_utils::parse_hardcoded_network(matches, "testnet")?;
    };
    if matches.is_present("testnet-dir") {
        optional_testnet_config = clap_utils::parse_testnet_dir(matches, "testnet-dir")?;
    };
    if optional_testnet_config.is_none() {
        optional_testnet_config = Eth2TestnetConfig::hard_coded_default()?;
    }

    let builder = if let Some(log_path) = matches.value_of("logfile") {
        let path = log_path
            .parse::<PathBuf>()
            .map_err(|e| format!("Failed to parse log path: {:?}", e))?;
        environment_builder.log_to_file(path, debug_level, log_format)?
    } else {
        environment_builder.async_logger(debug_level, log_format)?
    };

    let mut environment = builder
        .multi_threaded_tokio_runtime()?
        .optional_eth2_testnet_config(optional_testnet_config)?
        .build()?;

    let log = environment.core_context().log().clone();

    // Note: the current code technically allows for starting a beacon node _and_ a validator
    // client at the same time.
    //
    // Whilst this is possible, the mutual-exclusivity of `clap` sub-commands prevents it from
    // actually happening.
    //
    // Creating a command which can run both might be useful future works.

    // Print an indication of which network is currently in use.
    let optional_testnet = clap_utils::parse_optional::<String>(matches, "testnet")?;
    let optional_testnet_dir = clap_utils::parse_optional::<PathBuf>(matches, "testnet-dir")?;

    let testnet_name = match (optional_testnet, optional_testnet_dir) {
        (Some(testnet), None) => testnet,
        (None, Some(testnet_dir)) => format!("custom ({})", testnet_dir.display()),
        (None, None) => DEFAULT_HARDCODED_TESTNET.to_string(),
        (Some(_), Some(_)) => panic!("CLI prevents both --testnet and --testnet-dir"),
    };

    if let Some(sub_matches) = matches.subcommand_matches("account_manager") {
        eprintln!("Running account manager for {} testnet", testnet_name);
        // Pass the entire `environment` to the account manager so it can run blocking operations.
        account_manager::run(sub_matches, environment)?;

        // Exit as soon as account manager returns control.
        return Ok(());
    };

    warn!(
        log,
        "Ethereum 2.0 is pre-release. This software is experimental."
    );
    info!(log, "Lighthouse started"; "version" => VERSION);
    info!(
        log,
        "Configured for testnet";
        "name" => testnet_name
    );

    let beacon_node = if let Some(sub_matches) = matches.subcommand_matches("beacon_node") {
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

    let validator_client = if let Some(sub_matches) = matches.subcommand_matches("validator_client")
    {
        let runtime_context = environment.core_context();

        let mut validator = environment
            .runtime()
            .block_on(ProductionValidatorClient::new_from_cli(
                runtime_context,
                sub_matches,
            ))
            .map_err(|e| format!("Failed to init validator client: {}", e))?;

        environment
            .core_context()
            .executor
            .runtime_handle()
            .enter(|| {
                validator
                    .start_service()
                    .map_err(|e| format!("Failed to start validator client service: {}", e))
            })?;

        Some(validator)
    } else {
        None
    };

    if beacon_node.is_none() && validator_client.is_none() {
        crit!(log, "No subcommand supplied. See --help .");
        return Err("No subcommand supplied.".into());
    }

    // Block this thread until we get a ctrl-c or a task sends a shutdown signal.
    environment.block_until_shutdown_requested()?;
    info!(log, "Shutting down..");

    environment.fire_signal();
    drop(beacon_node);
    drop(validator_client);

    // Shutdown the environment once all tasks have completed.
    environment.shutdown_on_idle();
    Ok(())
}
