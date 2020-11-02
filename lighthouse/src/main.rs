use beacon_node::ProductionBeaconNode;
use clap::{App, Arg, ArgMatches};
use env_logger::{Builder, Env};
use environment::EnvironmentBuilder;
use eth2_testnet_config::{Eth2TestnetConfig, DEFAULT_HARDCODED_TESTNET};
use lighthouse_version::VERSION;
use slog::{crit, info, warn};
use std::path::PathBuf;
use std::process::exit;
use types::{EthSpec, EthSpecId};
use validator_client::ProductionValidatorClient;

pub const ETH2_CONFIG_FILENAME: &str = "eth2-spec.toml";

fn bls_library_name() -> &'static str {
    if cfg!(feature = "portable") {
        "blst-portable"
    } else if cfg!(feature = "modern") {
        "blst-modern"
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
                .value_name("DEPRECATED")
                .help("This flag is deprecated, it will be disallowed in a future release. This \
                    value is now derived from the --testnet or --testnet-dir flags.")
                .takes_value(true)
                .global(true)
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
                .help(
                    "Used to specify a custom root data directory for lighthouse keys and databases. \
                    Defaults to $HOME/.lighthouse/{testnet} where testnet is the value of the `testnet` flag \
                    Note: Users should specify separate custom datadirs for different testnets.")
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
                .possible_values(&["medalla", "altona", "spadina", "zinken"])
                .conflicts_with("testnet-dir")
                .takes_value(true)
                .global(true)

        )
        .subcommand(beacon_node::cli_app())
        .subcommand(boot_node::cli_app())
        .subcommand(validator_client::cli_app())
        .subcommand(account_manager::cli_app())
        .get_matches();

    // Debugging output for libp2p and external crates.
    if matches.is_present("env_log") {
        Builder::from_env(Env::default()).init();
    }

    let result = load_testnet_config(&matches).and_then(|testnet_config| {
        let eth_spec_id = testnet_config.eth_spec_id()?;

        // boot node subcommand circumvents the environment
        if let Some(bootnode_matches) = matches.subcommand_matches("boot_node") {
            // The bootnode uses the main debug-level flag
            let debug_info = matches
                .value_of("debug-level")
                .expect("Debug-level must be present")
                .into();

            boot_node::run(bootnode_matches, eth_spec_id, debug_info);

            return Ok(());
        }

        match eth_spec_id {
            EthSpecId::Minimal => run(EnvironmentBuilder::minimal(), &matches, testnet_config),
            EthSpecId::Mainnet => run(EnvironmentBuilder::mainnet(), &matches, testnet_config),
            EthSpecId::V012Legacy => {
                run(EnvironmentBuilder::v012_legacy(), &matches, testnet_config)
            }
        }
    });

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

fn load_testnet_config(matches: &ArgMatches) -> Result<Eth2TestnetConfig, String> {
    if matches.is_present("testnet-dir") {
        clap_utils::parse_testnet_dir(matches, "testnet-dir")?
            .ok_or_else(|| "Unable to load testnet dir".to_string())
    } else if matches.is_present("testnet") {
        clap_utils::parse_hardcoded_network(matches, "testnet")?
            .ok_or_else(|| "Unable to load hard coded network config".to_string())
    } else {
        Eth2TestnetConfig::hard_coded_default()?
            .ok_or_else(|| "Unable to load default network config".to_string())
    }
}

fn run<E: EthSpec>(
    environment_builder: EnvironmentBuilder<E>,
    matches: &ArgMatches,
    testnet_config: Eth2TestnetConfig,
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
        .optional_eth2_testnet_config(Some(testnet_config))?
        .build()?;

    let log = environment.core_context().log().clone();

    if matches.is_present("spec") {
        warn!(
            log,
            "The --spec flag is deprecated and will be removed in a future release"
        );
    }

    #[cfg(all(feature = "modern", target_arch = "x86_64"))]
    if !std::is_x86_feature_detected!("adx") {
        warn!(
            log,
            "CPU seems incompatible with optimized Lighthouse build";
            "advice" => "If you get a SIGILL, please try Lighthouse portable build"
        );
    }

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

    match matches.subcommand() {
        ("beacon_node", Some(matches)) => {
            let context = environment.core_context();
            let log = context.log().clone();
            let executor = context.executor.clone();
            let config = beacon_node::get_config::<E>(
                matches,
                &context.eth2_config().spec,
                context.log().clone(),
            )?;
            environment.runtime().spawn(async move {
                if let Err(e) = ProductionBeaconNode::new(context.clone(), config).await {
                    crit!(log, "Failed to start beacon node"; "reason" => e);
                    // Ignore the error since it always occurs during normal operation when
                    // shutting down.
                    let _ = executor
                        .shutdown_sender()
                        .try_send("Failed to start beacon node");
                }
            })
        }
        ("validator_client", Some(matches)) => {
            let context = environment.core_context();
            let log = context.log().clone();
            let executor = context.executor.clone();
            let config = validator_client::Config::from_cli(&matches, context.log())
                .map_err(|e| format!("Unable to initialize validator config: {}", e))?;
            environment.runtime().spawn(async move {
                let run = async {
                    ProductionValidatorClient::new(context, config)
                        .await?
                        .start_service()?;

                    Ok::<(), String>(())
                };
                if let Err(e) = run.await {
                    crit!(log, "Failed to start validator client"; "reason" => e);
                    // Ignore the error since it always occurs during normal operation when
                    // shutting down.
                    let _ = executor
                        .shutdown_sender()
                        .try_send("Failed to start validator client");
                }
            })
        }
        _ => {
            crit!(log, "No subcommand supplied. See --help .");
            return Err("No subcommand supplied.".into());
        }
    };

    // Block this thread until we get a ctrl-c or a task sends a shutdown signal.
    environment.block_until_shutdown_requested()?;
    info!(log, "Shutting down..");

    environment.fire_signal();

    // Shutdown the environment once all tasks have completed.
    environment.shutdown_on_idle();
    Ok(())
}
