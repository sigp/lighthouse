#![recursion_limit = "256"]

mod metrics;

use beacon_node::ProductionBeaconNode;
use clap::{App, Arg, ArgMatches};
use clap_utils::{flags::DISABLE_MALLOC_TUNING_FLAG, get_eth2_network_config};
use directory::{parse_path_or_default, DEFAULT_BEACON_NODE_DIR, DEFAULT_VALIDATOR_DIR};
use env_logger::{Builder, Env};
use environment::{EnvironmentBuilder, LoggerConfig};
use eth2_hashing::have_sha_extensions;
use eth2_network_config::{Eth2NetworkConfig, DEFAULT_HARDCODED_NETWORK, HARDCODED_NET_NAMES};
use lighthouse_version::VERSION;
use malloc_utils::configure_memory_allocator;
use slog::{crit, info, warn};
use std::path::PathBuf;
use std::process::exit;
use task_executor::ShutdownReason;
use types::{EthSpec, EthSpecId};
use validator_client::ProductionValidatorClient;

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
    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var("RUST_BACKTRACE").is_err() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

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
                 BLS library: {}\n\
                 SHA256 hardware acceleration: {}\n\
                 Specs: mainnet (true), minimal ({}), gnosis ({})",
                 VERSION.replace("Lighthouse/", ""),
                 bls_library_name(),
                 have_sha_extensions(),
                 cfg!(feature = "spec-minimal"),
                 cfg!(feature = "gnosis"),
            ).as_str()
        )
        .arg(
            Arg::with_name("spec")
                .short("s")
                .long("spec")
                .value_name("DEPRECATED")
                .help("This flag is deprecated, it will be disallowed in a future release. This \
                    value is now derived from the --network or --testnet-dir flags.")
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
                    "File path where the log file will be stored. Once it grows to the \
                    value specified in `--logfile-max-size` a new log file is generated where \
                    future logs are stored. \
                    Once the number of log files exceeds the value specified in \
                    `--logfile-max-number` the oldest log file will be overwritten.")
                .takes_value(true)
                .global(true),
        )
        .arg(
            Arg::with_name("logfile-debug-level")
                .long("logfile-debug-level")
                .value_name("LEVEL")
                .help("The verbosity level used when emitting logs to the log file.")
                .takes_value(true)
                .possible_values(&["info", "debug", "trace", "warn", "error", "crit"])
                .default_value("debug")
                .global(true),
        )
        .arg(
            Arg::with_name("logfile-max-size")
                .long("logfile-max-size")
                .value_name("SIZE")
                .help(
                    "The maximum size (in MB) each log file can grow to before rotating. If set \
                    to 0, background file logging is disabled.")
                .takes_value(true)
                .default_value("200")
                .global(true),
        )
        .arg(
            Arg::with_name("logfile-max-number")
                .long("logfile-max-number")
                .value_name("COUNT")
                .help(
                    "The maximum number of log files that will be stored. If set to 0, \
                    background file logging is disabled.")
                .takes_value(true)
                .default_value("5")
                .global(true),
        )
        .arg(
            Arg::with_name("logfile-compress")
                .long("logfile-compress")
                .help(
                    "If present, compress old log files. This can help reduce the space needed \
                    to store old logs.")
                .global(true),
        )
        .arg(
            Arg::with_name("log-format")
                .long("log-format")
                .value_name("FORMAT")
                .help("Specifies the log format used when emitting logs to the terminal.")
                .possible_values(&["JSON"])
                .takes_value(true)
                .global(true),
        )
        .arg(
            Arg::with_name("debug-level")
                .long("debug-level")
                .value_name("LEVEL")
                .help("Specifies the verbosity level used when emitting logs to the terminal.")
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
                    Defaults to $HOME/.lighthouse/{network} where network is the value of the `network` flag \
                    Note: Users should specify separate custom datadirs for different networks.")
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
            Arg::with_name("network")
                .long("network")
                .value_name("network")
                .help("Name of the Eth2 chain Lighthouse will sync and follow.")
                .possible_values(HARDCODED_NET_NAMES)
                .conflicts_with("testnet-dir")
                .takes_value(true)
                .global(true)

        )
        .arg(
            Arg::with_name("dump-config")
                .long("dump-config")
                .hidden(true)
                .help("Dumps the config to a desired location. Used for testing only.")
                .takes_value(true)
                .global(true)
        )
        .arg(
            Arg::with_name("dump-chain-config")
                .long("dump-chain-config")
                .hidden(true)
                .help("Dumps the chain config to a desired location. Used for testing only.")
                .takes_value(true)
                .global(true)
        )
        .arg(
            Arg::with_name("immediate-shutdown")
                .long("immediate-shutdown")
                .hidden(true)
                .help(
                    "Shuts down immediately after the Beacon Node or Validator has successfully launched. \
                    Used for testing only, DO NOT USE IN PRODUCTION.")
                .global(true)
        )
        .arg(
            Arg::with_name(DISABLE_MALLOC_TUNING_FLAG)
                .long(DISABLE_MALLOC_TUNING_FLAG)
                .help(
                    "If present, do not configure the system allocator. Providing this flag will \
                    generally increase memory usage, it should only be provided when debugging \
                    specific memory allocation issues."
                )
                .global(true),
        )
        .arg(
            Arg::with_name("terminal-total-difficulty-override")
                .long("terminal-total-difficulty-override")
                .value_name("INTEGER")
                .help("Used to coordinate manual overrides to the TERMINAL_TOTAL_DIFFICULTY parameter. \
                       Accepts a 256-bit decimal integer (not a hex value). \
                       This flag should only be used if the user has a clear understanding that \
                       the broad Ethereum community has elected to override the terminal difficulty. \
                       Incorrect use of this flag will cause your node to experience a consensus \
                       failure. Be extremely careful with this flag.")
                .takes_value(true)
                .global(true)
        )
        .arg(
            Arg::with_name("terminal-block-hash-override")
                .long("terminal-block-hash-override")
                .value_name("TERMINAL_BLOCK_HASH")
                .help("Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH parameter. \
                       This flag should only be used if the user has a clear understanding that \
                       the broad Ethereum community has elected to override the terminal PoW block. \
                       Incorrect use of this flag will cause your node to experience a consensus \
                       failure. Be extremely careful with this flag.")
                .requires("terminal-block-hash-epoch-override")
                .takes_value(true)
                .global(true)
        )
        .arg(
            Arg::with_name("terminal-block-hash-epoch-override")
                .long("terminal-block-hash-epoch-override")
                .value_name("EPOCH")
                .help("Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH \
                       parameter. This flag should only be used if the user has a clear understanding \
                       that the broad Ethereum community has elected to override the terminal PoW block. \
                       Incorrect use of this flag will cause your node to experience a consensus \
                       failure. Be extremely careful with this flag.")
                .requires("terminal-block-hash-override")
                .takes_value(true)
                .global(true)
        )
        .arg(
            Arg::with_name("safe-slots-to-import-optimistically")
                .long("safe-slots-to-import-optimistically")
                .value_name("INTEGER")
                .help("Used to coordinate manual overrides of the SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY \
                      parameter. This flag should only be used if the user has a clear understanding \
                      that the broad Ethereum community has elected to override this parameter in the event \
                      of an attack at the PoS transition block. Incorrect use of this flag can cause your \
                      node to possibly accept an invalid chain or sync more slowly. Be extremely careful with \
                      this flag.")
                .takes_value(true)
                .global(true)
        )
        .subcommand(beacon_node::cli_app())
        .subcommand(boot_node::cli_app())
        .subcommand(validator_client::cli_app())
        .subcommand(account_manager::cli_app())
        .subcommand(database_manager::cli_app())
        .get_matches();

    // Configure the allocator early in the process, before it has the chance to use the default values for
    // anything important.
    //
    // Only apply this optimization for the beacon node. It's the only process with a substantial
    // memory footprint.
    let is_beacon_node = matches.subcommand_name() == Some("beacon_node");
    if is_beacon_node && !matches.is_present(DISABLE_MALLOC_TUNING_FLAG) {
        if let Err(e) = configure_memory_allocator() {
            eprintln!(
                "Unable to configure the memory allocator: {} \n\
                Try providing the --{} flag",
                e, DISABLE_MALLOC_TUNING_FLAG
            );
            exit(1)
        }
    }

    // Debugging output for libp2p and external crates.
    if matches.is_present("env_log") {
        Builder::from_env(Env::default()).init();
    }

    let result = get_eth2_network_config(&matches).and_then(|eth2_network_config| {
        let eth_spec_id = eth2_network_config.eth_spec_id()?;

        // boot node subcommand circumvents the environment
        if let Some(bootnode_matches) = matches.subcommand_matches("boot_node") {
            // The bootnode uses the main debug-level flag
            let debug_info = matches
                .value_of("debug-level")
                .expect("Debug-level must be present")
                .into();

            boot_node::run(
                &matches,
                bootnode_matches,
                eth_spec_id,
                &eth2_network_config,
                debug_info,
            );

            return Ok(());
        }

        match eth_spec_id {
            EthSpecId::Mainnet => run(EnvironmentBuilder::mainnet(), &matches, eth2_network_config),
            #[cfg(feature = "gnosis")]
            EthSpecId::Gnosis => run(EnvironmentBuilder::gnosis(), &matches, eth2_network_config),
            #[cfg(feature = "spec-minimal")]
            EthSpecId::Minimal => run(EnvironmentBuilder::minimal(), &matches, eth2_network_config),
            #[cfg(not(all(feature = "spec-minimal", feature = "gnosis")))]
            other => {
                eprintln!(
                    "Eth spec `{}` is not supported by this build of Lighthouse",
                    other
                );
                eprintln!("You must compile with a feature flag to enable this spec variant");
                exit(1);
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

fn run<E: EthSpec>(
    environment_builder: EnvironmentBuilder<E>,
    matches: &ArgMatches,
    eth2_network_config: Eth2NetworkConfig,
) -> Result<(), String> {
    if std::mem::size_of::<usize>() != 8 {
        return Err(format!(
            "{}-bit architecture is not supported (64-bit only).",
            std::mem::size_of::<usize>() * 8
        ));
    }

    let debug_level = matches
        .value_of("debug-level")
        .ok_or("Expected --debug-level flag")?;

    let log_format = matches.value_of("log-format");

    let logfile_debug_level = matches
        .value_of("logfile-debug-level")
        .ok_or("Expected --logfile-debug-level flag")?;

    let logfile_max_size: u64 = matches
        .value_of("logfile-max-size")
        .ok_or("Expected --logfile-max-size flag")?
        .parse()
        .map_err(|e| format!("Failed to parse `logfile-max-size`: {:?}", e))?;

    let logfile_max_number: usize = matches
        .value_of("logfile-max-number")
        .ok_or("Expected --logfile-max-number flag")?
        .parse()
        .map_err(|e| format!("Failed to parse `logfile-max-number`: {:?}", e))?;

    let logfile_compress = matches.is_present("logfile-compress");

    // Construct the path to the log file.
    let mut log_path: Option<PathBuf> = clap_utils::parse_optional(matches, "logfile")?;
    if log_path.is_none() {
        log_path = match matches.subcommand() {
            ("beacon_node", _) => Some(
                parse_path_or_default(matches, "datadir")?
                    .join(DEFAULT_BEACON_NODE_DIR)
                    .join("logs")
                    .join("beacon")
                    .with_extension("log"),
            ),
            ("validator_client", Some(vc_matches)) => {
                let base_path = if vc_matches.is_present("validators-dir") {
                    parse_path_or_default(vc_matches, "validators-dir")?
                } else {
                    parse_path_or_default(matches, "datadir")?.join(DEFAULT_VALIDATOR_DIR)
                };

                Some(
                    base_path
                        .join("logs")
                        .join("validator")
                        .with_extension("log"),
                )
            }
            _ => None,
        };
    }

    let logger_config = LoggerConfig {
        path: log_path,
        debug_level,
        logfile_debug_level,
        log_format,
        max_log_size: logfile_max_size * 1_024 * 1_024,
        max_log_number: logfile_max_number,
        compression: logfile_compress,
    };

    let builder = environment_builder.initialize_logger(logger_config)?;

    let mut environment = builder
        .multi_threaded_tokio_runtime()?
        .optional_eth2_network_config(Some(eth2_network_config))?
        .build()?;

    let log = environment.core_context().log().clone();

    // Allow Prometheus to export the time at which the process was started.
    metrics::expose_process_start_time(&log);

    // Allow Prometheus access to the version and commit of the Lighthouse build.
    metrics::expose_lighthouse_version();

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
    let optional_testnet = clap_utils::parse_optional::<String>(matches, "network")?;
    let optional_testnet_dir = clap_utils::parse_optional::<PathBuf>(matches, "testnet-dir")?;

    let network_name = match (optional_testnet, optional_testnet_dir) {
        (Some(testnet), None) => testnet,
        (None, Some(testnet_dir)) => format!("custom ({})", testnet_dir.display()),
        (None, None) => DEFAULT_HARDCODED_NETWORK.to_string(),
        (Some(_), Some(_)) => panic!("CLI prevents both --network and --testnet-dir"),
    };

    if let Some(sub_matches) = matches.subcommand_matches("account_manager") {
        eprintln!("Running account manager for {} network", network_name);
        // Pass the entire `environment` to the account manager so it can run blocking operations.
        account_manager::run(sub_matches, environment)?;

        // Exit as soon as account manager returns control.
        return Ok(());
    }

    if let Some(sub_matches) = matches.subcommand_matches(database_manager::CMD) {
        info!(log, "Running database manager for {} network", network_name);
        // Pass the entire `environment` to the database manager so it can run blocking operations.
        database_manager::run(sub_matches, environment)?;

        // Exit as soon as database manager returns control.
        return Ok(());
    }

    info!(log, "Lighthouse started"; "version" => VERSION);
    info!(
        log,
        "Configured for network";
        "name" => &network_name
    );

    match matches.subcommand() {
        ("beacon_node", Some(matches)) => {
            let context = environment.core_context();
            let log = context.log().clone();
            let executor = context.executor.clone();
            let config = beacon_node::get_config::<E>(matches, &context)?;
            let shutdown_flag = matches.is_present("immediate-shutdown");
            // Dump configs if `dump-config` or `dump-chain-config` flags are set
            clap_utils::check_dump_configs::<_, E>(matches, &config, &context.eth2_config.spec)?;
            executor.clone().spawn(
                async move {
                    if let Err(e) = ProductionBeaconNode::new(context.clone(), config).await {
                        crit!(log, "Failed to start beacon node"; "reason" => e);
                        // Ignore the error since it always occurs during normal operation when
                        // shutting down.
                        let _ = executor
                            .shutdown_sender()
                            .try_send(ShutdownReason::Failure("Failed to start beacon node"));
                    } else if shutdown_flag {
                        let _ = executor.shutdown_sender().try_send(ShutdownReason::Success(
                            "Beacon node immediate shutdown triggered.",
                        ));
                    }
                },
                "beacon_node",
            );
        }
        ("validator_client", Some(matches)) => {
            let context = environment.core_context();
            let log = context.log().clone();
            let executor = context.executor.clone();
            let config = validator_client::Config::from_cli(matches, context.log())
                .map_err(|e| format!("Unable to initialize validator config: {}", e))?;
            let shutdown_flag = matches.is_present("immediate-shutdown");
            // Dump configs if `dump-config` or `dump-chain-config` flags are set
            clap_utils::check_dump_configs::<_, E>(matches, &config, &context.eth2_config.spec)?;
            if !shutdown_flag {
                executor.clone().spawn(
                    async move {
                        if let Err(e) = ProductionValidatorClient::new(context, config)
                            .await
                            .and_then(|mut vc| vc.start_service())
                        {
                            crit!(log, "Failed to start validator client"; "reason" => e);
                            // Ignore the error since it always occurs during normal operation when
                            // shutting down.
                            let _ = executor.shutdown_sender().try_send(ShutdownReason::Failure(
                                "Failed to start validator client",
                            ));
                        }
                    },
                    "validator_client",
                );
            } else {
                let _ = executor.shutdown_sender().try_send(ShutdownReason::Success(
                    "Validator client immediate shutdown triggered.",
                ));
            }
        }
        _ => {
            crit!(log, "No subcommand supplied. See --help .");
            return Err("No subcommand supplied.".into());
        }
    };

    // Block this thread until we get a ctrl-c or a task sends a shutdown signal.
    let shutdown_reason = environment.block_until_shutdown_requested()?;
    info!(log, "Shutting down.."; "reason" => ?shutdown_reason);

    environment.fire_signal();

    // Shutdown the environment once all tasks have completed.
    environment.shutdown_on_idle();

    match shutdown_reason {
        ShutdownReason::Success(_) => Ok(()),
        ShutdownReason::Failure(msg) => Err(msg.to_string()),
    }
}
