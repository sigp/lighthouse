mod metrics;

use beacon_node::ProductionBeaconNode;
use clap::{Arg, ArgAction, ArgMatches, Command};
use clap_utils::{
    flags::DISABLE_MALLOC_TUNING_FLAG, get_color_style, get_eth2_network_config, FLAG_HEADER,
};
use directory::{parse_path_or_default, DEFAULT_BEACON_NODE_DIR, DEFAULT_VALIDATOR_DIR};
use environment::{EnvironmentBuilder, LoggerConfig};
use eth2_network_config::{Eth2NetworkConfig, DEFAULT_HARDCODED_NETWORK, HARDCODED_NET_NAMES};
use ethereum_hashing::have_sha_extensions;
use futures::TryFutureExt;
use lazy_static::lazy_static;
use lighthouse_version::VERSION;
use malloc_utils::configure_memory_allocator;
use slog::{crit, info};
use std::backtrace::Backtrace;
use std::path::PathBuf;
use std::process::exit;
use task_executor::ShutdownReason;
use types::{EthSpec, EthSpecId};
use validator_client::ProductionValidatorClient;

lazy_static! {
    pub static ref SHORT_VERSION: String = VERSION.replace("Lighthouse/", "");
    pub static ref LONG_VERSION: String = format!(
        "{}\n\
         BLS library: {}\n\
         BLS hardware acceleration: {}\n\
         SHA256 hardware acceleration: {}\n\
         Allocator: {}\n\
         Profile: {}\n\
         Specs: mainnet (true), minimal ({}), gnosis ({})",
        SHORT_VERSION.as_str(),
        bls_library_name(),
        bls_hardware_acceleration(),
        have_sha_extensions(),
        allocator_name(),
        build_profile_name(),
        cfg!(feature = "spec-minimal"),
        cfg!(feature = "gnosis"),
    );
}

fn bls_library_name() -> &'static str {
    if cfg!(feature = "portable") {
        "blst-portable"
    } else if cfg!(feature = "modern") {
        "blst-modern"
    } else {
        "blst"
    }
}

#[inline(always)]
fn bls_hardware_acceleration() -> bool {
    #[cfg(target_arch = "x86_64")]
    return std::is_x86_feature_detected!("adx");

    #[cfg(target_arch = "aarch64")]
    return std::arch::is_aarch64_feature_detected!("neon");
}

fn allocator_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "system"
    } else {
        "jemalloc"
    }
}

fn build_profile_name() -> String {
    // Nice hack from https://stackoverflow.com/questions/73595435/how-to-get-profile-from-cargo-toml-in-build-rs-or-at-runtime
    // The profile name is always the 3rd last part of the path (with 1 based indexing).
    // e.g. /code/core/target/cli/build/my-build-info-9f91ba6f99d7a061/out
    std::env!("OUT_DIR")
        .split(std::path::MAIN_SEPARATOR)
        .nth_back(3)
        .unwrap_or_else(|| "unknown")
        .to_string()
}

fn main() {
    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var("RUST_BACKTRACE").is_err() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    // Parse the CLI parameters.
    let matches = Command::new("Lighthouse")
        .version(SHORT_VERSION.as_str())
        .author("Sigma Prime <contact@sigmaprime.io>")
        .styles(get_color_style())
        .next_line_help(true)
        .term_width(80)
        .disable_help_flag(true)
        .about(
            "Ethereum 2.0 client by Sigma Prime. Provides a full-featured beacon \
             node, a validator client and utilities for managing validator accounts.",
        )
        .long_version(LONG_VERSION.as_str())
        .display_order(0)
        .arg(
            Arg::new("env_log")
                .short('l')
                .help(
                    "DEPRECATED Enables environment logging giving access to sub-protocol logs such as discv5 and libp2p",
                )
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile")
                .long("logfile")
                .value_name("FILE")
                .help(
                    "File path where the log file will be stored. Once it grows to the \
                    value specified in `--logfile-max-size` a new log file is generated where \
                    future logs are stored. \
                    Once the number of log files exceeds the value specified in \
                    `--logfile-max-number` the oldest log file will be overwritten.")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-debug-level")
                .long("logfile-debug-level")
                .value_name("LEVEL")
                .help("The verbosity level used when emitting logs to the log file.")
                .action(ArgAction::Set)
                .value_parser(["info", "debug", "trace", "warn", "error", "crit"])
                .default_value("debug")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-format")
                .long("logfile-format")
                .value_name("FORMAT")
                .help("Specifies the log format used when emitting logs to the logfile.")
                .value_parser(["DEFAULT", "JSON"])
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-max-size")
                .long("logfile-max-size")
                .value_name("SIZE")
                .help(
                    "The maximum size (in MB) each log file can grow to before rotating. If set \
                    to 0, background file logging is disabled.")
                .action(ArgAction::Set)
                .default_value("200")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-max-number")
                .long("logfile-max-number")
                .value_name("COUNT")
                .help(
                    "The maximum number of log files that will be stored. If set to 0, \
                    background file logging is disabled.")
                .action(ArgAction::Set)
                .default_value("5")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-compress")
                .long("logfile-compress")
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .help(
                    "If present, compress old log files. This can help reduce the space needed \
                    to store old logs.")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("logfile-no-restricted-perms")
                .long("logfile-no-restricted-perms")
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .help(
                    "If present, log files will be generated as world-readable meaning they can be read by \
                    any user on the machine. Note that logs can often contain sensitive information \
                    about your validator and so this flag should be used with caution. For Windows users, \
                    the log file permissions will be inherited from the parent folder.")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("log-format")
                .long("log-format")
                .value_name("FORMAT")
                .help("Specifies the log format used when emitting logs to the terminal.")
                .value_parser(["JSON"])
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("log-color")
                .long("log-color")
                .alias("log-colour")
                .help("Force outputting colors when emitting logs to the terminal.")
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("disable-log-timestamp")
            .long("disable-log-timestamp")
            .action(ArgAction::SetTrue)
            .help_heading(FLAG_HEADER)
            .help("If present, do not include timestamps in logging output.")
            .global(true)
            .display_order(0)
        )
        .arg(
            Arg::new("debug-level")
                .long("debug-level")
                .value_name("LEVEL")
                .help("Specifies the verbosity level used when emitting logs to the terminal.")
                .action(ArgAction::Set)
                .value_parser(["info", "debug", "trace", "warn", "error", "crit"])
                .global(true)
                .default_value("info")
                .display_order(0)
        )
        .arg(
            Arg::new("datadir")
                .long("datadir")
                .short('d')
                .value_name("DIR")
                .global(true)
                .help(
                    "Used to specify a custom root data directory for lighthouse keys and databases. \
                    Defaults to $HOME/.lighthouse/{network} where network is the value of the `network` flag \
                    Note: Users should specify separate custom datadirs for different networks.")
                .action(ArgAction::Set)
                .display_order(0)
        )
        .arg(
            Arg::new("testnet-dir")
                .short('t')
                .long("testnet-dir")
                .value_name("DIR")
                .help(
                    "Path to directory containing eth2_testnet specs. Defaults to \
                      a hard-coded Lighthouse testnet. Only effective if there is no \
                      existing database.",
                )
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("network")
                .long("network")
                .value_name("network")
                .help("Name of the Eth2 chain Lighthouse will sync and follow.")
                .value_parser(HARDCODED_NET_NAMES.to_vec())
                .conflicts_with("testnet-dir")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("dump-config")
                .long("dump-config")
                .hide(true)
                .help("Dumps the config to a desired location. Used for testing only.")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("dump-chain-config")
                .long("dump-chain-config")
                .hide(true)
                .help("Dumps the chain config to a desired location. Used for testing only.")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("immediate-shutdown")
                .long("immediate-shutdown")
                .hide(true)
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .help(
                    "Shuts down immediately after the Beacon Node or Validator has successfully launched. \
                    Used for testing only, DO NOT USE IN PRODUCTION.")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new(DISABLE_MALLOC_TUNING_FLAG)
                .long(DISABLE_MALLOC_TUNING_FLAG)
                .help(
                    "If present, do not configure the system allocator. Providing this flag will \
                    generally increase memory usage, it should only be provided when debugging \
                    specific memory allocation issues."
                )
                .action(ArgAction::SetTrue)
                .help_heading(FLAG_HEADER)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("terminal-total-difficulty-override")
                .long("terminal-total-difficulty-override")
                .value_name("INTEGER")
                .help("Used to coordinate manual overrides to the TERMINAL_TOTAL_DIFFICULTY parameter. \
                       Accepts a 256-bit decimal integer (not a hex value). \
                       This flag should only be used if the user has a clear understanding that \
                       the broad Ethereum community has elected to override the terminal difficulty. \
                       Incorrect use of this flag will cause your node to experience a consensus \
                       failure. Be extremely careful with this flag.")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("terminal-block-hash-override")
                .long("terminal-block-hash-override")
                .value_name("TERMINAL_BLOCK_HASH")
                .help("Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH parameter. \
                       This flag should only be used if the user has a clear understanding that \
                       the broad Ethereum community has elected to override the terminal PoW block. \
                       Incorrect use of this flag will cause your node to experience a consensus \
                       failure. Be extremely careful with this flag.")
                .requires("terminal-block-hash-epoch-override")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("terminal-block-hash-epoch-override")
                .long("terminal-block-hash-epoch-override")
                .value_name("EPOCH")
                .help("Used to coordinate manual overrides to the TERMINAL_BLOCK_HASH_ACTIVATION_EPOCH \
                       parameter. This flag should only be used if the user has a clear understanding \
                       that the broad Ethereum community has elected to override the terminal PoW block. \
                       Incorrect use of this flag will cause your node to experience a consensus \
                       failure. Be extremely careful with this flag.")
                .requires("terminal-block-hash-override")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("safe-slots-to-import-optimistically")
                .long("safe-slots-to-import-optimistically")
                .value_name("INTEGER")
                .help("Used to coordinate manual overrides of the SAFE_SLOTS_TO_IMPORT_OPTIMISTICALLY \
                      parameter. This flag should only be used if the user has a clear understanding \
                      that the broad Ethereum community has elected to override this parameter in the event \
                      of an attack at the PoS transition block. Incorrect use of this flag can cause your \
                      node to possibly accept an invalid chain or sync more slowly. Be extremely careful with \
                      this flag.")
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("genesis-state-url")
                .long("genesis-state-url")
                .value_name("URL")
                .help(
                    "A URL of a beacon-API compatible server from which to download the genesis state. \
                    Checkpoint sync server URLs can generally be used with this flag. \
                    If not supplied, a default URL or the --checkpoint-sync-url may be used. \
                    If the genesis state is already included in this binary then this value will be ignored.",
                )
                .action(ArgAction::Set)
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("genesis-state-url-timeout")
                .long("genesis-state-url-timeout")
                .value_name("SECONDS")
                .help(
                    "The timeout in seconds for the request to --genesis-state-url.",
                )
                .action(ArgAction::Set)
                .default_value("180")
                .global(true)
                .display_order(0)
        )
        .arg(
            Arg::new("help")
            .long("help")
            .short('h')
            .help("Prints help information")
            .action(ArgAction::HelpLong)
            .display_order(0)
            .help_heading(FLAG_HEADER)
        )
        .subcommand(beacon_node::cli_app())
        .subcommand(boot_node::cli_app())
        .subcommand(validator_client::cli_app())
        .subcommand(account_manager::cli_app())
        .subcommand(database_manager::cli_app())
        .subcommand(validator_manager::cli_app())
        .get_matches();

    // Configure the allocator early in the process, before it has the chance to use the default values for
    // anything important.
    //
    // Only apply this optimization for the beacon node. It's the only process with a substantial
    // memory footprint.
    let is_beacon_node = matches.subcommand_name() == Some("beacon_node");
    if is_beacon_node && !matches.get_flag(DISABLE_MALLOC_TUNING_FLAG) {
        if let Err(e) = configure_memory_allocator() {
            eprintln!(
                "Unable to configure the memory allocator: {} \n\
                Try providing the --{} flag",
                e, DISABLE_MALLOC_TUNING_FLAG
            );
            exit(1)
        }
    }

    let result = get_eth2_network_config(&matches).and_then(|eth2_network_config| {
        let eth_spec_id = eth2_network_config.eth_spec_id()?;

        // boot node subcommand circumvents the environment
        if let Some(bootnode_matches) = matches.subcommand_matches("boot_node") {
            // The bootnode uses the main debug-level flag
            let debug_info = matches
                .get_one::<String>("debug-level")
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
        .get_one::<String>("debug-level")
        .ok_or("Expected --debug-level flag")?;

    let log_format = matches.get_one::<String>("log-format");

    let log_color = matches.get_flag("log-color");

    let disable_log_timestamp = matches.get_flag("disable-log-timestamp");

    let logfile_debug_level = matches
        .get_one::<String>("logfile-debug-level")
        .ok_or("Expected --logfile-debug-level flag")?;

    let logfile_format = matches
        .get_one::<String>("logfile-format")
        // Ensure that `logfile-format` defaults to the value of `log-format`.
        .or_else(|| matches.get_one::<String>("log-format"));

    let logfile_max_size: u64 = matches
        .get_one::<String>("logfile-max-size")
        .ok_or("Expected --logfile-max-size flag")?
        .parse()
        .map_err(|e| format!("Failed to parse `logfile-max-size`: {:?}", e))?;

    let logfile_max_number: usize = matches
        .get_one::<String>("logfile-max-number")
        .ok_or("Expected --logfile-max-number flag")?
        .parse()
        .map_err(|e| format!("Failed to parse `logfile-max-number`: {:?}", e))?;

    let logfile_compress = matches.get_flag("logfile-compress");

    let logfile_restricted = !matches.get_flag("logfile-no-restricted-perms");

    // Construct the path to the log file.
    let mut log_path: Option<PathBuf> = clap_utils::parse_optional(matches, "logfile")?;
    if log_path.is_none() {
        log_path = match matches.subcommand() {
            Some(("beacon_node", _)) => Some(
                parse_path_or_default(matches, "datadir")?
                    .join(DEFAULT_BEACON_NODE_DIR)
                    .join("logs")
                    .join("beacon")
                    .with_extension("log"),
            ),
            Some(("validator_client", vc_matches)) => {
                let base_path = if vc_matches.contains_id("validators-dir") {
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

    let sse_logging = {
        if let Some(bn_matches) = matches.subcommand_matches("beacon_node") {
            bn_matches.get_flag("gui")
        } else if let Some(vc_matches) = matches.subcommand_matches("validator_client") {
            vc_matches.get_flag("http")
        } else {
            false
        }
    };

    let logger_config = LoggerConfig {
        path: log_path.clone(),
        debug_level: String::from(debug_level),
        logfile_debug_level: String::from(logfile_debug_level),
        log_format: log_format.map(String::from),
        logfile_format: logfile_format.map(String::from),
        log_color,
        disable_log_timestamp,
        max_log_size: logfile_max_size * 1_024 * 1_024,
        max_log_number: logfile_max_number,
        compression: logfile_compress,
        is_restricted: logfile_restricted,
        sse_logging,
    };

    let builder = environment_builder.initialize_logger(logger_config.clone())?;

    let mut environment = builder
        .multi_threaded_tokio_runtime()?
        .eth2_network_config(eth2_network_config)?
        .build()?;

    let log = environment.core_context().log().clone();

    // Log panics properly.
    {
        let log = log.clone();
        std::panic::set_hook(Box::new(move |info| {
            crit!(
                log,
                "Task panic. This is a bug!";
                "location" => info.location().map(ToString::to_string),
                "message" => info.payload().downcast_ref::<String>(),
                "backtrace" => %Backtrace::capture(),
                "advice" => "Please check above for a backtrace and notify the developers",
            );
        }));
    }

    let mut tracing_log_path: Option<PathBuf> = clap_utils::parse_optional(matches, "logfile")?;

    if tracing_log_path.is_none() {
        tracing_log_path = Some(
            parse_path_or_default(matches, "datadir")?
                .join(DEFAULT_BEACON_NODE_DIR)
                .join("logs"),
        )
    }

    let path = tracing_log_path.clone().unwrap();

    logging::create_tracing_layer(path);

    // Allow Prometheus to export the time at which the process was started.
    metrics::expose_process_start_time(&log);

    // Allow Prometheus access to the version and commit of the Lighthouse build.
    metrics::expose_lighthouse_version();

    #[cfg(all(feature = "modern", target_arch = "x86_64"))]
    if !std::is_x86_feature_detected!("adx") {
        slog::warn!(
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

    if let Some(sub_matches) = matches.subcommand_matches(account_manager::CMD) {
        eprintln!("Running account manager for {} network", network_name);
        // Pass the entire `environment` to the account manager so it can run blocking operations.
        account_manager::run(sub_matches, environment)?;

        // Exit as soon as account manager returns control.
        return Ok(());
    }

    if let Some(sub_matches) = matches.subcommand_matches(validator_manager::CMD) {
        eprintln!("Running validator manager for {} network", network_name);

        // Pass the entire `environment` to the account manager so it can run blocking operations.
        validator_manager::run::<E>(sub_matches, environment)?;

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
        Some(("beacon_node", matches)) => {
            let context = environment.core_context();
            let log = context.log().clone();
            let executor = context.executor.clone();
            let mut config = beacon_node::get_config::<E>(matches, &context)?;
            config.logger_config = logger_config;
            // Dump configs if `dump-config` or `dump-chain-config` flags are set
            clap_utils::check_dump_configs::<_, E>(matches, &config, &context.eth2_config.spec)?;

            let shutdown_flag = matches.get_flag("immediate-shutdown");
            if shutdown_flag {
                info!(log, "Beacon node immediate shutdown triggered.");
                return Ok(());
            }

            executor.clone().spawn(
                async move {
                    if let Err(e) = ProductionBeaconNode::new(context.clone(), config).await {
                        crit!(log, "Failed to start beacon node"; "reason" => e);
                        // Ignore the error since it always occurs during normal operation when
                        // shutting down.
                        let _ = executor
                            .shutdown_sender()
                            .try_send(ShutdownReason::Failure("Failed to start beacon node"));
                    }
                },
                "beacon_node",
            );
        }
        Some(("validator_client", matches)) => {
            let context = environment.core_context();
            let log = context.log().clone();
            let executor = context.executor.clone();
            let config = validator_client::Config::from_cli(matches, context.log())
                .map_err(|e| format!("Unable to initialize validator config: {}", e))?;
            // Dump configs if `dump-config` or `dump-chain-config` flags are set
            clap_utils::check_dump_configs::<_, E>(matches, &config, &context.eth2_config.spec)?;

            let shutdown_flag = matches.get_flag("immediate-shutdown");
            if shutdown_flag {
                info!(log, "Validator client immediate shutdown triggered.");
                return Ok(());
            }

            executor.clone().spawn(
                async move {
                    if let Err(e) = ProductionValidatorClient::new(context, config)
                        .and_then(|mut vc| async move { vc.start_service().await })
                        .await
                    {
                        crit!(log, "Failed to start validator client"; "reason" => e);
                        // Ignore the error since it always occurs during normal operation when
                        // shutting down.
                        let _ = executor
                            .shutdown_sender()
                            .try_send(ShutdownReason::Failure("Failed to start validator client"));
                    }
                },
                "validator_client",
            );
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
