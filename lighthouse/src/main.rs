mod cli;
mod metrics;

use beacon_node::ProductionBeaconNode;
use clap::Parser;
use clap_utils::{flags::DISABLE_MALLOC_TUNING_FLAG, GlobalConfig};
use cli::Lighthouse;
use directory::{parse_path_or_default, DEFAULT_BEACON_NODE_DIR};
use environment::{EnvironmentBuilder, LoggerConfig};
use eth2_network_config::{Eth2NetworkConfig, DEFAULT_HARDCODED_NETWORK};
use futures::TryFutureExt;
use lighthouse_version::VERSION;
use malloc_utils::configure_memory_allocator;
use slog::{crit, info};
use std::backtrace::Backtrace;
use std::path::PathBuf;
use std::process::exit;
use task_executor::ShutdownReason;
use types::{EthSpec, EthSpecId};
use validator_client::ProductionValidatorClient;

fn main() {
    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var("RUST_BACKTRACE").is_err() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    let lighthouse_config: Lighthouse = Lighthouse::parse();
    let global_config: GlobalConfig = lighthouse_config.get_global_config();

    // Configure the allocator early in the process, before it has the chance to use the default values for
    // anything important.
    //
    // Only apply this optimization for the beacon node. It's the only process with a substantial
    // memory footprint.
    if let cli::LighthouseSubcommand::BeaconNode(_) = &lighthouse_config.subcommand {
        if !lighthouse_config.disable_malloc_tuning {
            if let Err(e) = configure_memory_allocator() {
                eprintln!(
                    "Unable to configure the memory allocator: {} \n\
                    Try providing the --{} flag",
                    e, DISABLE_MALLOC_TUNING_FLAG
                );
                exit(1)
            }
        }
    }

    let result = lighthouse_config
        .get_eth2_network_config()
        .and_then(|eth2_network_config| {
            let eth_spec_id = eth2_network_config.eth_spec_id()?;

            if let cli::LighthouseSubcommand::BootNode(boot_node_config) =
                &lighthouse_config.subcommand
            {
                // The bootnode uses the main debug-level flag
                let debug_info = lighthouse_config.debug_level;

                boot_node::run(
                    &global_config,
                    boot_node_config,
                    eth_spec_id,
                    &eth2_network_config,
                    debug_info.to_str(),
                );

                return Ok(());
            }

            match eth_spec_id {
                EthSpecId::Mainnet => run(
                    EnvironmentBuilder::mainnet(),
                    &lighthouse_config,
                    &global_config,
                    eth2_network_config,
                ),
                #[cfg(feature = "gnosis")]
                EthSpecId::Gnosis => run(
                    EnvironmentBuilder::gnosis(),
                    &lighthouse_config,
                    &global_config,
                    eth2_network_config,
                ),
                #[cfg(feature = "spec-minimal")]
                EthSpecId::Minimal => run(
                    EnvironmentBuilder::minimal(),
                    &lighthouse_config,
                    &global_config,
                    eth2_network_config,
                ),
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
    lighthouse_config: &Lighthouse,
    global_config: &GlobalConfig,
    eth2_network_config: Eth2NetworkConfig,
) -> Result<(), String> {
    if std::mem::size_of::<usize>() != 8 {
        return Err(format!(
            "{}-bit architecture is not supported (64-bit only).",
            std::mem::size_of::<usize>() * 8
        ));
    }

    let debug_level = lighthouse_config.debug_level;
    let log_format = lighthouse_config.log_format.clone();
    let log_color = lighthouse_config.log_color;
    let disable_log_timestamp = lighthouse_config.disable_log_timestamp;
    let logfile_debug_level = lighthouse_config.logfile_debug_level;
    let logfile_format = lighthouse_config.logfile_format;
    let logfile_max_size = lighthouse_config.logfile_max_size;
    let logfile_max_number = lighthouse_config.logfile_max_number;
    let logfile_compress = lighthouse_config.logfile_compress;
    let logfile_restricted = lighthouse_config.logfile_no_restricted_perms;

    // Construct the path to the log file.
    let mut log_path: Option<PathBuf> = lighthouse_config.logfile.clone();
    if log_path.is_none() {
        log_path = match &lighthouse_config.subcommand {
            cli::LighthouseSubcommand::BeaconNode(_) => Some(
                parse_path_or_default(global_config, global_config.datadir.clone())?
                    .join(DEFAULT_BEACON_NODE_DIR)
                    .join("logs")
                    .join("beacon")
                    .with_extension("log"),
            ),
            cli::LighthouseSubcommand::ValidatorClient(validator_config) => {
                let base_path = if let Some(validators_dir) = &validator_config.validators_dir {
                    parse_path_or_default(global_config, Some(validators_dir.clone()))?
                } else {
                    parse_path_or_default(global_config, global_config.datadir.clone())?
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
        match &lighthouse_config.subcommand {
            cli::LighthouseSubcommand::BeaconNode(beacon_node_config) => beacon_node_config.gui,
            cli::LighthouseSubcommand::ValidatorClient(validator_client_config) => {
                validator_client_config.http
            }
            _ => false,
        }
    };

    let logger_config = LoggerConfig {
        path: log_path.clone(),
        debug_level: debug_level.to_str(),
        logfile_debug_level: logfile_debug_level.to_str(),
        log_format: Some(log_format),
        logfile_format: Some(logfile_format.to_str()),
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

    let mut tracing_log_path = lighthouse_config.logfile.clone();

    if tracing_log_path.is_none() {
        tracing_log_path = Some(
            parse_path_or_default(global_config, global_config.datadir.clone())?
                .join(DEFAULT_BEACON_NODE_DIR)
                .join("logs"),
        )
    }

    let path = tracing_log_path.clone().unwrap();

    let turn_on_terminal_logs = lighthouse_config.env_log;

    logging::create_tracing_layer(path, turn_on_terminal_logs);

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
    let optional_testnet = lighthouse_config.network;
    let optional_testnet_dir = lighthouse_config.testnet_dir.clone();

    let network_name = match (optional_testnet, optional_testnet_dir) {
        (Some(testnet), None) => testnet.to_str(),
        (None, Some(testnet_dir)) => format!("custom ({})", testnet_dir.display()),
        (None, None) => DEFAULT_HARDCODED_NETWORK.to_string(),
        (Some(_), Some(_)) => panic!("CLI prevents both --network and --testnet-dir"),
    };

    match &lighthouse_config.subcommand {
        cli::LighthouseSubcommand::AccountManager(account_manager_config) => {
            eprintln!("Running account manager for {} network", network_name);
            // Pass the entire `environment` to the account manager so it can run blocking operations.
            account_manager::run(account_manager_config, global_config, environment)?;

            // Exit as soon as account manager returns control.
            return Ok(());
        }
        cli::LighthouseSubcommand::DatabaseManager(database_manager_config) => {
            info!(log, "Running database manager for {} network", network_name);
            // Pass the entire `environment` to the database manager so it can run blocking operations.
            database_manager::run(database_manager_config, global_config, environment)?;

            // Exit as soon as database manager returns control.
            return Ok(());
        }
        cli::LighthouseSubcommand::ValidatorManager(validator_manager_config) => {
            eprintln!("Running validator manager for {} network", network_name);

            // Pass the entire `environment` to the account manager so it can run blocking operations.
            validator_manager::run::<E>(validator_manager_config, global_config, environment)?;

            // Exit as soon as account manager returns control.
            return Ok(());
        }
        _ => {}
    }

    info!(log, "Lighthouse started"; "version" => VERSION);
    info!(
        log,
        "Configured for network";
        "name" => &network_name
    );

    match &lighthouse_config.subcommand {
        cli::LighthouseSubcommand::BeaconNode(beacon_node_config) => {
            let context = environment.core_context();
            let log = context.log().clone();
            let executor = context.executor.clone();
            let mut config =
                beacon_node::get_config::<E>(beacon_node_config, global_config, &context)?;
            config.logger_config = logger_config;
            let shutdown_flag = lighthouse_config.immediate_shutdown;
            // Dump configs if `dump-config` or `dump-chain-config` flags are set
            clap_utils::check_dump_configs::<_, E>(
                global_config,
                &config,
                &context.eth2_config.spec,
            )?;
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
        cli::LighthouseSubcommand::ValidatorClient(validator_client_config) => {
            let context = environment.core_context();
            let log = context.log().clone();
            let executor = context.executor.clone();
            let config = validator_client::Config::from_cli(
                validator_client_config,
                global_config,
                context.log(),
            )
            .map_err(|e| format!("Unable to initialize validator config: {}", e))?;
            let shutdown_flag = lighthouse_config.immediate_shutdown;
            // Dump configs if `dump-config` or `dump-chain-config` flags are set
            clap_utils::check_dump_configs::<_, E>(
                global_config,
                &config,
                &context.eth2_config.spec,
            )?;
            if !shutdown_flag {
                executor.clone().spawn(
                    async move {
                        if let Err(e) = ProductionValidatorClient::new(context, config)
                            .and_then(|mut vc| async move { vc.start_service().await })
                            .await
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
    }

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
