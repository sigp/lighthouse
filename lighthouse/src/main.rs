#![recursion_limit = "256"]

mod cli;
mod metrics;

use crate::cli::{Lighthouse, LighthouseSubcommand};
use beacon_node::ProductionBeaconNode;
use clap::Parser;
use clap_utils::{flags::DISABLE_MALLOC_TUNING_FLAG, GlobalConfig};
use directory::{parse_path_or_default, DEFAULT_BEACON_NODE_DIR, DEFAULT_VALIDATOR_DIR};
use env_logger::{Builder, Env};
use environment::{EnvironmentBuilder, LoggerConfig};
use eth2_network_config::{Eth2NetworkConfig, DEFAULT_HARDCODED_NETWORK};
use lighthouse_version::VERSION;
use malloc_utils::configure_memory_allocator;
use slog::{crit, info, warn};
use std::fs::File;
use std::process::exit;
use task_executor::ShutdownReason;
use types::{EthSpec, EthSpecId};
use validator_client::ProductionValidatorClient;

fn main() {
    // Enable backtraces unless a RUST_BACKTRACE value has already been explicitly provided.
    if std::env::var("RUST_BACKTRACE").is_err() {
        std::env::set_var("RUST_BACKTRACE", "1");
    }

    let lighthouse: Lighthouse = Lighthouse::parse();

    // Configure the allocator early in the process, before it has the chance to use the default values for
    // anything important.
    //
    // Only apply this optimization for the beacon node. It's the only process with a substantial
    // memory footprint.
    if lighthouse.is_beacon_node() && !lighthouse.disable_malloc_tuning {
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
    if lighthouse.env_log {
        Builder::from_env(Env::default()).init();
    }

    let result = lighthouse
        .get_eth2_network_config()
        .and_then(|eth2_network_config| {
            let eth_spec_id = eth2_network_config.eth_spec_id()?;

            let global_config = lighthouse.get_global_config();

            match &lighthouse.subcommand {
                // Boot node subcommand circumvents the environment.
                LighthouseSubcommand::BootNode(boot_node) => {
                    boot_node::run(boot_node, &global_config, eth_spec_id, &eth2_network_config);

                    return Ok(());
                }
                _ => match eth_spec_id {
                    EthSpecId::Mainnet => run(
                        EnvironmentBuilder::mainnet(),
                        &lighthouse,
                        &global_config,
                        eth2_network_config,
                    ),
                    #[cfg(feature = "gnosis")]
                    EthSpecId::Gnosis => run(
                        EnvironmentBuilder::gnosis(),
                        &lighthouse,
                        &global_config,
                        eth2_network_config,
                    ),
                    #[cfg(feature = "spec-minimal")]
                    EthSpecId::Minimal => run(
                        EnvironmentBuilder::minimal(),
                        &lighthouse,
                        &global_config,
                        eth2_network_config,
                    ),
                    #[cfg(not(all(feature = "spec-minimal", feature = "gnosis")))]
                    other => {
                        eprintln!(
                            "Eth spec `{}` is not supported by this build of Lighthouse",
                            other
                        );
                        eprintln!(
                            "You must compile with a feature flag to enable this spec variant"
                        );
                        exit(1);
                    }
                },
            }
        });

    // `std::process::exit` does not run destructors so we drop manually.
    drop(lighthouse);

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
    lighthouse: &Lighthouse,
    global_config: &GlobalConfig,
    eth2_network_config: Eth2NetworkConfig,
) -> Result<(), String> {
    if std::mem::size_of::<usize>() != 8 {
        return Err(format!(
            "{}-bit architecture is not supported (64-bit only).",
            std::mem::size_of::<usize>() * 8
        ));
    }

    let debug_level = lighthouse.debug_level.as_str();
    let log_format = lighthouse.log_format.as_ref().map(String::as_str);
    let logfile_debug_level = lighthouse.logfile_debug_level.as_str();
    let logfile_max_size: u64 = lighthouse.logfile_max_size;
    let logfile_max_number: usize = lighthouse.logfile_max_number;
    let logfile_compress = lighthouse.logfile_compress;

    // Construct the path to the log file.
    let mut log_path = lighthouse.logfile.clone();
    if log_path.is_none() {
        log_path = match lighthouse.subcommand {
            LighthouseSubcommand::BeaconNode(_) => Some(
                parse_path_or_default(lighthouse.datadir.clone(), global_config)?
                    .join(DEFAULT_BEACON_NODE_DIR)
                    .join("logs")
                    .join("beacon")
                    .with_extension("log"),
            ),
            LighthouseSubcommand::ValidatorClient(_) => Some(
                parse_path_or_default(lighthouse.datadir.clone(), global_config)?
                    .join(DEFAULT_VALIDATOR_DIR)
                    .join("logs")
                    .join("validator")
                    .with_extension("log"),
            ),
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

    if lighthouse.spec.is_some() {
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
    let optional_testnet = lighthouse.network.clone();
    let optional_testnet_dir = lighthouse.testnet_dir.clone();

    let network_name = match (optional_testnet, optional_testnet_dir) {
        (Some(testnet), None) => testnet,
        (None, Some(testnet_dir)) => format!("custom ({})", testnet_dir.display()),
        (None, None) => DEFAULT_HARDCODED_NETWORK.to_string(),
        (Some(_), Some(_)) => panic!("CLI prevents both --network and --testnet-dir"),
    };

    if let LighthouseSubcommand::AccountManager(acc_manager) = &lighthouse.subcommand {
        eprintln!("Running account manager for {} network", network_name);
        // Pass the entire `environment` to the account manager so it can run blocking operations.
        account_manager::run(acc_manager, &global_config, environment)?;

        // Exit as soon as account manager returns control.
        return Ok(());
    };

    info!(log, "Lighthouse started"; "version" => VERSION);
    info!(
        log,
        "Configured for network";
        "name" => &network_name
    );

    match &lighthouse.subcommand {
        LighthouseSubcommand::BeaconNode(beacon_node) => {
            let context = environment.core_context();
            let log = context.log().clone();
            let executor = context.executor.clone();
            let config = beacon_node::get_config::<E>(beacon_node, global_config, &context)?;
            let shutdown_flag = lighthouse.immediate_shutdown;
            if let Some(dump_path) = lighthouse.dump_config.as_ref() {
                let mut file = File::create(dump_path)
                    .map_err(|e| format!("Failed to create dumped config: {:?}", e))?;
                serde_json::to_writer(&mut file, &config)
                    .map_err(|e| format!("Error serializing config: {:?}", e))?;
            };

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
        LighthouseSubcommand::ValidatorClient(validator_client) => {
            let context = environment.core_context();
            let log = context.log().clone();
            let executor = context.executor.clone();
            let config =
                validator_client::Config::from_cli(validator_client, global_config, context.log())
                    .map_err(|e| format!("Unable to initialize validator config: {}", e))?;
            let shutdown_flag = lighthouse.immediate_shutdown;
            if let Some(dump_path) = lighthouse.dump_config.as_ref() {
                let mut file = File::create(dump_path)
                    .map_err(|e| format!("Failed to create dumped config: {:?}", e))?;
                serde_json::to_writer(&mut file, &config)
                    .map_err(|e| format!("Error serializing config: {:?}", e))?;
            };
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
