mod attestation_producer;
mod block_producer;
mod cli;
mod config;
mod duties;
mod error;
mod service;
mod signer;

pub use cli::cli_app;
pub use config::Config;

use clap::ArgMatches;
use config::{Config as ClientConfig, KeySource};
use environment::RuntimeContext;
use eth2_config::Eth2Config;
use exit_future::Signal;
use futures::Stream;
use lighthouse_bootstrap::Bootstrapper;
use parking_lot::RwLock;
use protos::services_grpc::ValidatorServiceClient;
use service::Service;
use slog::{error, info, warn, Logger};
use slot_clock::SlotClock;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::timer::Interval;
use types::{EthSpec, Keypair};

/// A fixed amount of time after a slot to perform operations. This gives the node time to complete
/// per-slot processes.
const TIME_DELAY_FROM_SLOT: Duration = Duration::from_millis(100);

#[derive(Clone)]
pub struct ProductionValidatorClient<T: EthSpec> {
    context: RuntimeContext<T>,
    service: Arc<Service<ValidatorServiceClient, Keypair, T>>,
    exit_signals: Arc<RwLock<Vec<Signal>>>,
}

impl<T: EthSpec> ProductionValidatorClient<T> {
    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub fn new_from_cli(context: RuntimeContext<T>, matches: &ArgMatches) -> Result<Self, String> {
        let mut log = context.log.clone();

        let (client_config, eth2_config) = get_configs(&matches, &mut log)
            .map_err(|e| format!("Unable to initialize config: {}", e))?;

        info!(
            log,
            "Starting validator client";
            "datadir" => client_config.full_data_dir().expect("Unable to find datadir").to_str(),
        );

        let service: Service<ValidatorServiceClient, Keypair, T> =
            Service::initialize_service(client_config, eth2_config, log.clone())
                .map_err(|e| e.to_string())?;

        Ok(Self {
            context,
            service: Arc::new(service),
            exit_signals: Arc::new(RwLock::new(vec![])),
        })
    }

    /// Starts the timers to trigger block and attestation production.
    pub fn start_service(&self) -> Result<(), String> {
        let service = self.clone().service;
        let log = self.context.log.clone();

        let duration_to_next_slot = service
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "Unable to determine duration to next slot. Exiting.".to_string())?;

        // set up the validator work interval - start at next slot and proceed every slot
        let interval = {
            // Set the interval to start at the next slot, and every slot after
            let slot_duration = Duration::from_millis(service.spec.milliseconds_per_slot);
            //TODO: Handle checked add correctly
            Interval::new(Instant::now() + duration_to_next_slot, slot_duration)
        };

        if service.slot_clock.now().is_none() {
            warn!(
                log,
                "Starting node prior to genesis";
            );
        }

        info!(
            log,
            "Waiting for next slot";
            "seconds_to_wait" => duration_to_next_slot.as_secs()
        );

        let (exit_signal, exit_fut) = exit_future::signal();

        self.exit_signals.write().push(exit_signal);

        /* kick off the core service */
        self.context.executor.spawn(
            interval
                .map_err(move |e| {
                    error! {
                        log,
                        "Timer thread failed";
                        "error" => format!("{}", e)
                    }
                })
                .and_then(move |_| if exit_fut.is_live() { Ok(()) } else { Err(()) })
                .for_each(move |_| {
                    // wait for node to process
                    std::thread::sleep(TIME_DELAY_FROM_SLOT);
                    // if a non-fatal error occurs, proceed to the next slot.
                    let _ignore_error = service.per_slot_execution();
                    // completed a slot process
                    Ok(())
                }),
        );

        Ok(())
    }
}

/// Parses the CLI arguments and attempts to load the client and eth2 configuration.
///
/// This is not a pure function, it reads from disk and may contact network servers.
fn get_configs(
    cli_args: &ArgMatches,
    mut log: &mut Logger,
) -> Result<(ClientConfig, Eth2Config), String> {
    let mut client_config = ClientConfig::default();

    client_config.apply_cli_args(&cli_args, &mut log)?;

    if let Some(server) = cli_args.value_of("server") {
        client_config.server = server.to_string();
    }

    if let Some(port) = cli_args.value_of("server-http-port") {
        client_config.server_http_port = port
            .parse::<u16>()
            .map_err(|e| format!("Unable to parse HTTP port: {:?}", e))?;
    }

    if let Some(port) = cli_args.value_of("server-grpc-port") {
        client_config.server_grpc_port = port
            .parse::<u16>()
            .map_err(|e| format!("Unable to parse gRPC port: {:?}", e))?;
    }

    info!(
        *log,
        "Beacon node connection info";
        "grpc_port" => client_config.server_grpc_port,
        "http_port" => client_config.server_http_port,
        "server" => &client_config.server,
    );

    let (client_config, eth2_config) = match cli_args.subcommand() {
        ("testnet", Some(sub_cli_args)) => {
            if cli_args.is_present("eth2-config") && sub_cli_args.is_present("bootstrap") {
                return Err(
                    "Cannot specify --eth2-config and --bootstrap as it may result \
                     in ambiguity."
                        .into(),
                );
            }
            process_testnet_subcommand(sub_cli_args, client_config, log)
        }
        _ => return Err("You must use the testnet command. See '--help'.".into()),
    }?;

    Ok((client_config, eth2_config))
}

/// Parses the `testnet` CLI subcommand.
///
/// This is not a pure function, it reads from disk and may contact network servers.
fn process_testnet_subcommand(
    cli_args: &ArgMatches,
    mut client_config: ClientConfig,
    log: &Logger,
) -> Result<(ClientConfig, Eth2Config), String> {
    let eth2_config = if cli_args.is_present("bootstrap") {
        info!(log, "Connecting to bootstrap server");
        let bootstrapper = Bootstrapper::connect(
            format!(
                "http://{}:{}",
                client_config.server, client_config.server_http_port
            ),
            &log,
        )?;

        let eth2_config = bootstrapper.eth2_config()?;

        info!(
            log,
            "Bootstrapped eth2 config via HTTP";
            "slot_time_millis" => eth2_config.spec.milliseconds_per_slot,
            "spec" => &eth2_config.spec_constants,
        );

        eth2_config
    } else {
        match cli_args.value_of("spec") {
            Some("mainnet") => Eth2Config::mainnet(),
            Some("minimal") => Eth2Config::minimal(),
            Some("interop") => Eth2Config::interop(),
            _ => return Err("No --spec flag provided. See '--help'.".into()),
        }
    };

    client_config.key_source = match cli_args.subcommand() {
        ("insecure", Some(sub_cli_args)) => {
            let first = sub_cli_args
                .value_of("first_validator")
                .ok_or_else(|| "No first validator supplied")?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse first validator: {:?}", e))?;
            let count = sub_cli_args
                .value_of("validator_count")
                .ok_or_else(|| "No validator count supplied")?
                .parse::<usize>()
                .map_err(|e| format!("Unable to parse validator count: {:?}", e))?;

            info!(
                log,
                "Generating unsafe testing keys";
                "first_validator" => first,
                "count" => count
            );

            KeySource::TestingKeypairRange(first..first + count)
        }
        ("interop-yaml", Some(sub_cli_args)) => {
            let path = sub_cli_args
                .value_of("path")
                .ok_or_else(|| "No yaml path supplied")?
                .parse::<PathBuf>()
                .map_err(|e| format!("Unable to parse yaml path: {:?}", e))?;

            info!(
                log,
                "Loading keypairs from interop YAML format";
                "path" => format!("{:?}", path),
            );

            KeySource::YamlKeypairs(path)
        }
        _ => KeySource::Disk,
    };

    Ok((client_config, eth2_config))
}
