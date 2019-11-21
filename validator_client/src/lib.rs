mod block_service;
mod cli;
mod config;
mod duties_service;
mod error;
mod fork_service;
mod signer;
mod validator_store;

pub mod validator_directory;

pub use cli::cli_app;
pub use config::Config;

use block_service::{BlockService, BlockServiceBuilder};
use clap::ArgMatches;
use config::{Config as ClientConfig, KeySource};
use duties_service::{DutiesService, DutiesServiceBuilder};
use environment::RuntimeContext;
use eth2_config::Eth2Config;
use exit_future::Signal;
use fork_service::{ForkService, ForkServiceBuilder};
use futures::{Future, IntoFuture};
use lighthouse_bootstrap::Bootstrapper;
use parking_lot::RwLock;
use remote_beacon_node::RemoteBeaconNode;
use slog::{info, Logger};
use slot_clock::SlotClock;
use slot_clock::SystemTimeSlotClock;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use types::EthSpec;
use validator_store::ValidatorStore;

#[derive(Clone)]
pub struct ProductionValidatorClient<T: EthSpec> {
    context: RuntimeContext<T>,
    duties_service: DutiesService<SystemTimeSlotClock, T>,
    fork_service: ForkService<SystemTimeSlotClock, T>,
    block_service: BlockService<SystemTimeSlotClock, T>,
    exit_signals: Arc<RwLock<Vec<Signal>>>,
}

impl<T: EthSpec> ProductionValidatorClient<T> {
    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub fn new_from_cli(
        mut context: RuntimeContext<T>,
        matches: &ArgMatches,
    ) -> impl Future<Item = Self, Error = String> {
        let mut log = context.log.clone();

        get_configs(&matches, &mut log)
            .into_future()
            .map_err(|e| format!("Unable to initialize config: {}", e))
            .and_then(|(client_config, eth2_config)| {
                // TODO: the eth2 config in the env is being completely ignored.
                //
                // See https://github.com/sigp/lighthouse/issues/602
                context.eth2_config = eth2_config;

                Self::new(context, client_config)
            })
    }

    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub fn new(
        mut context: RuntimeContext<T>,
        client_config: ClientConfig,
    ) -> impl Future<Item = Self, Error = String> {
        let log = context.log.clone();

        info!(
            log,
            "Starting validator client";
            "datadir" => client_config.full_data_dir().expect("Unable to find datadir").to_str(),
        );

        format!(
            "{}:{}",
            client_config.server, client_config.server_http_port
        )
        .parse()
        .map_err(|e| format!("Unable to parse server address: {:?}", e))
        .into_future()
        .and_then(|http_server_addr| {
            RemoteBeaconNode::new(http_server_addr)
                .map_err(|e| format!("Unable to init beacon node http client: {}", e))
        })
        .and_then(|beacon_node| {
            // TODO: add loop function to retry if node not online.
            beacon_node
                .http
                .spec()
                .get_eth2_config()
                .map(|eth2_config| (beacon_node, eth2_config))
                .map_err(|e| format!("Unable to read eth2 config from beacon node: {:?}", e))
        })
        .and_then(|(beacon_node, eth2_config)| {
            beacon_node
                .http
                .beacon()
                .get_genesis_time()
                .map(|genesis_time| (beacon_node, eth2_config, genesis_time))
                .map_err(|e| format!("Unable to read genesis time from beacon node: {:?}", e))
        })
        .and_then(move |(beacon_node, remote_eth2_config, genesis_time)| {
            // Do not permit a connection to a beacon node using different spec constants.
            if context.eth2_config.spec_constants != remote_eth2_config.spec_constants {
                return Err(format!(
                    "Beacon node is using an incompatible spec. Got {}, expected {}",
                    remote_eth2_config.spec_constants, context.eth2_config.spec_constants
                ));
            }

            // Note: here we just assume the spec variables of the remote node. This is very useful
            // for testnets, but perhaps a security issue when it comes to mainnet.
            //
            // A damaging attack would be for a beacon node to convince the validator client of a
            // different `SLOTS_PER_EPOCH` variable. This could result in slashable messages being
            // produced. We are safe from this because `SLOTS_PER_EPOCH` is a type-level constant
            // for Lighthouse.
            context.eth2_config = remote_eth2_config;

            let slot_clock = SystemTimeSlotClock::new(
                context.eth2_config.spec.genesis_slot,
                Duration::from_secs(genesis_time),
                Duration::from_millis(context.eth2_config.spec.milliseconds_per_slot),
            );

            dbg!(context.eth2_config.spec.milliseconds_per_slot);

            // TODO: fix expect.
            let validator_store = ValidatorStore::load_from_disk(
                client_config.full_data_dir().expect("Get rid of this."),
                context.eth2_config.spec.clone(),
                log.clone(),
            )?;

            info!(
                log,
                "Loaded validator keypair store";
                "voting_validators" => validator_store.num_voting_validators()
            );

            let duties_service = DutiesServiceBuilder::new()
                .slot_clock(slot_clock.clone())
                .validator_store(validator_store.clone())
                .beacon_node(beacon_node.clone())
                .runtime_context(context.service_context("duties"))
                .build()?;

            let fork_service = ForkServiceBuilder::new()
                .slot_clock(slot_clock.clone())
                .beacon_node(beacon_node.clone())
                .runtime_context(context.service_context("fork"))
                .build()?;

            let block_service = BlockServiceBuilder::new()
                .duties_service(duties_service.clone())
                .fork_service(fork_service.clone())
                .slot_clock(slot_clock)
                .validator_store(validator_store)
                .beacon_node(beacon_node)
                .runtime_context(context.service_context("block"))
                .build()?;

            Ok(Self {
                context,
                duties_service,
                fork_service,
                block_service,
                exit_signals: Arc::new(RwLock::new(vec![])),
            })
        })
    }

    pub fn start_service(&self) -> Result<(), String> {
        let duties_exit = self
            .duties_service
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start duties service: {}", e))?;

        self.exit_signals.write().push(duties_exit);

        let fork_exit = self
            .fork_service
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start fork service: {}", e))?;

        self.exit_signals.write().push(fork_exit);

        let block_exit = self
            .block_service
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start block service: {}", e))?;

        self.exit_signals.write().push(block_exit);

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
