mod attestation_service;
mod block_service;
mod cli;
mod config;
mod duties_service;
mod fork_service;
mod notifier;
mod validator_store;

pub mod validator_directory;

pub use cli::cli_app;
pub use config::{Config, KeySource};

use attestation_service::{AttestationService, AttestationServiceBuilder};
use block_service::{BlockService, BlockServiceBuilder};
use clap::ArgMatches;
use duties_service::{DutiesService, DutiesServiceBuilder};
use environment::RuntimeContext;
use exit_future::Signal;
use fork_service::{ForkService, ForkServiceBuilder};
use futures::{
    future::{self, loop_fn, Loop},
    Future, IntoFuture,
};
use notifier::spawn_notifier;
use remote_beacon_node::RemoteBeaconNode;
use slog::{error, info, Logger};
use slot_clock::SlotClock;
use slot_clock::SystemTimeSlotClock;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::timer::Delay;
use types::EthSpec;
use validator_store::ValidatorStore;

/// The interval between attempts to contact the beacon node during startup.
const RETRY_DELAY: Duration = Duration::from_secs(2);

/// The global timeout for HTTP requests to the beacon node.
const HTTP_TIMEOUT: Duration = Duration::from_secs(12);

pub struct ProductionValidatorClient<T: EthSpec> {
    context: RuntimeContext<T>,
    duties_service: DutiesService<SystemTimeSlotClock, T>,
    fork_service: ForkService<SystemTimeSlotClock, T>,
    block_service: BlockService<SystemTimeSlotClock, T>,
    attestation_service: AttestationService<SystemTimeSlotClock, T>,
    exit_signals: Vec<Signal>,
}

impl<T: EthSpec> ProductionValidatorClient<T> {
    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub fn new_from_cli(
        context: RuntimeContext<T>,
        cli_args: &ArgMatches,
    ) -> impl Future<Item = Self, Error = String> {
        Config::from_cli(&cli_args)
            .into_future()
            .map_err(|e| format!("Unable to initialize config: {}", e))
            .and_then(|config| Self::new(context, config))
    }

    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub fn new(
        mut context: RuntimeContext<T>,
        config: Config,
    ) -> impl Future<Item = Self, Error = String> {
        let log_1 = context.log.clone();
        let log_2 = context.log.clone();
        let log_3 = context.log.clone();
        let log_4 = context.log.clone();

        info!(
            log_1,
            "Starting validator client";
            "beacon_node" => &config.http_server,
            "datadir" => format!("{:?}", config.data_dir),
        );

        RemoteBeaconNode::new_with_timeout(config.http_server.clone(), HTTP_TIMEOUT)
            .map_err(|e| format!("Unable to init beacon node http client: {}", e))
            .into_future()
            .and_then(move |beacon_node| wait_for_node(beacon_node, log_2))
            .and_then(|beacon_node| {
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
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .into_future()
                    .map_err(|e| format!("Unable to read system time: {:?}", e))
                    .and_then::<_, Box<dyn Future<Item = _, Error = _> + Send>>(move |now| {
                        let log = log_3.clone();
                        let genesis = Duration::from_secs(genesis_time);

                        // If the time now is less than (prior to) genesis, then delay until the
                        // genesis instant.
                        //
                        // If the validator client starts before genesis, it will get errors from
                        // the slot clock.
                        if now < genesis {
                            info!(
                                log,
                                "Starting node prior to genesis";
                                "seconds_to_wait" => (genesis - now).as_secs()
                            );

                            Box::new(
                                Delay::new(Instant::now() + (genesis - now))
                                    .map_err(|e| {
                                        format!("Unable to create genesis wait delay: {:?}", e)
                                    })
                                    .map(move |_| (beacon_node, remote_eth2_config, genesis_time)),
                            )
                        } else {
                            info!(
                                log,
                                "Genesis has already occurred";
                                "seconds_ago" => (now - genesis).as_secs()
                            );

                            Box::new(future::ok((beacon_node, remote_eth2_config, genesis_time)))
                        }
                    })
            })
            .and_then(|(beacon_node, eth2_config, genesis_time)| {
                beacon_node
                    .http
                    .beacon()
                    .get_genesis_validators_root()
                    .map(move |genesis_validators_root| {
                        (
                            beacon_node,
                            eth2_config,
                            genesis_time,
                            genesis_validators_root,
                        )
                    })
                    .map_err(|e| {
                        format!(
                            "Unable to read genesis validators root from beacon node: {:?}",
                            e
                        )
                    })
            })
            .and_then(
                move |(beacon_node, remote_eth2_config, genesis_time, genesis_validators_root)| {
                    let log = log_4.clone();

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

                    let fork_service = ForkServiceBuilder::new()
                        .slot_clock(slot_clock.clone())
                        .beacon_node(beacon_node.clone())
                        .runtime_context(context.service_context("fork".into()))
                        .build()?;

                    let validator_store: ValidatorStore<SystemTimeSlotClock, T> =
                        match &config.key_source {
                            // Load pre-existing validators from the data dir.
                            //
                            // Use the `account_manager` to generate these files.
                            KeySource::Disk => ValidatorStore::load_from_disk(
                                config.data_dir.clone(),
                                genesis_validators_root,
                                context.eth2_config.spec.clone(),
                                fork_service.clone(),
                                log.clone(),
                            )?,
                            // Generate ephemeral insecure keypairs for testing purposes.
                            //
                            // Do not use in production.
                            KeySource::InsecureKeypairs(indices) => {
                                ValidatorStore::insecure_ephemeral_validators(
                                    &indices,
                                    genesis_validators_root,
                                    context.eth2_config.spec.clone(),
                                    fork_service.clone(),
                                    log.clone(),
                                )?
                            }
                        };

                    info!(
                        log,
                        "Loaded validator keypair store";
                        "voting_validators" => validator_store.num_voting_validators()
                    );

                    let duties_service = DutiesServiceBuilder::new()
                        .slot_clock(slot_clock.clone())
                        .validator_store(validator_store.clone())
                        .beacon_node(beacon_node.clone())
                        .runtime_context(context.service_context("duties".into()))
                        .allow_unsynced_beacon_node(config.allow_unsynced_beacon_node)
                        .build()?;

                    let block_service = BlockServiceBuilder::new()
                        .duties_service(duties_service.clone())
                        .slot_clock(slot_clock.clone())
                        .validator_store(validator_store.clone())
                        .beacon_node(beacon_node.clone())
                        .runtime_context(context.service_context("block".into()))
                        .build()?;

                    let attestation_service = AttestationServiceBuilder::new()
                        .duties_service(duties_service.clone())
                        .slot_clock(slot_clock)
                        .validator_store(validator_store)
                        .beacon_node(beacon_node)
                        .runtime_context(context.service_context("attestation".into()))
                        .build()?;

                    Ok(Self {
                        context,
                        duties_service,
                        fork_service,
                        block_service,
                        attestation_service,
                        exit_signals: vec![],
                    })
                },
            )
    }

    pub fn start_service(&mut self) -> Result<(), String> {
        let duties_exit = self
            .duties_service
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start duties service: {}", e))?;

        let fork_exit = self
            .fork_service
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start fork service: {}", e))?;

        let block_exit = self
            .block_service
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start block service: {}", e))?;

        let attestation_exit = self
            .attestation_service
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start attestation service: {}", e))?;

        let notifier_exit =
            spawn_notifier(self).map_err(|e| format!("Failed to start notifier: {}", e))?;

        self.exit_signals = vec![
            duties_exit,
            fork_exit,
            block_exit,
            attestation_exit,
            notifier_exit,
        ];

        Ok(())
    }
}

/// Request the version from the node, looping back and trying again on failure. Exit once the node
/// has been contacted.
fn wait_for_node<E: EthSpec>(
    beacon_node: RemoteBeaconNode<E>,
    log: Logger,
) -> impl Future<Item = RemoteBeaconNode<E>, Error = String> {
    // Try to get the version string from the node, looping until success is returned.
    loop_fn(beacon_node.clone(), move |beacon_node| {
        let log = log.clone();
        beacon_node
            .clone()
            .http
            .node()
            .get_version()
            .map_err(|e| format!("{:?}", e))
            .then(move |result| {
                let future: Box<dyn Future<Item = Loop<_, _>, Error = String> + Send> = match result
                {
                    Ok(version) => {
                        info!(
                            log,
                            "Connected to beacon node";
                            "version" => version,
                        );

                        Box::new(future::ok(Loop::Break(beacon_node)))
                    }
                    Err(e) => {
                        error!(
                            log,
                            "Unable to connect to beacon node";
                            "error" => format!("{:?}", e),
                        );

                        Box::new(
                            Delay::new(Instant::now() + RETRY_DELAY)
                                .map_err(|e| format!("Failed to trigger delay: {:?}", e))
                                .and_then(|_| future::ok(Loop::Continue(beacon_node))),
                        )
                    }
                };

                future
            })
    })
    .map(|_| beacon_node)
}
