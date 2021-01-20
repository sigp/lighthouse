mod attestation_service;
mod beacon_node_fallback;
mod block_service;
mod check_synced;
mod cli;
mod config;
mod duties_service;
mod fork_service;
mod http_metrics;
mod initialized_validators;
mod key_cache;
mod notifier;
mod validator_duty;
mod validator_store;

pub mod http_api;

pub use cli::cli_app;
pub use config::Config;

use crate::beacon_node_fallback::{
    start_fallback_updater_service, BeaconNodeFallback, CandidateBeaconNode, RequireSynced,
};
use account_utils::validator_definitions::ValidatorDefinitions;
use attestation_service::{AttestationService, AttestationServiceBuilder};
use block_service::{BlockService, BlockServiceBuilder};
use clap::ArgMatches;
use duties_service::{DutiesService, DutiesServiceBuilder};
use environment::RuntimeContext;
use eth2::types::StateId;
use eth2::{reqwest::ClientBuilder, BeaconNodeHttpClient, StatusCode, Url};
use fork_service::{ForkService, ForkServiceBuilder};
use futures::channel::mpsc;
use http_api::ApiSecret;
use initialized_validators::InitializedValidators;
use notifier::spawn_notifier;
use parking_lot::RwLock;
use slashing_protection::{SlashingDatabase, SLASHING_PROTECTION_FILENAME};
use slog::{error, info, warn, Logger};
use slot_clock::SlotClock;
use slot_clock::SystemTimeSlotClock;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{sleep, Duration};
use types::{EthSpec, Fork, Hash256};
use validator_store::ValidatorStore;

/// The interval between attempts to contact the beacon node during startup.
const RETRY_DELAY: Duration = Duration::from_secs(2);

/// The time between polls when waiting for genesis.
const WAITING_FOR_GENESIS_POLL_TIME: Duration = Duration::from_secs(12);

/// The global timeout for HTTP requests to the beacon node.
const HTTP_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone)]
pub struct ProductionValidatorClient<T: EthSpec> {
    context: RuntimeContext<T>,
    duties_service: DutiesService<SystemTimeSlotClock, T>,
    fork_service: ForkService<SystemTimeSlotClock, T>,
    block_service: BlockService<SystemTimeSlotClock, T>,
    attestation_service: AttestationService<SystemTimeSlotClock, T>,
    validator_store: ValidatorStore<SystemTimeSlotClock, T>,
    http_api_listen_addr: Option<SocketAddr>,
    http_metrics_ctx: Option<Arc<http_metrics::Context<T>>>,
    config: Config,
}

impl<T: EthSpec> ProductionValidatorClient<T> {
    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub async fn new_from_cli(
        context: RuntimeContext<T>,
        cli_args: &ArgMatches<'_>,
    ) -> Result<Self, String> {
        let config = Config::from_cli(&cli_args, context.log())
            .map_err(|e| format!("Unable to initialize config: {}", e))?;
        Self::new(context, config).await
    }

    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub async fn new(context: RuntimeContext<T>, config: Config) -> Result<Self, String> {
        let log = context.log().clone();

        info!(
            log,
            "Starting validator client";
            "beacon_nodes" => format!("{:?}", &config.beacon_nodes),
            "validator_dir" => format!("{:?}", config.validator_dir),
        );

        // Optionally start the metrics server.
        let http_metrics_ctx = if config.http_metrics.enabled {
            let shared = http_metrics::Shared {
                validator_store: None,
                genesis_time: None,
                duties_service: None,
            };

            let ctx: Arc<http_metrics::Context<T>> = Arc::new(http_metrics::Context {
                config: config.http_metrics.clone(),
                shared: RwLock::new(shared),
                log: log.clone(),
            });

            let exit = context.executor.exit();

            let (_listen_addr, server) = http_metrics::serve(ctx.clone(), exit)
                .map_err(|e| format!("Unable to start metrics API server: {:?}", e))?;

            context
                .clone()
                .executor
                .spawn_without_exit(async move { server.await }, "metrics-api");

            Some(ctx)
        } else {
            info!(log, "HTTP metrics server is disabled");
            None
        };

        let mut validator_defs = ValidatorDefinitions::open_or_create(&config.validator_dir)
            .map_err(|e| format!("Unable to open or create validator definitions: {:?}", e))?;

        if !config.disable_auto_discover {
            let new_validators = validator_defs
                .discover_local_keystores(&config.validator_dir, &config.secrets_dir, &log)
                .map_err(|e| format!("Unable to discover local validator keystores: {:?}", e))?;
            validator_defs
                .save(&config.validator_dir)
                .map_err(|e| format!("Unable to update validator definitions: {:?}", e))?;
            info!(
                log,
                "Completed validator discovery";
                "new_validators" => new_validators,
            );
        }

        let validators = InitializedValidators::from_definitions(
            validator_defs,
            config.validator_dir.clone(),
            log.clone(),
        )
        .await
        .map_err(|e| format!("Unable to initialize validators: {:?}", e))?;

        let voting_pubkeys: Vec<_> = validators.iter_voting_pubkeys().collect();

        info!(
            log,
            "Initialized validators";
            "disabled" => validators.num_total().saturating_sub(validators.num_enabled()),
            "enabled" => validators.num_enabled(),
        );

        if voting_pubkeys.is_empty() {
            warn!(
                log,
                "No enabled validators";
                "hint" => "create validators via the API, or the `lighthouse account` CLI command"
            );
        }

        // Initialize slashing protection.
        //
        // Create the slashing database if there are no validators, even if
        // `init_slashing_protection` is not supplied. There is no risk in creating a slashing
        // database without any validators in it.
        let slashing_db_path = config.validator_dir.join(SLASHING_PROTECTION_FILENAME);
        let slashing_protection = if config.init_slashing_protection || voting_pubkeys.is_empty() {
            SlashingDatabase::open_or_create(&slashing_db_path).map_err(|e| {
                format!(
                    "Failed to open or create slashing protection database: {:?}",
                    e
                )
            })
        } else {
            SlashingDatabase::open(&slashing_db_path).map_err(|e| {
                format!(
                    "Failed to open slashing protection database: {:?}.\n\
                     Ensure that `slashing_protection.sqlite` is in {:?} folder",
                    e, config.validator_dir
                )
            })
        }?;

        // Check validator registration with slashing protection, or auto-register all validators.
        if config.init_slashing_protection {
            slashing_protection
                .register_validators(voting_pubkeys.iter().copied())
                .map_err(|e| format!("Error while registering slashing protection: {:?}", e))?;
        } else {
            slashing_protection
                .check_validator_registrations(voting_pubkeys.iter().copied())
                .map_err(|e| {
                    format!(
                        "One or more validators not found in slashing protection database.\n\
                         Ensure you haven't misplaced your slashing protection database, or \
                         carefully consider running with --init-slashing-protection (see --help). \
                         Error: {:?}",
                        e
                    )
                })?;
        }

        let beacon_node_urls: Vec<Url> = config
            .beacon_nodes
            .iter()
            .map(|s| s.parse())
            .collect::<Result<_, _>>()
            .map_err(|e| format!("Unable to parse beacon node URL: {:?}", e))?;
        let beacon_nodes: Vec<BeaconNodeHttpClient> = beacon_node_urls
            .into_iter()
            .map(|url| {
                let beacon_node_http_client = ClientBuilder::new()
                    .timeout(HTTP_TIMEOUT)
                    .build()
                    .map_err(|e| format!("Unable to build HTTP client: {:?}", e))?;
                Ok(BeaconNodeHttpClient::from_components(
                    url,
                    beacon_node_http_client,
                ))
            })
            .collect::<Result<Vec<BeaconNodeHttpClient>, String>>()?;

        let candidates = beacon_nodes
            .into_iter()
            .map(CandidateBeaconNode::new)
            .collect();
        let mut beacon_nodes: BeaconNodeFallback<_, T> =
            BeaconNodeFallback::new(candidates, context.eth2_config.spec.clone(), log.clone());

        // Perform some potentially long-running initialization tasks.
        let (genesis_time, genesis_validators_root, fork) = tokio::select! {
            tuple = init_from_beacon_node(&beacon_nodes, &context) => tuple?,
            () = context.executor.exit() => return Err("Shutting down".to_string())
        };

        // Update the metrics server.
        if let Some(ctx) = &http_metrics_ctx {
            ctx.shared.write().genesis_time = Some(genesis_time);
        }

        let slot_clock = SystemTimeSlotClock::new(
            context.eth2_config.spec.genesis_slot,
            Duration::from_secs(genesis_time),
            Duration::from_secs(context.eth2_config.spec.seconds_per_slot),
        );

        beacon_nodes.set_slot_clock(slot_clock.clone());
        let beacon_nodes = Arc::new(beacon_nodes);
        start_fallback_updater_service(context.clone(), beacon_nodes.clone())?;

        let fork_service = ForkServiceBuilder::new()
            .fork(fork)
            .slot_clock(slot_clock.clone())
            .beacon_nodes(beacon_nodes.clone())
            .log(log.clone())
            .build()?;

        let validator_store: ValidatorStore<SystemTimeSlotClock, T> = ValidatorStore::new(
            validators,
            slashing_protection,
            genesis_validators_root,
            context.eth2_config.spec.clone(),
            fork_service.clone(),
            log.clone(),
        );

        info!(
            log,
            "Loaded validator keypair store";
            "voting_validators" => validator_store.num_voting_validators()
        );

        let duties_service = DutiesServiceBuilder::new()
            .slot_clock(slot_clock.clone())
            .validator_store(validator_store.clone())
            .beacon_nodes(beacon_nodes.clone())
            .allow_unsynced_beacon_node(config.allow_unsynced_beacon_node)
            .runtime_context(context.service_context("duties".into()))
            .build()?;

        // Update the metrics server.
        if let Some(ctx) = &http_metrics_ctx {
            ctx.shared.write().validator_store = Some(validator_store.clone());
            ctx.shared.write().duties_service = Some(duties_service.clone());
        }

        let block_service = BlockServiceBuilder::new()
            .slot_clock(slot_clock.clone())
            .validator_store(validator_store.clone())
            .beacon_nodes(beacon_nodes.clone())
            .runtime_context(context.service_context("block".into()))
            .graffiti(config.graffiti)
            .build()?;

        let attestation_service = AttestationServiceBuilder::new()
            .duties_service(duties_service.clone())
            .slot_clock(slot_clock)
            .validator_store(validator_store.clone())
            .beacon_nodes(beacon_nodes.clone())
            .runtime_context(context.service_context("attestation".into()))
            .build()?;

        // Wait until genesis has occured.
        //
        // It seems most sensible to move this into the `start_service` function, but I'm caution
        // of making too many changes this close to genesis (<1 week).
        wait_for_genesis(&beacon_nodes, genesis_time, &context).await?;

        Ok(Self {
            context,
            duties_service,
            fork_service,
            block_service,
            attestation_service,
            validator_store,
            config,
            http_api_listen_addr: None,
            http_metrics_ctx,
        })
    }

    pub fn start_service(&mut self) -> Result<(), String> {
        // We use `SLOTS_PER_EPOCH` as the capacity of the block notification channel, because
        // we don't except notifications to be delayed by more than a single slot, let alone a
        // whole epoch!
        let channel_capacity = T::slots_per_epoch() as usize;
        let (block_service_tx, block_service_rx) = mpsc::channel(channel_capacity);
        let log = self.context.log();

        self.duties_service
            .clone()
            .start_update_service(
                block_service_tx,
                Arc::new(self.context.eth2_config.spec.clone()),
            )
            .map_err(|e| format!("Unable to start duties service: {}", e))?;

        self.fork_service
            .clone()
            .start_update_service(&self.context)
            .map_err(|e| format!("Unable to start fork service: {}", e))?;

        self.block_service
            .clone()
            .start_update_service(block_service_rx)
            .map_err(|e| format!("Unable to start block service: {}", e))?;

        self.attestation_service
            .clone()
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start attestation service: {}", e))?;

        spawn_notifier(self).map_err(|e| format!("Failed to start notifier: {}", e))?;

        let api_secret = ApiSecret::create_or_open(&self.config.validator_dir)?;

        self.http_api_listen_addr = if self.config.http_api.enabled {
            let ctx: Arc<http_api::Context<SystemTimeSlotClock, T>> = Arc::new(http_api::Context {
                runtime: self.context.executor.runtime(),
                api_secret,
                validator_store: Some(self.validator_store.clone()),
                validator_dir: Some(self.config.validator_dir.clone()),
                spec: self.context.eth2_config.spec.clone(),
                config: self.config.http_api.clone(),
                log: log.clone(),
                _phantom: PhantomData,
            });

            let exit = self.context.executor.exit();

            let (listen_addr, server) = http_api::serve(ctx, exit)
                .map_err(|e| format!("Unable to start HTTP API server: {:?}", e))?;

            self.context
                .clone()
                .executor
                .spawn_without_exit(async move { server.await }, "http-api");

            Some(listen_addr)
        } else {
            info!(log, "HTTP API server is disabled");
            None
        };

        Ok(())
    }
}

async fn init_from_beacon_node<E: EthSpec>(
    beacon_nodes: &BeaconNodeFallback<SystemTimeSlotClock, E>,
    context: &RuntimeContext<E>,
) -> Result<(u64, Hash256, Fork), String> {
    loop {
        beacon_nodes.update_unready_candidates().await;
        let num_available = beacon_nodes.num_available().await;
        let num_total = beacon_nodes.num_total().await;
        if num_available > 0 {
            info!(
                context.log(),
                "Initialized beacon node connections";
                "total" => num_total,
                "available" => num_available,
            );
            break;
        } else {
            warn!(
                context.log(),
                "Unable to connect to a beacon node";
                "retry in" => format!("{} seconds", RETRY_DELAY.as_secs()),
                "total" => num_total,
                "available" => num_available,
            );
            sleep(RETRY_DELAY).await;
        }
    }

    let genesis = loop {
        match beacon_nodes
            .first_success(RequireSynced::No, |node| async move {
                node.get_beacon_genesis().await
            })
            .await
        {
            Ok(genesis) => break genesis.data,
            Err(errors) => {
                // Search for a 404 error which indicates that genesis has not yet
                // occurred.
                if errors
                    .0
                    .iter()
                    .filter_map(|(_, e)| e.request_failure())
                    .any(|e| e.status() == Some(StatusCode::NOT_FOUND))
                {
                    info!(
                        context.log(),
                        "Waiting for genesis";
                    );
                } else {
                    error!(
                        context.log(),
                        "Errors polling beacon node";
                        "error" => %errors
                    );
                }
            }
        }

        sleep(RETRY_DELAY).await;
    };

    let fork = loop {
        match beacon_nodes
            .first_success(RequireSynced::No, |node| async move {
                node.get_beacon_states_fork(StateId::Head).await
            })
            .await
        {
            Ok(Some(fork)) => break fork.data,
            Ok(None) => {
                info!(
                    context.log(),
                    "Failed to get fork, state not found";
                );
            }
            Err(errors) => {
                error!(
                    context.log(),
                    "Failed to get fork";
                    "error" => %errors
                );
            }
        }

        sleep(RETRY_DELAY).await;
    };

    Ok((genesis.genesis_time, genesis.genesis_validators_root, fork))
}

async fn wait_for_genesis<E: EthSpec>(
    beacon_nodes: &BeaconNodeFallback<SystemTimeSlotClock, E>,
    genesis_time: u64,
    context: &RuntimeContext<E>,
) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Unable to read system time: {:?}", e))?;
    let genesis_time = Duration::from_secs(genesis_time);

    // If the time now is less than (prior to) genesis, then delay until the
    // genesis instant.
    //
    // If the validator client starts before genesis, it will get errors from
    // the slot clock.
    if now < genesis_time {
        info!(
            context.log(),
            "Starting node prior to genesis";
            "seconds_to_wait" => (genesis_time - now).as_secs()
        );

        // Start polling the node for pre-genesis information, cancelling the polling as soon as the
        // timer runs out.
        tokio::select! {
            result = poll_whilst_waiting_for_genesis(beacon_nodes, genesis_time, context.log()) => result?,
            () = sleep(genesis_time - now) => ()
        };

        info!(
            context.log(),
            "Genesis has occurred";
            "ms_since_genesis" => (genesis_time - now).as_millis()
        );
    } else {
        info!(
            context.log(),
            "Genesis has already occurred";
            "seconds_ago" => (now - genesis_time).as_secs()
        );
    }

    Ok(())
}

/// Request the version from the node, looping back and trying again on failure. Exit once the node
/// has been contacted.
async fn poll_whilst_waiting_for_genesis<E: EthSpec>(
    beacon_nodes: &BeaconNodeFallback<SystemTimeSlotClock, E>,
    genesis_time: Duration,
    log: &Logger,
) -> Result<(), String> {
    loop {
        match beacon_nodes
            .first_success(RequireSynced::No, |beacon_node| async move {
                beacon_node.get_lighthouse_staking().await
            })
            .await
        {
            Ok(is_staking) => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| format!("Unable to read system time: {:?}", e))?;

                if !is_staking {
                    error!(
                        log,
                        "Staking is disabled for beacon node";
                        "msg" => "this will caused missed duties",
                        "info" => "see the --staking CLI flag on the beacon node"
                    );
                }

                if now < genesis_time {
                    info!(
                        log,
                        "Waiting for genesis";
                        "bn_staking_enabled" => is_staking,
                        "seconds_to_wait" => (genesis_time - now).as_secs()
                    );
                } else {
                    break Ok(());
                }
            }
            Err(e) => {
                error!(
                    log,
                    "Error polling beacon node";
                    "error" => %e
                );
            }
        }

        sleep(WAITING_FOR_GENESIS_POLL_TIME).await;
    }
}
