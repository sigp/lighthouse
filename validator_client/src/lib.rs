mod attestation_service;
mod beacon_node_fallback;
mod block_service;
mod check_synced;
mod cli;
mod config;
mod duties_service;
mod graffiti_file;
mod http_metrics;
mod key_cache;
mod notifier;
mod signing_method;
mod sync_committee_service;

mod doppelganger_service;
pub mod http_api;
pub mod initialized_validators;
pub mod validator_store;

pub use cli::cli_app;
pub use config::Config;
use initialized_validators::InitializedValidators;
use lighthouse_metrics::set_gauge;
use monitoring_api::{MonitoringHttpClient, ProcessType};
pub use slashing_protection::{SlashingDatabase, SLASHING_PROTECTION_FILENAME};

use crate::beacon_node_fallback::{
    start_fallback_updater_service, BeaconNodeFallback, CandidateBeaconNode, RequireSynced,
};
use crate::doppelganger_service::DoppelgangerService;
use account_utils::validator_definitions::ValidatorDefinitions;
use attestation_service::{AttestationService, AttestationServiceBuilder};
use block_service::{BlockService, BlockServiceBuilder};
use clap::ArgMatches;
use duties_service::DutiesService;
use environment::RuntimeContext;
use eth2::{reqwest::ClientBuilder, BeaconNodeHttpClient, StatusCode, Timeouts};
use http_api::ApiSecret;
use notifier::spawn_notifier;
use parking_lot::RwLock;
use reqwest::Certificate;
use slog::{error, info, warn, Logger};
use slot_clock::SlotClock;
use slot_clock::SystemTimeSlotClock;
use std::fs::File;
use std::io::Read;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use sync_committee_service::SyncCommitteeService;
use tokio::{
    sync::mpsc,
    time::{sleep, Duration},
};
use types::{EthSpec, Hash256};
use validator_store::ValidatorStore;

/// The interval between attempts to contact the beacon node during startup.
const RETRY_DELAY: Duration = Duration::from_secs(2);

/// The time between polls when waiting for genesis.
const WAITING_FOR_GENESIS_POLL_TIME: Duration = Duration::from_secs(12);

/// Specific timeout constants for HTTP requests involved in different validator duties.
/// This can help ensure that proper endpoint fallback occurs.
const HTTP_ATTESTATION_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_ATTESTER_DUTIES_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_LIVENESS_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_PROPOSAL_TIMEOUT_QUOTIENT: u32 = 2;
const HTTP_PROPOSER_DUTIES_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_SYNC_DUTIES_TIMEOUT_QUOTIENT: u32 = 4;

const DOPPELGANGER_SERVICE_NAME: &str = "doppelganger";

#[derive(Clone)]
pub struct ProductionValidatorClient<T: EthSpec> {
    context: RuntimeContext<T>,
    duties_service: Arc<DutiesService<SystemTimeSlotClock, T>>,
    block_service: BlockService<SystemTimeSlotClock, T>,
    attestation_service: AttestationService<SystemTimeSlotClock, T>,
    sync_committee_service: SyncCommitteeService<SystemTimeSlotClock, T>,
    doppelganger_service: Option<Arc<DoppelgangerService>>,
    validator_store: Arc<ValidatorStore<SystemTimeSlotClock, T>>,
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
        let config = Config::from_cli(cli_args, context.log())
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

        // Start the explorer client which periodically sends validator process
        // and system metrics to the configured endpoint.
        if let Some(monitoring_config) = &config.monitoring_api {
            let monitoring_client =
                MonitoringHttpClient::new(monitoring_config, context.log().clone())?;
            monitoring_client.auto_update(
                context.executor.clone(),
                vec![ProcessType::Validator, ProcessType::System],
            );
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

        let last_beacon_node_index = config
            .beacon_nodes
            .len()
            .checked_sub(1)
            .ok_or_else(|| "No beacon nodes defined.".to_string())?;

        let beacon_nodes: Vec<BeaconNodeHttpClient> = config
            .beacon_nodes
            .iter()
            .enumerate()
            .map(|(i, url)| {
                let slot_duration = Duration::from_secs(context.eth2_config.spec.seconds_per_slot);

                let mut beacon_node_http_client_builder = ClientBuilder::new();

                // Add new custom root certificates if specified.
                if let Some(certificates) = &config.beacon_nodes_tls_certs {
                    for cert in certificates {
                        beacon_node_http_client_builder = beacon_node_http_client_builder
                            .add_root_certificate(load_pem_certificate(cert)?);
                    }
                }

                let beacon_node_http_client = beacon_node_http_client_builder
                    // Set default timeout to be the full slot duration.
                    .timeout(slot_duration)
                    .build()
                    .map_err(|e| format!("Unable to build HTTP client: {:?}", e))?;

                // Use quicker timeouts if a fallback beacon node exists.
                let timeouts = if i < last_beacon_node_index && !config.use_long_timeouts {
                    info!(
                        log,
                        "Fallback endpoints are available, using optimized timeouts.";
                    );
                    Timeouts {
                        attestation: slot_duration / HTTP_ATTESTATION_TIMEOUT_QUOTIENT,
                        attester_duties: slot_duration / HTTP_ATTESTER_DUTIES_TIMEOUT_QUOTIENT,
                        liveness: slot_duration / HTTP_LIVENESS_TIMEOUT_QUOTIENT,
                        proposal: slot_duration / HTTP_PROPOSAL_TIMEOUT_QUOTIENT,
                        proposer_duties: slot_duration / HTTP_PROPOSER_DUTIES_TIMEOUT_QUOTIENT,
                        sync_duties: slot_duration / HTTP_SYNC_DUTIES_TIMEOUT_QUOTIENT,
                    }
                } else {
                    Timeouts::set_all(slot_duration)
                };

                Ok(BeaconNodeHttpClient::from_components(
                    url.clone(),
                    beacon_node_http_client,
                    timeouts,
                ))
            })
            .collect::<Result<Vec<BeaconNodeHttpClient>, String>>()?;

        let num_nodes = beacon_nodes.len();
        let candidates = beacon_nodes
            .into_iter()
            .map(CandidateBeaconNode::new)
            .collect();

        // Set the count for beacon node fallbacks excluding the primary beacon node.
        set_gauge(
            &http_metrics::metrics::ETH2_FALLBACK_CONFIGURED,
            num_nodes.saturating_sub(1) as i64,
        );
        // Initialize the number of connected, synced fallbacks to 0.
        set_gauge(&http_metrics::metrics::ETH2_FALLBACK_CONNECTED, 0);
        let mut beacon_nodes: BeaconNodeFallback<_, T> =
            BeaconNodeFallback::new(candidates, context.eth2_config.spec.clone(), log.clone());

        // Perform some potentially long-running initialization tasks.
        let (genesis_time, genesis_validators_root) = tokio::select! {
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

        let doppelganger_service = if config.enable_doppelganger_protection {
            Some(Arc::new(DoppelgangerService::new(
                context
                    .service_context(DOPPELGANGER_SERVICE_NAME.into())
                    .log()
                    .clone(),
            )))
        } else {
            None
        };

        let validator_store = Arc::new(ValidatorStore::new(
            validators,
            slashing_protection,
            genesis_validators_root,
            context.eth2_config.spec.clone(),
            doppelganger_service.clone(),
            slot_clock.clone(),
            context.executor.clone(),
            log.clone(),
        ));

        // Ensure all validators are registered in doppelganger protection.
        validator_store.register_all_in_doppelganger_protection_if_enabled()?;

        info!(
            log,
            "Loaded validator keypair store";
            "voting_validators" => validator_store.num_voting_validators()
        );

        // Perform pruning of the slashing protection database on start-up. In case the database is
        // oversized from having not been pruned (by a prior version) we don't want to prune
        // concurrently, as it will hog the lock and cause the attestation service to spew CRITs.
        if let Some(slot) = slot_clock.now() {
            validator_store.prune_slashing_protection_db(slot.epoch(T::slots_per_epoch()), true);
        }

        let duties_context = context.service_context("duties".into());
        let duties_service = Arc::new(DutiesService {
            attesters: <_>::default(),
            proposers: <_>::default(),
            sync_duties: <_>::default(),
            slot_clock: slot_clock.clone(),
            beacon_nodes: beacon_nodes.clone(),
            validator_store: validator_store.clone(),
            require_synced: if config.allow_unsynced_beacon_node {
                RequireSynced::Yes
            } else {
                RequireSynced::No
            },
            spec: context.eth2_config.spec.clone(),
            context: duties_context,
        });

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
            .graffiti_file(config.graffiti_file.clone())
            .build()?;

        let attestation_service = AttestationServiceBuilder::new()
            .duties_service(duties_service.clone())
            .slot_clock(slot_clock.clone())
            .validator_store(validator_store.clone())
            .beacon_nodes(beacon_nodes.clone())
            .runtime_context(context.service_context("attestation".into()))
            .build()?;

        let sync_committee_service = SyncCommitteeService::new(
            duties_service.clone(),
            validator_store.clone(),
            slot_clock,
            beacon_nodes.clone(),
            context.service_context("sync_committee".into()),
        );

        // Wait until genesis has occured.
        //
        // It seems most sensible to move this into the `start_service` function, but I'm caution
        // of making too many changes this close to genesis (<1 week).
        wait_for_genesis(&beacon_nodes, genesis_time, &context).await?;

        Ok(Self {
            context,
            duties_service,
            block_service,
            attestation_service,
            sync_committee_service,
            doppelganger_service,
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

        duties_service::start_update_service(self.duties_service.clone(), block_service_tx);

        self.block_service
            .clone()
            .start_update_service(block_service_rx)
            .map_err(|e| format!("Unable to start block service: {}", e))?;

        self.attestation_service
            .clone()
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start attestation service: {}", e))?;

        self.sync_committee_service
            .clone()
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start sync committee service: {}", e))?;

        if let Some(doppelganger_service) = self.doppelganger_service.clone() {
            DoppelgangerService::start_update_service(
                doppelganger_service,
                self.context
                    .service_context(DOPPELGANGER_SERVICE_NAME.into()),
                self.validator_store.clone(),
                self.duties_service.beacon_nodes.clone(),
                self.duties_service.slot_clock.clone(),
            )
            .map_err(|e| format!("Unable to start doppelganger service: {}", e))?
        } else {
            info!(log, "Doppelganger protection disabled.")
        }

        spawn_notifier(self).map_err(|e| format!("Failed to start notifier: {}", e))?;

        let api_secret = ApiSecret::create_or_open(&self.config.validator_dir)?;

        self.http_api_listen_addr = if self.config.http_api.enabled {
            let ctx = Arc::new(http_api::Context {
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
) -> Result<(u64, Hash256), String> {
    loop {
        beacon_nodes.update_unready_candidates().await;
        let num_available = beacon_nodes.num_available().await;
        let num_total = beacon_nodes.num_total();
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

    Ok((genesis.genesis_time, genesis.genesis_validators_root))
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

pub fn load_pem_certificate<P: AsRef<Path>>(pem_path: P) -> Result<Certificate, String> {
    let mut buf = Vec::new();
    File::open(&pem_path)
        .map_err(|e| format!("Unable to open certificate path: {}", e))?
        .read_to_end(&mut buf)
        .map_err(|e| format!("Unable to read certificate file: {}", e))?;
    Certificate::from_pem(&buf).map_err(|e| format!("Unable to parse certificate: {}", e))
}
