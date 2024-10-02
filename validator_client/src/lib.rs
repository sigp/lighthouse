mod attestation_service;
mod beacon_node_fallback;
mod block_service;
mod check_synced;
mod cli;
mod duties_service;
mod graffiti_file;
mod http_metrics;
mod key_cache;
mod latency;
mod notifier;
mod preparation_service;
mod signing_method;
mod sync_committee_service;

pub mod config;
mod doppelganger_service;
pub mod http_api;
pub mod initialized_validators;
pub mod validator_store;

pub use beacon_node_fallback::ApiTopic;
pub use cli::cli_app;
pub use config::Config;
use initialized_validators::InitializedValidators;
use lighthouse_metrics::set_gauge;
use monitoring_api::{MonitoringHttpClient, ProcessType};
use sensitive_url::SensitiveUrl;
pub use slashing_protection::{SlashingDatabase, SLASHING_PROTECTION_FILENAME};

use crate::beacon_node_fallback::{
    start_fallback_updater_service, BeaconNodeFallback, CandidateBeaconNode, OfflineOnFailure,
    RequireSynced,
};
use crate::doppelganger_service::DoppelgangerService;
use crate::graffiti_file::GraffitiFile;
use crate::initialized_validators::Error::UnableToOpenVotingKeystore;
use account_utils::validator_definitions::ValidatorDefinitions;
use attestation_service::{AttestationService, AttestationServiceBuilder};
use block_service::{BlockService, BlockServiceBuilder};
use clap::ArgMatches;
use duties_service::{sync::SyncDutiesMap, DutiesService};
use environment::RuntimeContext;
use eth2::{reqwest::ClientBuilder, types::Graffiti, BeaconNodeHttpClient, StatusCode, Timeouts};
use http_api::ApiSecret;
use notifier::spawn_notifier;
use parking_lot::RwLock;
use preparation_service::{PreparationService, PreparationServiceBuilder};
use reqwest::Certificate;
use slog::{debug, error, info, warn, Logger};
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
use types::{EthSpec, Hash256, PublicKeyBytes};
use validator_store::ValidatorStore;

/// The interval between attempts to contact the beacon node during startup.
const RETRY_DELAY: Duration = Duration::from_secs(2);

/// The time between polls when waiting for genesis.
const WAITING_FOR_GENESIS_POLL_TIME: Duration = Duration::from_secs(12);

/// Specific timeout constants for HTTP requests involved in different validator duties.
/// This can help ensure that proper endpoint fallback occurs.
const HTTP_ATTESTATION_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_ATTESTER_DUTIES_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_ATTESTATION_SUBSCRIPTIONS_TIMEOUT_QUOTIENT: u32 = 24;
const HTTP_LIVENESS_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_PROPOSAL_TIMEOUT_QUOTIENT: u32 = 2;
const HTTP_PROPOSER_DUTIES_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_SYNC_COMMITTEE_CONTRIBUTION_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_SYNC_DUTIES_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_GET_BEACON_BLOCK_SSZ_TIMEOUT_QUOTIENT: u32 = 4;
const HTTP_GET_DEBUG_BEACON_STATE_QUOTIENT: u32 = 4;
const HTTP_GET_DEPOSIT_SNAPSHOT_QUOTIENT: u32 = 4;
const HTTP_GET_VALIDATOR_BLOCK_TIMEOUT_QUOTIENT: u32 = 4;

const DOPPELGANGER_SERVICE_NAME: &str = "doppelganger";

#[derive(Clone)]
pub struct ProductionValidatorClient<E: EthSpec> {
    context: RuntimeContext<E>,
    duties_service: Arc<DutiesService<SystemTimeSlotClock, E>>,
    block_service: BlockService<SystemTimeSlotClock, E>,
    attestation_service: AttestationService<SystemTimeSlotClock, E>,
    sync_committee_service: SyncCommitteeService<SystemTimeSlotClock, E>,
    doppelganger_service: Option<Arc<DoppelgangerService>>,
    preparation_service: PreparationService<SystemTimeSlotClock, E>,
    validator_store: Arc<ValidatorStore<SystemTimeSlotClock, E>>,
    slot_clock: SystemTimeSlotClock,
    http_api_listen_addr: Option<SocketAddr>,
    config: Config,
    beacon_nodes: Arc<BeaconNodeFallback<SystemTimeSlotClock, E>>,
    genesis_time: u64,
}

impl<E: EthSpec> ProductionValidatorClient<E> {
    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub async fn new_from_cli(
        context: RuntimeContext<E>,
        cli_args: &ArgMatches,
    ) -> Result<Self, String> {
        let config = Config::from_cli(cli_args, context.log())
            .map_err(|e| format!("Unable to initialize config: {}", e))?;
        Self::new(context, config).await
    }

    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub async fn new(context: RuntimeContext<E>, config: Config) -> Result<Self, String> {
        let log = context.log().clone();

        // Attempt to raise soft fd limit. The behavior is OS specific:
        // `linux` - raise soft fd limit to hard
        // `macos` - raise soft fd limit to `min(kernel limit, hard fd limit)`
        // `windows` & rest - noop
        match fdlimit::raise_fd_limit().map_err(|e| format!("Unable to raise fd limit: {}", e))? {
            fdlimit::Outcome::LimitRaised { from, to } => {
                debug!(
                    log,
                    "Raised soft open file descriptor resource limit";
                    "old_limit" => from,
                    "new_limit" => to
                );
            }
            fdlimit::Outcome::Unsupported => {
                debug!(
                    log,
                    "Raising soft open file descriptor resource limit is not supported"
                );
            }
        };

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

            let ctx: Arc<http_metrics::Context<E>> = Arc::new(http_metrics::Context {
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
                .spawn_without_exit(server, "metrics-api");

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
            validator_defs.save(&config.validator_dir).map_err(|e| {
                format!(
                    "Provide --suggested-fee-recipient or update validator definitions: {:?}",
                    e
                )
            })?;
            info!(
                log,
                "Completed validator discovery";
                "new_validators" => new_validators,
            );
        }

        let validators = InitializedValidators::from_definitions(
            validator_defs,
            config.validator_dir.clone(),
            config.clone(),
            log.clone(),
        )
        .await
        .map_err(|e| {
            match e {
                UnableToOpenVotingKeystore(err) => {
                    format!("Unable to initialize validators: {:?}. If you have recently moved the location of your data directory \
                    make sure to update the location of voting_keystore_path in your validator_definitions.yml", err)
                },
                err => {
                    format!("Unable to initialize validators: {:?}", err)}
                }
            })?;

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

        let beacon_node_setup = |x: (usize, &SensitiveUrl)| {
            let i = x.0;
            let url = x.1;
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
                    attestation_subscriptions: slot_duration
                        / HTTP_ATTESTATION_SUBSCRIPTIONS_TIMEOUT_QUOTIENT,
                    liveness: slot_duration / HTTP_LIVENESS_TIMEOUT_QUOTIENT,
                    proposal: slot_duration / HTTP_PROPOSAL_TIMEOUT_QUOTIENT,
                    proposer_duties: slot_duration / HTTP_PROPOSER_DUTIES_TIMEOUT_QUOTIENT,
                    sync_committee_contribution: slot_duration
                        / HTTP_SYNC_COMMITTEE_CONTRIBUTION_TIMEOUT_QUOTIENT,
                    sync_duties: slot_duration / HTTP_SYNC_DUTIES_TIMEOUT_QUOTIENT,
                    get_beacon_blocks_ssz: slot_duration
                        / HTTP_GET_BEACON_BLOCK_SSZ_TIMEOUT_QUOTIENT,
                    get_debug_beacon_states: slot_duration / HTTP_GET_DEBUG_BEACON_STATE_QUOTIENT,
                    get_deposit_snapshot: slot_duration / HTTP_GET_DEPOSIT_SNAPSHOT_QUOTIENT,
                    get_validator_block: slot_duration / HTTP_GET_VALIDATOR_BLOCK_TIMEOUT_QUOTIENT,
                }
            } else {
                Timeouts::set_all(slot_duration)
            };

            Ok(BeaconNodeHttpClient::from_components(
                url.clone(),
                beacon_node_http_client,
                timeouts,
            ))
        };

        let beacon_nodes: Vec<BeaconNodeHttpClient> = config
            .beacon_nodes
            .iter()
            .enumerate()
            .map(beacon_node_setup)
            .collect::<Result<Vec<BeaconNodeHttpClient>, String>>()?;

        let proposer_nodes: Vec<BeaconNodeHttpClient> = config
            .proposer_nodes
            .iter()
            .enumerate()
            .map(beacon_node_setup)
            .collect::<Result<Vec<BeaconNodeHttpClient>, String>>()?;

        let num_nodes = beacon_nodes.len();
        let candidates = beacon_nodes
            .into_iter()
            .map(CandidateBeaconNode::new)
            .collect();

        let proposer_nodes_num = proposer_nodes.len();
        let proposer_candidates = proposer_nodes
            .into_iter()
            .map(CandidateBeaconNode::new)
            .collect();

        // Set the count for beacon node fallbacks excluding the primary beacon node.
        set_gauge(
            &http_metrics::metrics::ETH2_FALLBACK_CONFIGURED,
            num_nodes.saturating_sub(1) as i64,
        );
        // Set the total beacon node count.
        set_gauge(
            &http_metrics::metrics::TOTAL_BEACON_NODES_COUNT,
            num_nodes as i64,
        );

        // Initialize the number of connected, synced beacon nodes to 0.
        set_gauge(&http_metrics::metrics::ETH2_FALLBACK_CONNECTED, 0);
        set_gauge(&http_metrics::metrics::SYNCED_BEACON_NODES_COUNT, 0);
        // Initialize the number of connected, avaliable beacon nodes to 0.
        set_gauge(&http_metrics::metrics::AVAILABLE_BEACON_NODES_COUNT, 0);

        let mut beacon_nodes: BeaconNodeFallback<_, E> = BeaconNodeFallback::new(
            candidates,
            config.broadcast_topics.clone(),
            context.eth2_config.spec.clone(),
            log.clone(),
        );

        let mut proposer_nodes: BeaconNodeFallback<_, E> = BeaconNodeFallback::new(
            proposer_candidates,
            config.broadcast_topics.clone(),
            context.eth2_config.spec.clone(),
            log.clone(),
        );

        // Perform some potentially long-running initialization tasks.
        let (genesis_time, genesis_validators_root) = tokio::select! {
            tuple = init_from_beacon_node(&beacon_nodes, &proposer_nodes, &context) => tuple?,
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
        proposer_nodes.set_slot_clock(slot_clock.clone());

        let beacon_nodes = Arc::new(beacon_nodes);
        start_fallback_updater_service(context.clone(), beacon_nodes.clone())?;

        let proposer_nodes = Arc::new(proposer_nodes);
        start_fallback_updater_service(context.clone(), proposer_nodes.clone())?;

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
            &config,
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
            validator_store.prune_slashing_protection_db(slot.epoch(E::slots_per_epoch()), true);
        }

        let duties_context = context.service_context("duties".into());
        let duties_service = Arc::new(DutiesService {
            attesters: <_>::default(),
            proposers: <_>::default(),
            sync_duties: SyncDutiesMap::new(config.distributed),
            slot_clock: slot_clock.clone(),
            beacon_nodes: beacon_nodes.clone(),
            validator_store: validator_store.clone(),
            unknown_validator_next_poll_slots: <_>::default(),
            spec: context.eth2_config.spec.clone(),
            context: duties_context,
            enable_high_validator_count_metrics: config.enable_high_validator_count_metrics,
            distributed: config.distributed,
        });

        // Update the metrics server.
        if let Some(ctx) = &http_metrics_ctx {
            ctx.shared.write().validator_store = Some(validator_store.clone());
            ctx.shared.write().duties_service = Some(duties_service.clone());
        }

        let mut block_service_builder = BlockServiceBuilder::new()
            .slot_clock(slot_clock.clone())
            .validator_store(validator_store.clone())
            .beacon_nodes(beacon_nodes.clone())
            .runtime_context(context.service_context("block".into()))
            .graffiti(config.graffiti)
            .graffiti_file(config.graffiti_file.clone());

        // If we have proposer nodes, add them to the block service builder.
        if proposer_nodes_num > 0 {
            block_service_builder = block_service_builder.proposer_nodes(proposer_nodes.clone());
        }

        let block_service = block_service_builder.build()?;

        let attestation_service = AttestationServiceBuilder::new()
            .duties_service(duties_service.clone())
            .slot_clock(slot_clock.clone())
            .validator_store(validator_store.clone())
            .beacon_nodes(beacon_nodes.clone())
            .runtime_context(context.service_context("attestation".into()))
            .build()?;

        let preparation_service = PreparationServiceBuilder::new()
            .slot_clock(slot_clock.clone())
            .validator_store(validator_store.clone())
            .beacon_nodes(beacon_nodes.clone())
            .runtime_context(context.service_context("preparation".into()))
            .builder_registration_timestamp_override(config.builder_registration_timestamp_override)
            .validator_registration_batch_size(config.validator_registration_batch_size)
            .build()?;

        let sync_committee_service = SyncCommitteeService::new(
            duties_service.clone(),
            validator_store.clone(),
            slot_clock.clone(),
            beacon_nodes.clone(),
            context.service_context("sync_committee".into()),
        );

        Ok(Self {
            context,
            duties_service,
            block_service,
            attestation_service,
            sync_committee_service,
            doppelganger_service,
            preparation_service,
            validator_store,
            config,
            slot_clock,
            http_api_listen_addr: None,
            genesis_time,
            beacon_nodes,
        })
    }

    pub async fn start_service(&mut self) -> Result<(), String> {
        // We use `SLOTS_PER_EPOCH` as the capacity of the block notification channel, because
        // we don't expect notifications to be delayed by more than a single slot, let alone a
        // whole epoch!
        let channel_capacity = E::slots_per_epoch() as usize;
        let (block_service_tx, block_service_rx) = mpsc::channel(channel_capacity);
        let log = self.context.log();

        let api_secret = ApiSecret::create_or_open(&self.config.validator_dir)?;

        self.http_api_listen_addr = if self.config.http_api.enabled {
            let ctx = Arc::new(http_api::Context {
                task_executor: self.context.executor.clone(),
                api_secret,
                validator_store: Some(self.validator_store.clone()),
                validator_dir: Some(self.config.validator_dir.clone()),
                secrets_dir: Some(self.config.secrets_dir.clone()),
                graffiti_file: self.config.graffiti_file.clone(),
                graffiti_flag: self.config.graffiti,
                spec: self.context.eth2_config.spec.clone(),
                config: self.config.http_api.clone(),
                sse_logging_components: self.context.sse_logging_components.clone(),
                slot_clock: self.slot_clock.clone(),
                log: log.clone(),
                _phantom: PhantomData,
            });

            let exit = self.context.executor.exit();

            let (listen_addr, server) = http_api::serve(ctx, exit)
                .map_err(|e| format!("Unable to start HTTP API server: {:?}", e))?;

            self.context
                .clone()
                .executor
                .spawn_without_exit(server, "http-api");

            Some(listen_addr)
        } else {
            info!(log, "HTTP API server is disabled");
            None
        };

        // Wait until genesis has occurred.
        wait_for_genesis(&self.beacon_nodes, self.genesis_time, &self.context).await?;

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

        self.preparation_service
            .clone()
            .start_update_service(&self.context.eth2_config.spec)
            .map_err(|e| format!("Unable to start preparation service: {}", e))?;

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

        if self.config.enable_latency_measurement_service {
            latency::start_latency_service(
                self.context.clone(),
                self.duties_service.slot_clock.clone(),
                self.duties_service.beacon_nodes.clone(),
            );
        }

        Ok(())
    }
}

async fn init_from_beacon_node<E: EthSpec>(
    beacon_nodes: &BeaconNodeFallback<SystemTimeSlotClock, E>,
    proposer_nodes: &BeaconNodeFallback<SystemTimeSlotClock, E>,
    context: &RuntimeContext<E>,
) -> Result<(u64, Hash256), String> {
    loop {
        beacon_nodes.update_all_candidates().await;
        proposer_nodes.update_all_candidates().await;

        let num_available = beacon_nodes.num_available().await;
        let num_total = beacon_nodes.num_total();

        let proposer_available = proposer_nodes.num_available().await;
        let proposer_total = proposer_nodes.num_total();

        if proposer_total > 0 && proposer_available == 0 {
            warn!(
                context.log(),
                "Unable to connect to a proposer node";
                "retry in" => format!("{} seconds", RETRY_DELAY.as_secs()),
                "total_proposers" => proposer_total,
                "available_proposers" => proposer_available,
                "total_beacon_nodes" => num_total,
                "available_beacon_nodes" => num_available,
            );
        }

        if num_available > 0 && proposer_available == 0 {
            info!(
                context.log(),
                "Initialized beacon node connections";
                "total" => num_total,
                "available" => num_available,
            );
            break;
        } else if num_available > 0 {
            info!(
                context.log(),
                "Initialized beacon node connections";
                "total" => num_total,
                "available" => num_available,
                "proposers_available" => proposer_available,
                "proposers_total" => proposer_total,
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
            .first_success(
                RequireSynced::No,
                OfflineOnFailure::Yes,
                |node| async move { node.get_beacon_genesis().await },
            )
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
            .first_success(
                RequireSynced::No,
                OfflineOnFailure::Yes,
                |beacon_node| async move { beacon_node.get_lighthouse_staking().await },
            )
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

// Given the various graffiti control methods, determine the graffiti that will be used for
// the next block produced by the validator with the given public key.
pub fn determine_graffiti(
    validator_pubkey: &PublicKeyBytes,
    log: &Logger,
    graffiti_file: Option<GraffitiFile>,
    validator_definition_graffiti: Option<Graffiti>,
    graffiti_flag: Option<Graffiti>,
) -> Option<Graffiti> {
    graffiti_file
        .and_then(|mut g| match g.load_graffiti(validator_pubkey) {
            Ok(g) => g,
            Err(e) => {
                warn!(log, "Failed to read graffiti file"; "error" => ?e);
                None
            }
        })
        .or(validator_definition_graffiti)
        .or(graffiti_flag)
}
