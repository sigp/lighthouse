pub mod cli;
pub mod config;

use crate::cli::ValidatorClient;
use crate::duties_service::SelectionProofConfig;
pub use config::Config;
use initialized_validators::InitializedValidators;
use metrics::set_gauge;
use monitoring_api::{MonitoringHttpClient, ProcessType};
use sensitive_url::SensitiveUrl;
use slashing_protection::{SLASHING_PROTECTION_FILENAME, SlashingDatabase};

use account_utils::validator_definitions::ValidatorDefinitions;
use beacon_node_fallback::{
    BeaconNodeFallback, CandidateBeaconNode, start_fallback_updater_service,
};
use clap::ArgMatches;
use doppelganger_service::DoppelgangerService;
use environment::RuntimeContext;
use eth2::{BeaconNodeHttpClient, StatusCode, Timeouts, reqwest::ClientBuilder};
use initialized_validators::Error::UnableToOpenVotingKeystore;
use lighthouse_validator_store::LighthouseValidatorStore;
use parking_lot::RwLock;
use reqwest::Certificate;
use slot_clock::SlotClock;
use slot_clock::SystemTimeSlotClock;
use std::fs::File;
use std::io::Read;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::{
    sync::mpsc,
    time::{Duration, sleep},
};
use tracing::{debug, error, info, warn};
use types::{EthSpec, Hash256};
use validator_http_api::ApiSecret;
use validator_services::notifier_service::spawn_notifier;
use validator_services::{
    attestation_service::{AttestationService, AttestationServiceBuilder},
    block_service::{BlockService, BlockServiceBuilder},
    duties_service::{self, DutiesService, DutiesServiceBuilder},
    latency_service,
    preparation_service::{PreparationService, PreparationServiceBuilder},
    sync_committee_service::SyncCommitteeService,
};
use validator_store::ValidatorStore as ValidatorStoreTrait;

/// The interval between attempts to contact the beacon node during startup.
const RETRY_DELAY: Duration = Duration::from_secs(2);

/// The time between polls when waiting for genesis.
const WAITING_FOR_GENESIS_POLL_TIME: Duration = Duration::from_secs(12);

const DOPPELGANGER_SERVICE_NAME: &str = "doppelganger";

/// Compute attestation selection proofs this many slots before they are required.
///
/// At start-up selection proofs will be computed with less lookahead out of necessity.
const SELECTION_PROOF_SLOT_LOOKAHEAD: u64 = 8;

/// The attestation selection proof lookahead for those running with the --distributed flag.
const SELECTION_PROOF_SLOT_LOOKAHEAD_DVT: u64 = 1;

/// Fraction of a slot at which attestation selection proof signing should happen (2 means half way).
const SELECTION_PROOF_SCHEDULE_DENOM: u32 = 2;

/// Number of epochs in advance to compute sync selection proofs when not in `distributed` mode.
pub const AGGREGATION_PRE_COMPUTE_EPOCHS: u64 = 2;
/// Number of slots in advance to compute sync selection proofs when in `distributed` mode.
pub const AGGREGATION_PRE_COMPUTE_SLOTS_DISTRIBUTED: u64 = 1;

type ValidatorStore<E> = LighthouseValidatorStore<SystemTimeSlotClock, E>;

#[derive(Clone)]
pub struct ProductionValidatorClient<E: EthSpec> {
    context: RuntimeContext<E>,
    duties_service: Arc<DutiesService<ValidatorStore<E>, SystemTimeSlotClock>>,
    block_service: BlockService<ValidatorStore<E>, SystemTimeSlotClock>,
    attestation_service: AttestationService<ValidatorStore<E>, SystemTimeSlotClock>,
    sync_committee_service: SyncCommitteeService<ValidatorStore<E>, SystemTimeSlotClock>,
    doppelganger_service: Option<Arc<DoppelgangerService>>,
    preparation_service: PreparationService<ValidatorStore<E>, SystemTimeSlotClock>,
    validator_store: Arc<ValidatorStore<E>>,
    slot_clock: SystemTimeSlotClock,
    http_api_listen_addr: Option<SocketAddr>,
    config: Config,
    genesis_time: u64,
}

impl<E: EthSpec> ProductionValidatorClient<E> {
    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub async fn new_from_cli(
        context: RuntimeContext<E>,
        cli_args: &ArgMatches,
        validator_client_config: &ValidatorClient,
    ) -> Result<Self, String> {
        let config = Config::from_cli(cli_args, validator_client_config)
            .map_err(|e| format!("Unable to initialize config: {}", e))?;
        Self::new(context, config).await
    }

    /// Instantiates the validator client, _without_ starting the timers to trigger block
    /// and attestation production.
    pub async fn new(context: RuntimeContext<E>, config: Config) -> Result<Self, String> {
        // Attempt to raise soft fd limit. The behavior is OS specific:
        // `linux` - raise soft fd limit to hard
        // `macos` - raise soft fd limit to `min(kernel limit, hard fd limit)`
        // `windows` & rest - noop
        match fdlimit::raise_fd_limit().map_err(|e| format!("Unable to raise fd limit: {}", e))? {
            fdlimit::Outcome::LimitRaised { from, to } => {
                debug!(
                    old_limit = from,
                    new_limit = to,
                    "Raised soft open file descriptor resource limit"
                );
            }
            fdlimit::Outcome::Unsupported => {
                debug!("Raising soft open file descriptor resource limit is not supported");
            }
        };

        info!(
            beacon_nodes = ?config.beacon_nodes,
            validator_dir = ?config.validator_dir,
            "Starting validator client"
        );

        // Optionally start the metrics server.
        let validator_metrics_ctx = if config.http_metrics.enabled {
            let shared = validator_http_metrics::Shared {
                validator_store: None,
                genesis_time: None,
                duties_service: None,
            };

            let ctx: Arc<validator_http_metrics::Context<E>> =
                Arc::new(validator_http_metrics::Context {
                    config: config.http_metrics.clone(),
                    shared: RwLock::new(shared),
                });

            let exit = context.executor.exit();

            let (_listen_addr, server) = validator_http_metrics::serve(ctx.clone(), exit)
                .map_err(|e| format!("Unable to start metrics API server: {:?}", e))?;

            context
                .clone()
                .executor
                .spawn_without_exit(server, "metrics-api");

            Some(ctx)
        } else {
            info!("HTTP metrics server is disabled");
            None
        };

        // Start the explorer client which periodically sends validator process
        // and system metrics to the configured endpoint.
        if let Some(monitoring_config) = &config.monitoring_api {
            let monitoring_client = MonitoringHttpClient::new(monitoring_config)?;
            monitoring_client.auto_update(
                context.executor.clone(),
                vec![ProcessType::Validator, ProcessType::System],
            );
        };

        let mut validator_defs = ValidatorDefinitions::open_or_create(&config.validator_dir)
            .map_err(|e| format!("Unable to open or create validator definitions: {:?}", e))?;

        if !config.disable_auto_discover {
            let new_validators = validator_defs
                .discover_local_keystores(&config.validator_dir, &config.secrets_dir)
                .map_err(|e| format!("Unable to discover local validator keystores: {:?}", e))?;
            validator_defs.save(&config.validator_dir).map_err(|e| {
                format!(
                    "Provide --suggested-fee-recipient or update validator definitions: {:?}",
                    e
                )
            })?;
            info!(new_validators, "Completed validator discovery");
        }

        let validators = InitializedValidators::from_definitions(
            validator_defs,
            config.validator_dir.clone(),
            config.initialized_validators.clone(),
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
            disabled = validators
                .num_total()
                .saturating_sub(validators.num_enabled()),
            enabled = validators.num_enabled(),
            "Initialized validators"
        );

        if voting_pubkeys.is_empty() {
            warn!(
                hint = "create validators via the API, or the `lighthouse account` CLI command",
                "No enabled validators"
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
                info!("Fallback endpoints are available, using optimized timeouts.");
                Timeouts::use_optimized_timeouts(slot_duration)
            } else {
                Timeouts::set_all(slot_duration.saturating_mul(config.long_timeouts_multiplier))
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
        // User order of `beacon_nodes` is preserved, so `index` corresponds to the position of
        // the node in `--beacon_nodes`.
        let candidates = beacon_nodes
            .into_iter()
            .enumerate()
            .map(|(index, node)| CandidateBeaconNode::new(node, index))
            .collect();

        let proposer_nodes_num = proposer_nodes.len();
        // User order of `proposer_nodes` is preserved, so `index` corresponds to the position of
        // the node in `--proposer_nodes`.
        let proposer_candidates = proposer_nodes
            .into_iter()
            .enumerate()
            .map(|(index, node)| CandidateBeaconNode::new(node, index))
            .collect();

        // Set the count for beacon node fallbacks excluding the primary beacon node.
        set_gauge(
            &validator_metrics::ETH2_FALLBACK_CONFIGURED,
            num_nodes.saturating_sub(1) as i64,
        );
        // Set the total beacon node count.
        set_gauge(
            &validator_metrics::TOTAL_BEACON_NODES_COUNT,
            num_nodes as i64,
        );

        // Initialize the number of connected, synced beacon nodes to 0.
        set_gauge(&validator_metrics::ETH2_FALLBACK_CONNECTED, 0);
        set_gauge(&validator_metrics::SYNCED_BEACON_NODES_COUNT, 0);
        // Initialize the number of connected, avaliable beacon nodes to 0.
        set_gauge(&validator_metrics::AVAILABLE_BEACON_NODES_COUNT, 0);

        let mut beacon_nodes: BeaconNodeFallback<_> = BeaconNodeFallback::new(
            candidates,
            config.beacon_node_fallback,
            config.broadcast_topics.clone(),
            context.eth2_config.spec.clone(),
        );

        let mut proposer_nodes: BeaconNodeFallback<_> = BeaconNodeFallback::new(
            proposer_candidates,
            config.beacon_node_fallback,
            config.broadcast_topics.clone(),
            context.eth2_config.spec.clone(),
        );

        // Perform some potentially long-running initialization tasks.
        let (genesis_time, genesis_validators_root) = tokio::select! {
            tuple = init_from_beacon_node::<E>(&beacon_nodes, &proposer_nodes) => tuple?,
            () = context.executor.exit() => return Err("Shutting down".to_string())
        };

        // Update the metrics server.
        if let Some(ctx) = &validator_metrics_ctx {
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
        start_fallback_updater_service::<_, E>(context.executor.clone(), beacon_nodes.clone())?;

        let proposer_nodes = Arc::new(proposer_nodes);
        start_fallback_updater_service::<_, E>(context.executor.clone(), proposer_nodes.clone())?;

        let doppelganger_service = if config.enable_doppelganger_protection {
            Some(Arc::new(DoppelgangerService::default()))
        } else {
            None
        };

        let validator_store = Arc::new(LighthouseValidatorStore::new(
            validators,
            slashing_protection,
            genesis_validators_root,
            context.eth2_config.spec.clone(),
            doppelganger_service.clone(),
            slot_clock.clone(),
            &config.validator_store,
            context.executor.clone(),
        ));

        // Ensure all validators are registered in doppelganger protection.
        validator_store.register_all_in_doppelganger_protection_if_enabled()?;

        info!(
            voting_validators = validator_store.num_voting_validators(),
            "Loaded validator keypair store"
        );

        // Perform pruning of the slashing protection database on start-up. In case the database is
        // oversized from having not been pruned (by a prior version) we don't want to prune
        // concurrently, as it will hog the lock and cause the attestation service to spew CRITs.
        if let Some(slot) = slot_clock.now() {
            validator_store.prune_slashing_protection_db(slot.epoch(E::slots_per_epoch()), true);
        }

        // Define a config to be pass to duties_service.
        // The defined config here defaults to using selections_endpoint and parallel_sign (i.e., distributed mode)
        // Other DVT applications, e.g., Anchor can pass in different configs to suit different needs.
        let attestation_selection_proof_config = if config.distributed {
            SelectionProofConfig {
                lookahead_slot: SELECTION_PROOF_SLOT_LOOKAHEAD_DVT,
                computation_offset: slot_clock.slot_duration() / SELECTION_PROOF_SCHEDULE_DENOM,
                selections_endpoint: true,
                parallel_sign: true,
            }
        } else {
            SelectionProofConfig {
                lookahead_slot: SELECTION_PROOF_SLOT_LOOKAHEAD,
                computation_offset: slot_clock.slot_duration() / SELECTION_PROOF_SCHEDULE_DENOM,
                selections_endpoint: false,
                parallel_sign: false,
            }
        };

        let sync_selection_proof_config = if config.distributed {
            SelectionProofConfig {
                lookahead_slot: AGGREGATION_PRE_COMPUTE_SLOTS_DISTRIBUTED,
                computation_offset: Duration::default(),
                selections_endpoint: true,
                parallel_sign: true,
            }
        } else {
            SelectionProofConfig {
                lookahead_slot: E::slots_per_epoch() * AGGREGATION_PRE_COMPUTE_EPOCHS,
                computation_offset: Duration::default(),
                selections_endpoint: false,
                parallel_sign: false,
            }
        };

        let duties_service = Arc::new(
            DutiesServiceBuilder::new()
                .slot_clock(slot_clock.clone())
                .beacon_nodes(beacon_nodes.clone())
                .validator_store(validator_store.clone())
                .spec(context.eth2_config.spec.clone())
                .executor(context.executor.clone())
                .enable_high_validator_count_metrics(config.enable_high_validator_count_metrics)
                .attestation_selection_proof_config(attestation_selection_proof_config)
                .sync_selection_proof_config(sync_selection_proof_config)
                .disable_attesting(config.disable_attesting)
                .build()?,
        );

        // Update the metrics server.
        if let Some(ctx) = &validator_metrics_ctx {
            ctx.shared.write().validator_store = Some(validator_store.clone());
            ctx.shared.write().duties_service = Some(duties_service.clone());
        }

        let mut block_service_builder = BlockServiceBuilder::new()
            .slot_clock(slot_clock.clone())
            .validator_store(validator_store.clone())
            .beacon_nodes(beacon_nodes.clone())
            .executor(context.executor.clone())
            .chain_spec(context.eth2_config.spec.clone())
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
            .executor(context.executor.clone())
            .chain_spec(context.eth2_config.spec.clone())
            .disable(config.disable_attesting)
            .build()?;

        let preparation_service = PreparationServiceBuilder::new()
            .slot_clock(slot_clock.clone())
            .validator_store(validator_store.clone())
            .beacon_nodes(beacon_nodes.clone())
            .executor(context.executor.clone())
            .builder_registration_timestamp_override(config.builder_registration_timestamp_override)
            .validator_registration_batch_size(config.validator_registration_batch_size)
            .build()?;

        let sync_committee_service = SyncCommitteeService::new(
            duties_service.clone(),
            validator_store.clone(),
            slot_clock.clone(),
            beacon_nodes.clone(),
            context.executor.clone(),
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
        })
    }

    pub async fn start_service(&mut self) -> Result<(), String> {
        // We use `SLOTS_PER_EPOCH` as the capacity of the block notification channel, because
        // we don't expect notifications to be delayed by more than a single slot, let alone a
        // whole epoch!
        let channel_capacity = E::slots_per_epoch() as usize;
        let (block_service_tx, block_service_rx) = mpsc::channel(channel_capacity);

        let api_secret = ApiSecret::create_or_open(&self.config.http_api.http_token_path)?;

        self.http_api_listen_addr = if self.config.http_api.enabled {
            let ctx = Arc::new(validator_http_api::Context {
                task_executor: self.context.executor.clone(),
                api_secret,
                block_service: Some(self.block_service.clone()),
                validator_store: Some(self.validator_store.clone()),
                validator_dir: Some(self.config.validator_dir.clone()),
                secrets_dir: Some(self.config.secrets_dir.clone()),
                graffiti_file: self.config.graffiti_file.clone(),
                graffiti_flag: self.config.graffiti,
                spec: self.context.eth2_config.spec.clone(),
                config: self.config.http_api.clone(),
                sse_logging_components: self.context.sse_logging_components.clone(),
                slot_clock: self.slot_clock.clone(),
            });

            let exit = self.context.executor.exit();

            let (listen_addr, server) = validator_http_api::serve::<_, E>(ctx, exit)
                .map_err(|e| format!("Unable to start HTTP API server: {:?}", e))?;

            self.context
                .clone()
                .executor
                .spawn_without_exit(server, "http-api");

            Some(listen_addr)
        } else {
            info!("HTTP API server is disabled");
            None
        };

        // Wait until genesis has occurred.
        wait_for_genesis(self.genesis_time).await?;

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
            info!("Doppelganger protection disabled.")
        }

        let context = self.context.service_context("notifier".into());
        spawn_notifier(
            self.duties_service.clone(),
            context.executor,
            &self.context.eth2_config.spec,
        )
        .map_err(|e| format!("Failed to start notifier: {}", e))?;

        if self.config.enable_latency_measurement_service {
            latency_service::start_latency_service(
                self.context.executor.clone(),
                self.duties_service.slot_clock.clone(),
                self.duties_service.beacon_nodes.clone(),
            );
        }

        Ok(())
    }
}

async fn init_from_beacon_node<E: EthSpec>(
    beacon_nodes: &BeaconNodeFallback<SystemTimeSlotClock>,
    proposer_nodes: &BeaconNodeFallback<SystemTimeSlotClock>,
) -> Result<(u64, Hash256), String> {
    loop {
        beacon_nodes.update_all_candidates::<E>().await;
        proposer_nodes.update_all_candidates::<E>().await;

        let num_available = beacon_nodes.num_available().await;
        let num_total = beacon_nodes.num_total().await;

        let proposer_available = proposer_nodes.num_available().await;
        let proposer_total = proposer_nodes.num_total().await;

        if proposer_total > 0 && proposer_available == 0 {
            warn!(
                retry_in = format!("{} seconds", RETRY_DELAY.as_secs()),
                total_proposers = proposer_total,
                available_proposers = proposer_available,
                total_beacon_nodes = num_total,
                available_beacon_nodes = num_available,
                "Unable to connect to a proposer node"
            );
        }

        if num_available > 0 && proposer_available == 0 {
            info!(
                total = num_total,
                available = num_available,
                "Initialized beacon node connections"
            );
            break;
        } else if num_available > 0 {
            info!(
                total = num_total,
                available = num_available,
                proposer_available,
                proposer_total,
                "Initialized beacon node connections"
            );
            break;
        } else {
            warn!(
                retry_in = format!("{} seconds", RETRY_DELAY.as_secs()),
                total = num_total,
                available = num_available,
                "Unable to connect to a beacon node"
            );
            sleep(RETRY_DELAY).await;
        }
    }

    let genesis = loop {
        match beacon_nodes
            .first_success(|node| async move { node.get_beacon_genesis().await })
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
                    info!("Waiting for genesis");
                } else {
                    error!(
                        %errors,
                        "Errors polling beacon node"
                    );
                }
            }
        }

        sleep(RETRY_DELAY).await;
    };

    Ok((genesis.genesis_time, genesis.genesis_validators_root))
}

async fn wait_for_genesis(genesis_time: u64) -> Result<(), String> {
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
            seconds_to_wait = (genesis_time - now).as_secs(),
            "Starting node prior to genesis"
        );

        // Start polling the node for pre-genesis information, cancelling the polling as soon as the
        // timer runs out.
        tokio::select! {
            result = poll_whilst_waiting_for_genesis(genesis_time) => result?,
            () = sleep(genesis_time - now) => ()
        };

        info!(
            ms_since_genesis = (genesis_time - now).as_millis(),
            "Genesis has occurred"
        );
    } else {
        info!(
            seconds_ago = (now - genesis_time).as_secs(),
            "Genesis has already occurred"
        );
    }

    Ok(())
}

/// Request the version from the node, looping back and trying again on failure. Exit once the node
/// has been contacted.
async fn poll_whilst_waiting_for_genesis(genesis_time: Duration) -> Result<(), String> {
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Unable to read system time: {:?}", e))?;

        if now < genesis_time {
            info!(
                seconds_to_wait = (genesis_time - now).as_secs(),
                "Waiting for genesis"
            );
        } else {
            break Ok(());
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
