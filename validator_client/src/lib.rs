mod attestation_service;
mod block_service;
mod cli;
mod config;
mod duties_service;
mod fork_service;
mod initialized_validators;
mod is_synced;
mod key_cache;
mod notifier;
mod validator_duty;
mod validator_store;

pub mod http_api;

pub use cli::cli_app;
pub use config::Config;

use account_utils::validator_definitions::ValidatorDefinitions;
use attestation_service::{AttestationService, AttestationServiceBuilder};
use block_service::{BlockService, BlockServiceBuilder};
use clap::ArgMatches;
use duties_service::{DutiesService, DutiesServiceBuilder};
use environment::RuntimeContext;
use eth2::{reqwest::ClientBuilder, BeaconNodeHttpClient, StatusCode, Url};
use fork_service::{ForkService, ForkServiceBuilder};
use futures::channel::mpsc;
use http_api::ApiSecret;
use initialized_validators::InitializedValidators;
use notifier::spawn_notifier;
use slashing_protection::{SlashingDatabase, SLASHING_PROTECTION_FILENAME};
use slog::{error, info, warn, Logger};
use slot_clock::SlotClock;
use slot_clock::SystemTimeSlotClock;
use std::marker::PhantomData;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::time::{delay_for, Duration};
use types::{EthSpec, Hash256, YamlConfig};
use validator_store::ValidatorStore;

/// The interval between attempts to contact the beacon node during startup.
const RETRY_DELAY: Duration = Duration::from_secs(2);

/// The global timeout for HTTP requests to the beacon node.
const HTTP_TIMEOUT: Duration = Duration::from_secs(12);

pub struct ProductionValidatorClient<T: EthSpec> {
    context: RuntimeContext<T>,
    duties_service: DutiesService<SystemTimeSlotClock, T>,
    fork_service: ForkService<SystemTimeSlotClock>,
    block_service: BlockService<SystemTimeSlotClock, T>,
    attestation_service: AttestationService<SystemTimeSlotClock, T>,
    validator_store: ValidatorStore<SystemTimeSlotClock, T>,
    http_api_listen_addr: Option<SocketAddr>,
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
            "beacon_node" => &config.beacon_node,
            "validator_dir" => format!("{:?}", config.validator_dir),
        );

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
            config.delete_lockfiles,
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

        let beacon_node_url: Url = config
            .beacon_node
            .parse()
            .map_err(|e| format!("Unable to parse beacon node URL: {:?}", e))?;
        let beacon_node_http_client = ClientBuilder::new()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| format!("Unable to build HTTP client: {:?}", e))?;
        let beacon_node =
            BeaconNodeHttpClient::from_components(beacon_node_url, beacon_node_http_client);

        // Perform some potentially long-running initialization tasks.
        let (yaml_config, genesis_time, genesis_validators_root) = tokio::select! {
            tuple = init_from_beacon_node(&beacon_node, &context) => tuple?,
            () = context.executor.exit() => return Err("Shutting down".to_string())
        };
        let beacon_node_spec = yaml_config.apply_to_chain_spec::<T>(&T::default_spec())
            .ok_or_else(||
                    "The minimal/mainnet spec type of the beacon node does not match the validator client. \
                    See the --testnet command.".to_string()
            )?;

        if context.eth2_config.spec != beacon_node_spec {
            return Err(
                "The beacon node is using a different Eth2 specification to this validator client. \
                See the --testnet command."
                    .to_string(),
            );
        }

        let slot_clock = SystemTimeSlotClock::new(
            context.eth2_config.spec.genesis_slot,
            Duration::from_secs(genesis_time),
            Duration::from_millis(context.eth2_config.spec.milliseconds_per_slot),
        );

        let fork_service = ForkServiceBuilder::new()
            .slot_clock(slot_clock.clone())
            .beacon_node(beacon_node.clone())
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
            .beacon_node(beacon_node.clone())
            .runtime_context(context.service_context("duties".into()))
            .allow_unsynced_beacon_node(config.allow_unsynced_beacon_node)
            .build()?;

        let block_service = BlockServiceBuilder::new()
            .slot_clock(slot_clock.clone())
            .validator_store(validator_store.clone())
            .beacon_node(beacon_node.clone())
            .runtime_context(context.service_context("block".into()))
            .graffiti(config.graffiti)
            .build()?;

        let attestation_service = AttestationServiceBuilder::new()
            .duties_service(duties_service.clone())
            .slot_clock(slot_clock)
            .validator_store(validator_store.clone())
            .beacon_node(beacon_node)
            .runtime_context(context.service_context("attestation".into()))
            .build()?;

        Ok(Self {
            context,
            duties_service,
            fork_service,
            block_service,
            attestation_service,
            validator_store,
            config,
            http_api_listen_addr: None,
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
    beacon_node: &BeaconNodeHttpClient,
    context: &RuntimeContext<E>,
) -> Result<(YamlConfig, u64, Hash256), String> {
    // Wait for the beacon node to come online.
    wait_for_node(beacon_node, context.log()).await?;

    let yaml_config = beacon_node
        .get_config_spec()
        .await
        .map_err(|e| format!("Unable to read spec from beacon node: {:?}", e))?
        .data;

    let genesis = loop {
        match beacon_node.get_beacon_genesis().await {
            Ok(genesis) => break genesis.data,
            Err(e) => {
                // A 404 error on the genesis endpoint indicates that genesis has not yet occurred.
                if e.status() == Some(StatusCode::NOT_FOUND) {
                    info!(
                        context.log(),
                        "Waiting for genesis";
                    );
                } else {
                    error!(
                        context.log(),
                        "Error polling beacon node";
                        "error" => format!("{:?}", e)
                    );
                }
            }
        }

        delay_for(RETRY_DELAY).await;
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Unable to read system time: {:?}", e))?;
    let genesis_time = Duration::from_secs(genesis.genesis_time);

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

        delay_for(genesis_time - now).await;
    } else {
        info!(
            context.log(),
            "Genesis has already occurred";
            "seconds_ago" => (now - genesis_time).as_secs()
        );
    }

    Ok((
        yaml_config,
        genesis.genesis_time,
        genesis.genesis_validators_root,
    ))
}

/// Request the version from the node, looping back and trying again on failure. Exit once the node
/// has been contacted.
async fn wait_for_node(beacon_node: &BeaconNodeHttpClient, log: &Logger) -> Result<(), String> {
    // Try to get the version string from the node, looping until success is returned.
    loop {
        let log = log.clone();
        let result = beacon_node
            .get_node_version()
            .await
            .map_err(|e| format!("{:?}", e))
            .map(|body| body.data.version);

        match result {
            Ok(version) => {
                info!(
                    log,
                    "Connected to beacon node";
                    "version" => version,
                );

                return Ok(());
            }
            Err(e) => {
                error!(
                    log,
                    "Unable to connect to beacon node";
                    "error" => format!("{:?}", e),
                );
                delay_for(RETRY_DELAY).await;
            }
        }
    }
}
