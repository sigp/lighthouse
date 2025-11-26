use crate::Client;
use crate::compute_light_client_updates::{
    LIGHT_CLIENT_SERVER_CHANNEL_CAPACITY, compute_light_client_updates,
};
use crate::config::{ClientGenesis, Config as ClientConfig};
use crate::notifier::spawn_notifier;
use beacon_chain::attestation_simulator::start_attestation_simulator_service;
use beacon_chain::data_availability_checker::start_availability_cache_maintenance_service;
use beacon_chain::graffiti_calculator::start_engine_version_cache_refresh_service;
use beacon_chain::proposer_prep_service::start_proposer_prep_service;
use beacon_chain::schema_change::migrate_schema;
use beacon_chain::{
    BeaconChain, BeaconChainTypes, MigratorConfig, ServerSentEventHandler,
    builder::{BeaconChainBuilder, Witness},
    slot_clock::{SlotClock, SystemTimeSlotClock},
    state_advance_timer::spawn_state_advance_timer,
    store::{HotColdDB, ItemStore, StoreConfig},
};
use beacon_chain::{Kzg, LightClientProducerEvent};
use beacon_processor::{BeaconProcessor, BeaconProcessorChannels};
use beacon_processor::{BeaconProcessorConfig, BeaconProcessorQueueLengths};
use environment::RuntimeContext;
use eth2::{
    BeaconNodeHttpClient, Error as ApiError, Timeouts,
    types::{BlockId, StateId},
};
use execution_layer::ExecutionLayer;
use execution_layer::test_utils::generate_genesis_header;
use futures::channel::mpsc::Receiver;
use genesis::{DEFAULT_ETH1_BLOCK_HASH, interop_genesis_state};
use lighthouse_network::identity::Keypair;
use lighthouse_network::{NetworkGlobals, prometheus_client::registry::Registry};
use monitoring_api::{MonitoringHttpClient, ProcessType};
use network::{NetworkConfig, NetworkSenders, NetworkService};
use rand::SeedableRng;
use rand::rngs::{OsRng, StdRng};
use slasher::Slasher;
use slasher_service::SlasherService;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};
use store::database::interface::BeaconNodeBackend;
use timer::spawn_timer;
use tracing::{debug, info, warn};
use types::data_column_custody_group::compute_ordered_custody_column_indices;
use types::{
    BeaconState, BlobSidecarList, ChainSpec, EthSpec, ExecutionBlockHash, Hash256,
    SignedBeaconBlock, test_utils::generate_deterministic_keypairs,
};

/// Interval between polling the eth1 node for genesis information.
pub const ETH1_GENESIS_UPDATE_INTERVAL_MILLIS: u64 = 7_000;

/// Reduces the blob availability period by some epochs. Helps prevent the user
/// from starting a genesis sync so near to the blob pruning window that blobs
/// have been pruned before they can manage to sync the chain.
const BLOB_AVAILABILITY_REDUCTION_EPOCHS: u64 = 2;

/// Builds a `Client` instance.
///
/// ## Notes
///
/// The builder may start some services (e.g.., libp2p, http server) immediately after they are
/// initialized, _before_ the `self.build(..)` method has been called.
///
/// Types may be elided and the compiler will infer them once all required methods have been
/// called.
///
/// If type inference errors are raised, ensure all necessary components have been initialized. For
/// example, the compiler will be unable to infer `T::Store` unless `self.disk_store(..)` or
/// `self.memory_store(..)` has been called.
pub struct ClientBuilder<T: BeaconChainTypes> {
    slot_clock: Option<T::SlotClock>,
    #[allow(clippy::type_complexity)]
    store: Option<Arc<HotColdDB<T::EthSpec, T::HotStore, T::ColdStore>>>,
    runtime_context: Option<RuntimeContext<T::EthSpec>>,
    chain_spec: Option<Arc<ChainSpec>>,
    beacon_chain_builder: Option<BeaconChainBuilder<T>>,
    beacon_chain: Option<Arc<BeaconChain<T>>>,
    network_globals: Option<Arc<NetworkGlobals<T::EthSpec>>>,
    network_senders: Option<NetworkSenders<T::EthSpec>>,
    libp2p_registry: Option<Registry>,
    db_path: Option<PathBuf>,
    freezer_db_path: Option<PathBuf>,
    http_api_config: http_api::Config,
    http_metrics_config: http_metrics::Config,
    slasher: Option<Arc<Slasher<T::EthSpec>>>,
    beacon_processor_config: Option<BeaconProcessorConfig>,
    beacon_processor_channels: Option<BeaconProcessorChannels<T::EthSpec>>,
    light_client_server_rv: Option<Receiver<LightClientProducerEvent<T::EthSpec>>>,
    eth_spec_instance: T::EthSpec,
}

impl<TSlotClock, E, THotStore, TColdStore>
    ClientBuilder<Witness<TSlotClock, E, THotStore, TColdStore>>
where
    TSlotClock: SlotClock + Clone + 'static,
    E: EthSpec + 'static,
    THotStore: ItemStore<E> + 'static,
    TColdStore: ItemStore<E> + 'static,
{
    /// Instantiates a new, empty builder.
    ///
    /// The `eth_spec_instance` parameter is used to concretize `E`.
    pub fn new(eth_spec_instance: E) -> Self {
        Self {
            slot_clock: None,
            store: None,
            runtime_context: None,
            chain_spec: None,
            beacon_chain_builder: None,
            beacon_chain: None,
            network_globals: None,
            network_senders: None,
            libp2p_registry: None,
            db_path: None,
            freezer_db_path: None,
            http_api_config: <_>::default(),
            http_metrics_config: <_>::default(),
            slasher: None,
            eth_spec_instance,
            beacon_processor_config: None,
            beacon_processor_channels: None,
            light_client_server_rv: None,
        }
    }

    /// Specifies the runtime context (tokio executor, logger, etc) for client services.
    pub fn runtime_context(mut self, context: RuntimeContext<E>) -> Self {
        self.runtime_context = Some(context);
        self
    }

    /// Specifies the `ChainSpec`.
    pub fn chain_spec(mut self, spec: Arc<ChainSpec>) -> Self {
        self.chain_spec = Some(spec);
        self
    }

    pub fn beacon_processor(mut self, config: BeaconProcessorConfig) -> Self {
        self.beacon_processor_channels = Some(BeaconProcessorChannels::new(&config));
        self.beacon_processor_config = Some(config);
        self
    }

    pub fn slasher(mut self, slasher: Arc<Slasher<E>>) -> Self {
        self.slasher = Some(slasher);
        self
    }

    /// Initializes the `BeaconChainBuilder`. The `build_beacon_chain` method will need to be
    /// called later in order to actually instantiate the `BeaconChain`.
    pub async fn beacon_chain_builder(
        mut self,
        client_genesis: ClientGenesis,
        config: ClientConfig,
        node_id: [u8; 32],
    ) -> Result<Self, String> {
        let store = self.store.clone();
        let chain_spec = self.chain_spec.clone();
        let runtime_context = self.runtime_context.clone();
        let eth_spec_instance = self.eth_spec_instance.clone();
        let chain_config = config.chain.clone();
        let beacon_graffiti = config.beacon_graffiti;

        let store = store.ok_or("beacon_chain_start_method requires a store")?;
        let runtime_context =
            runtime_context.ok_or("beacon_chain_start_method requires a runtime context")?;
        let context = runtime_context.service_context("beacon".into());
        let spec = chain_spec.ok_or("beacon_chain_start_method requires a chain spec")?;
        let event_handler = if self.http_api_config.enabled {
            Some(ServerSentEventHandler::new(
                self.http_api_config.sse_capacity_multiplier,
            ))
        } else {
            None
        };

        let execution_layer = if let Some(config) = config.execution_layer.clone() {
            let context = runtime_context.service_context("exec".into());
            let execution_layer = ExecutionLayer::from_config(config, context.executor.clone())
                .map_err(|e| format!("unable to start execution layer endpoints: {:?}", e))?;
            Some(execution_layer)
        } else {
            None
        };

        let kzg_err_msg = |e| format!("Failed to load trusted setup: {:?}", e);
        let kzg = if spec.is_peer_das_scheduled() {
            Kzg::new_from_trusted_setup(&config.trusted_setup).map_err(kzg_err_msg)?
        } else {
            Kzg::new_from_trusted_setup_no_precomp(&config.trusted_setup).map_err(kzg_err_msg)?
        };

        let ordered_custody_column_indices =
            compute_ordered_custody_column_indices::<E>(node_id, &spec).map_err(|e| {
                format!("Failed to compute ordered custody column indices: {:?}", e)
            })?;

        let builder = BeaconChainBuilder::new(eth_spec_instance, Arc::new(kzg))
            .store(store)
            .task_executor(context.executor.clone())
            .custom_spec(spec.clone())
            .store_migrator_config(
                MigratorConfig::default().epochs_per_migration(chain_config.epochs_per_migration),
            )
            .chain_config(chain_config)
            .beacon_graffiti(beacon_graffiti)
            .event_handler(event_handler)
            .execution_layer(execution_layer)
            .node_custody_type(config.chain.node_custody_type)
            .ordered_custody_column_indices(ordered_custody_column_indices)
            .validator_monitor_config(config.validator_monitor.clone())
            .rng(Box::new(
                StdRng::try_from_rng(&mut OsRng)
                    .map_err(|e| format!("Failed to create RNG: {:?}", e))?,
            ));

        let builder = if let Some(slasher) = self.slasher.clone() {
            builder.slasher(slasher)
        } else {
            builder
        };

        let builder = if config.network.enable_light_client_server {
            let (tx, rv) = futures::channel::mpsc::channel::<LightClientProducerEvent<E>>(
                LIGHT_CLIENT_SERVER_CHANNEL_CAPACITY,
            );
            self.light_client_server_rv = Some(rv);
            builder.light_client_server_tx(tx)
        } else {
            builder
        };

        let chain_exists = builder.store_contains_beacon_chain().unwrap_or(false);

        // If the client is expect to resume but there's no beacon chain in the database,
        // use the `DepositContract` method. This scenario is quite common when the client
        // is shutdown before finding genesis via eth1.
        //
        // Alternatively, if there's a beacon chain in the database then always resume
        // using it.
        let client_genesis = if matches!(client_genesis, ClientGenesis::FromStore) && !chain_exists
        {
            info!("Defaulting to deposit contract genesis");

            ClientGenesis::DepositContract
        } else if chain_exists {
            if matches!(client_genesis, ClientGenesis::WeakSubjSszBytes { .. })
                || matches!(client_genesis, ClientGenesis::CheckpointSyncUrl { .. })
            {
                info!(
                    msg = "database already exists, use --purge-db to force checkpoint sync",
                    "Refusing to checkpoint sync"
                );
            }

            ClientGenesis::FromStore
        } else {
            client_genesis
        };

        let beacon_chain_builder = match client_genesis {
            ClientGenesis::Interop {
                validator_count,
                genesis_time,
            } => {
                let keypairs = generate_deterministic_keypairs(validator_count);
                let genesis_state = interop_genesis_state(
                    &keypairs,
                    genesis_time,
                    Hash256::from_slice(DEFAULT_ETH1_BLOCK_HASH),
                    None,
                    &spec,
                )?;
                builder.genesis_state(genesis_state)?
            }
            ClientGenesis::InteropMerge {
                validator_count,
                genesis_time,
            } => {
                let execution_payload_header = generate_genesis_header(&spec, true);
                let keypairs = generate_deterministic_keypairs(validator_count);
                let genesis_state = interop_genesis_state(
                    &keypairs,
                    genesis_time,
                    Hash256::from_slice(DEFAULT_ETH1_BLOCK_HASH),
                    execution_payload_header,
                    &spec,
                )?;
                builder.genesis_state(genesis_state)?
            }
            ClientGenesis::GenesisState => {
                info!("Starting from known genesis state");

                let genesis_state = genesis_state(&runtime_context, &config).await?;

                // If the user has not explicitly allowed genesis sync, prevent
                // them from trying to sync from genesis if we're outside of the
                // blob P2P availability window.
                //
                // It doesn't make sense to try and sync the chain if we can't
                // verify blob availability by downloading blobs from the P2P
                // network. The user should do a checkpoint sync instead.
                if !config.allow_insecure_genesis_sync
                    && let Some(deneb_fork_epoch) = spec.deneb_fork_epoch
                {
                    let now = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map_err(|e| format!("Unable to read system time: {e:}"))?
                        .as_secs();
                    let genesis_time = genesis_state.genesis_time();
                    let deneb_time = genesis_time
                        + (deneb_fork_epoch.as_u64()
                            * E::slots_per_epoch()
                            * spec.seconds_per_slot);

                    // Shrink the blob availability window so users don't start
                    // a sync right before blobs start to disappear from the P2P
                    // network.
                    let reduced_p2p_availability_epochs = spec
                        .min_epochs_for_blob_sidecars_requests
                        .saturating_sub(BLOB_AVAILABILITY_REDUCTION_EPOCHS);
                    let blob_availability_window = reduced_p2p_availability_epochs
                        * E::slots_per_epoch()
                        * spec.seconds_per_slot;

                    if now > deneb_time + blob_availability_window {
                        return Err(
                                    "Syncing from genesis is insecure and incompatible with data availability checks. \
                                    You should instead perform a checkpoint sync from a trusted node using the --checkpoint-sync-url option. \
                                    For a list of public endpoints, see: https://eth-clients.github.io/checkpoint-sync-endpoints/ \
                                    Alternatively, use --allow-insecure-genesis-sync if the risks are understood."
                                        .to_string(),
                                );
                    }
                }

                builder.genesis_state(genesis_state)?
            }
            ClientGenesis::WeakSubjSszBytes {
                anchor_state_bytes,
                anchor_block_bytes,
                anchor_blobs_bytes,
            } => {
                info!("Starting checkpoint sync");
                if config.chain.genesis_backfill {
                    info!("Blocks will downloaded all the way back to genesis");
                }

                let anchor_state = BeaconState::from_ssz_bytes(&anchor_state_bytes, &spec)
                    .map_err(|e| format!("Unable to parse weak subj state SSZ: {:?}", e))?;
                let anchor_block = SignedBeaconBlock::from_ssz_bytes(&anchor_block_bytes, &spec)
                    .map_err(|e| format!("Unable to parse weak subj block SSZ: {:?}", e))?;

                // `BlobSidecar` is no longer used from Fulu onwards (superseded by `DataColumnSidecar`),
                // which will be fetched via rpc instead (unimplemented).
                let is_before_fulu = !spec
                    .fork_name_at_slot::<E>(anchor_block.slot())
                    .fulu_enabled();
                let anchor_blobs = if is_before_fulu && anchor_block.message().body().has_blobs() {
                    let max_blobs_len = spec.max_blobs_per_block(anchor_block.epoch()) as usize;
                    let anchor_blobs_bytes = anchor_blobs_bytes
                        .ok_or("Blobs for checkpoint must be provided using --checkpoint-blobs")?;
                    Some(
                        BlobSidecarList::from_ssz_bytes(&anchor_blobs_bytes, max_blobs_len)
                            .map_err(|e| format!("Unable to parse weak subj blobs SSZ: {e:?}"))?,
                    )
                } else {
                    None
                };
                let genesis_state = genesis_state(&runtime_context, &config).await?;

                builder.weak_subjectivity_state(
                    anchor_state,
                    anchor_block,
                    anchor_blobs,
                    genesis_state,
                )?
            }
            ClientGenesis::CheckpointSyncUrl { url } => {
                info!(
                    remote_url = %url,
                    "Starting checkpoint sync"
                );
                if config.chain.genesis_backfill {
                    info!("Blocks will be downloaded all the way back to genesis");
                }

                let remote = BeaconNodeHttpClient::new(
                    url,
                    Timeouts::set_all(Duration::from_secs(
                        config.chain.checkpoint_sync_url_timeout,
                    )),
                );

                debug!("Downloading finalized state");
                let state = remote
                    .get_debug_beacon_states_ssz::<E>(StateId::Finalized, &spec)
                    .await
                    .map_err(|e| format!("Error loading checkpoint state from remote: {:?}", e))?
                    .ok_or_else(|| "Checkpoint state missing from remote".to_string())?;

                debug!(slot = ?state.slot(), "Downloaded finalized state");

                let finalized_block_slot = state.latest_block_header().slot;

                debug!(block_slot = ?finalized_block_slot,"Downloading finalized block");
                let block = remote
                    .get_beacon_blocks_ssz::<E>(BlockId::Slot(finalized_block_slot), &spec)
                    .await
                    .map_err(|e| match e {
                        ApiError::InvalidSsz(e) => format!(
                            "Unable to parse SSZ: {:?}. Ensure the checkpoint-sync-url refers to a \
                            node for the correct network",
                            e
                        ),
                        e => format!("Error fetching finalized block from remote: {:?}", e),
                    })?
                    .ok_or("Finalized block missing from remote, it returned 404")?;
                let block_root = block.canonical_root();

                debug!("Downloaded finalized block");

                // `get_blob_sidecars` API is deprecated from Fulu and may not be supported by all servers
                let is_before_fulu = !spec
                    .fork_name_at_slot::<E>(finalized_block_slot)
                    .fulu_enabled();
                let blobs = if is_before_fulu && block.message().body().has_blobs() {
                    debug!("Downloading finalized blobs");
                    if let Some(response) = remote
                        .get_blob_sidecars::<E>(BlockId::Root(block_root), None, &spec)
                        .await
                        .map_err(|e| format!("Error fetching finalized blobs from remote: {e:?}"))?
                    {
                        debug!("Downloaded finalized blobs");
                        Some(response.into_data())
                    } else {
                        warn!(
                            block_root = %block_root,
                            hint = "use a different URL or ask the provider to update",
                            impact = "db will be slightly corrupt until these blobs are pruned",
                            "Checkpoint server is missing blobs"
                        );
                        None
                    }
                } else {
                    None
                };

                let genesis_state = genesis_state(&runtime_context, &config).await?;

                info!(
                    block_slot = %block.slot(),
                    state_slot = %state.slot(),
                    block_root = ?block_root,
                    "Loaded checkpoint block and state"
                );

                builder.weak_subjectivity_state(state, block, blobs, genesis_state)?
            }
            ClientGenesis::DepositContract => {
                return Err("Loading genesis from deposit contract no longer supported".to_string());
            }
            ClientGenesis::FromStore => builder.resume_from_db()?,
        };

        self.beacon_chain_builder = Some(beacon_chain_builder);
        Ok(self)
    }

    /// Starts the networking stack.
    pub async fn network(
        mut self,
        config: Arc<NetworkConfig>,
        local_keypair: Keypair,
    ) -> Result<Self, String> {
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or("network requires a beacon chain")?;
        let context = self
            .runtime_context
            .as_ref()
            .ok_or("network requires a runtime_context")?
            .clone();
        let beacon_processor_channels = self
            .beacon_processor_channels
            .as_ref()
            .ok_or("network requires beacon_processor_channels")?;

        // If gossipsub metrics are required we build a registry to record them
        let mut libp2p_registry = if config.metrics_enabled {
            Some(Registry::default())
        } else {
            None
        };

        let (network_globals, network_senders) = NetworkService::start(
            beacon_chain.clone(),
            config,
            context.executor,
            libp2p_registry.as_mut(),
            beacon_processor_channels.beacon_processor_tx.clone(),
            local_keypair,
        )
        .await
        .map_err(|e| format!("Failed to start network: {:?}", e))?;

        self.network_globals = Some(network_globals);
        self.network_senders = Some(network_senders);
        self.libp2p_registry = libp2p_registry;

        Ok(self)
    }

    /// Immediately starts the timer service.
    fn timer(self) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or("node timer requires a runtime_context")?
            .service_context("node_timer".into());
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or("node timer requires a beacon chain")?;

        spawn_timer(context.executor, beacon_chain)
            .map_err(|e| format!("Unable to start node timer: {}", e))?;

        Ok(self)
    }

    /// Provides configuration for the HTTP API.
    pub fn http_api_config(mut self, config: http_api::Config) -> Self {
        self.http_api_config = config;
        self
    }

    /// Provides configuration for the HTTP server that serves Prometheus metrics.
    pub fn http_metrics_config(mut self, config: http_metrics::Config) -> Self {
        self.http_metrics_config = config;
        self
    }

    /// Immediately start the slasher service.
    ///
    /// Error if no slasher is configured.
    pub fn start_slasher_service(&self) -> Result<(), String> {
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or("slasher service requires a beacon chain")?;
        let network_senders = self
            .network_senders
            .clone()
            .ok_or("slasher service requires network senders")?;
        let context = self
            .runtime_context
            .as_ref()
            .ok_or("slasher requires a runtime_context")?
            .service_context("slasher_service_ctxt".into());
        SlasherService::new(beacon_chain, network_senders.network_send()).run(&context.executor)
    }

    /// Start the explorer client which periodically sends beacon
    /// and system metrics to the configured endpoint.
    pub fn monitoring_client(self, config: &monitoring_api::Config) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or("monitoring_client requires a runtime_context")?
            .service_context("monitoring_client".into());
        let monitoring_client = MonitoringHttpClient::new(config)?;
        monitoring_client.auto_update(
            context.executor,
            vec![ProcessType::BeaconNode, ProcessType::System],
        );
        Ok(self)
    }

    /// Immediately starts the service that periodically logs information each slot.
    pub fn notifier(self) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or("slot_notifier requires a runtime_context")?
            .service_context("slot_notifier".into());
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or("slot_notifier requires a beacon chain")?;
        let network_globals = self
            .network_globals
            .clone()
            .ok_or("slot_notifier requires a libp2p network")?;
        let seconds_per_slot = self
            .chain_spec
            .as_ref()
            .ok_or("slot_notifier requires a chain spec")?
            .seconds_per_slot;

        spawn_notifier(
            context.executor,
            beacon_chain,
            network_globals,
            seconds_per_slot,
        )
        .map_err(|e| format!("Unable to start slot notifier: {}", e))?;

        Ok(self)
    }

    /// Consumes the builder, returning a `Client` if all necessary components have been
    /// specified.
    ///
    /// If type inference errors are being raised, see the comment on the definition of `Self`.
    #[allow(clippy::type_complexity)]
    pub fn build(
        mut self,
    ) -> Result<Client<Witness<TSlotClock, E, THotStore, TColdStore>>, String> {
        let runtime_context = self
            .runtime_context
            .as_ref()
            .ok_or("build requires a runtime context")?;
        let beacon_processor_channels = self
            .beacon_processor_channels
            .take()
            .ok_or("build requires beacon_processor_channels")?;
        let beacon_processor_config = self
            .beacon_processor_config
            .take()
            .ok_or("build requires a beacon_processor_config")?;

        let http_api_listen_addr = if self.http_api_config.enabled {
            let ctx = Arc::new(http_api::Context {
                config: self.http_api_config.clone(),
                chain: self.beacon_chain.clone(),
                network_senders: self.network_senders.clone(),
                network_globals: self.network_globals.clone(),
                beacon_processor_send: Some(beacon_processor_channels.beacon_processor_tx.clone()),
                sse_logging_components: runtime_context.sse_logging_components.clone(),
            });

            let exit = runtime_context.executor.exit();

            let (listen_addr, server) = http_api::serve(ctx, exit)
                .map_err(|e| format!("Unable to start HTTP API server: {:?}", e))?;

            let http_api_task = async move {
                server.await;
                debug!("HTTP API server task ended");
            };

            runtime_context
                .clone()
                .executor
                .spawn_without_exit(http_api_task, "http-api");

            Some(listen_addr)
        } else {
            info!("HTTP server is disabled");
            None
        };

        let http_metrics_listen_addr = if self.http_metrics_config.enabled {
            let ctx = Arc::new(http_metrics::Context {
                config: self.http_metrics_config.clone(),
                chain: self.beacon_chain.clone(),
                db_path: self.db_path.clone(),
                freezer_db_path: self.freezer_db_path.clone(),
                gossipsub_registry: self.libp2p_registry.take().map(std::sync::Mutex::new),
            });

            let exit = runtime_context.executor.exit();

            let (listen_addr, server) = http_metrics::serve(ctx, exit)
                .map_err(|e| format!("Unable to start HTTP metrics server: {:?}", e))?;

            runtime_context
                .executor
                .spawn_without_exit(server, "http-metrics");

            Some(listen_addr)
        } else {
            debug!("Metrics server is disabled");
            None
        };

        if self.slasher.is_some() {
            self.start_slasher_service()?;
        }

        if let Some(beacon_chain) = self.beacon_chain.as_ref() {
            if let Some(network_globals) = &self.network_globals {
                let beacon_processor_context = runtime_context.service_context("bproc".into());
                BeaconProcessor {
                    network_globals: network_globals.clone(),
                    executor: beacon_processor_context.executor.clone(),
                    current_workers: 0,
                    config: beacon_processor_config,
                }
                .spawn_manager(
                    beacon_processor_channels.beacon_processor_rx,
                    None,
                    beacon_chain.slot_clock.clone(),
                    beacon_chain.spec.maximum_gossip_clock_disparity(),
                    BeaconProcessorQueueLengths::from_state(
                        &beacon_chain
                            .canonical_head
                            .cached_head()
                            .snapshot
                            .beacon_state,
                        &beacon_chain.spec,
                    )?,
                )?;
            }

            let state_advance_context = runtime_context.service_context("state_advance".into());
            spawn_state_advance_timer(state_advance_context.executor, beacon_chain.clone());

            if let Some(execution_layer) = beacon_chain.execution_layer.as_ref() {
                // Only send a head update *after* genesis.
                if let Ok(current_slot) = beacon_chain.slot() {
                    let params = beacon_chain
                        .canonical_head
                        .cached_head()
                        .forkchoice_update_parameters();
                    if params
                        .head_hash
                        .is_some_and(|hash| hash != ExecutionBlockHash::zero())
                    {
                        // Spawn a new task to update the EE without waiting for it to complete.
                        let inner_chain = beacon_chain.clone();
                        runtime_context.executor.spawn(
                            async move {
                                let result = inner_chain
                                    .update_execution_engine_forkchoice(
                                        current_slot,
                                        params,
                                        Default::default(),
                                    )
                                    .await;

                                // No need to exit early if setting the head fails. It will be set again if/when the
                                // node comes online.
                                if let Err(e) = result {
                                    warn!(
                                        error = ?e,
                                        "Failed to update head on execution engines"
                                    );
                                }
                            },
                            "el_fork_choice_update",
                        );
                    }

                    // Spawn a routine that tracks the status of the execution engines.
                    execution_layer.spawn_watchdog_routine(beacon_chain.slot_clock.clone());

                    // Spawn a routine that removes expired proposer preparations.
                    execution_layer.spawn_clean_proposer_caches_routine::<TSlotClock>(
                        beacon_chain.slot_clock.clone(),
                    );
                }
            }

            // Spawn service to publish light_client updates at some interval into the slot.
            if let Some(light_client_server_rv) = self.light_client_server_rv {
                let inner_chain = beacon_chain.clone();
                let light_client_update_context =
                    runtime_context.service_context("lc_update".to_string());
                light_client_update_context.executor.spawn(
                    async move {
                        compute_light_client_updates(
                            &inner_chain,
                            light_client_server_rv,
                            beacon_processor_channels.beacon_processor_tx,
                        )
                        .await
                    },
                    "lc_update",
                );
            }

            start_proposer_prep_service(runtime_context.executor.clone(), beacon_chain.clone());
            start_availability_cache_maintenance_service(
                runtime_context.executor.clone(),
                beacon_chain.clone(),
            );
            start_engine_version_cache_refresh_service(
                beacon_chain.as_ref(),
                runtime_context.executor.clone(),
            );
            start_attestation_simulator_service(
                beacon_chain.task_executor.clone(),
                beacon_chain.clone(),
            );
        }

        Ok(Client {
            beacon_chain: self.beacon_chain,
            network_globals: self.network_globals,
            http_api_listen_addr,
            http_metrics_listen_addr,
        })
    }
}

impl<TSlotClock, E, THotStore, TColdStore>
    ClientBuilder<Witness<TSlotClock, E, THotStore, TColdStore>>
where
    TSlotClock: SlotClock + Clone + 'static,
    E: EthSpec + 'static,
    THotStore: ItemStore<E> + 'static,
    TColdStore: ItemStore<E> + 'static,
{
    /// Consumes the internal `BeaconChainBuilder`, attaching the resulting `BeaconChain` to self.
    pub fn build_beacon_chain(mut self) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or("beacon_chain requires a runtime context")?
            .clone();

        let chain = self
            .beacon_chain_builder
            .ok_or("beacon_chain requires a beacon_chain_builder")?
            .slot_clock(
                self.slot_clock
                    .clone()
                    .ok_or("beacon_chain requires a slot clock")?,
            )
            .shutdown_sender(context.executor.shutdown_sender())
            .build()
            .map_err(|e| format!("Failed to build beacon chain: {}", e))?;

        self.beacon_chain = Some(Arc::new(chain));
        self.beacon_chain_builder = None;

        // a beacon chain requires a timer
        self.timer()
    }
}

impl<TSlotClock, E>
    ClientBuilder<Witness<TSlotClock, E, BeaconNodeBackend<E>, BeaconNodeBackend<E>>>
where
    TSlotClock: SlotClock + 'static,
    E: EthSpec + 'static,
{
    /// Specifies that the `Client` should use a `HotColdDB` database.
    pub fn disk_store(
        mut self,
        hot_path: &Path,
        cold_path: &Path,
        blobs_path: &Path,
        config: StoreConfig,
    ) -> Result<Self, String> {
        let spec = self
            .chain_spec
            .clone()
            .ok_or("disk_store requires a chain spec")?;

        self.db_path = Some(hot_path.into());
        self.freezer_db_path = Some(cold_path.into());

        let schema_upgrade =
            |db, from, to| migrate_schema::<Witness<TSlotClock, _, _, _>>(db, from, to);

        let store = HotColdDB::open(
            hot_path,
            cold_path,
            blobs_path,
            schema_upgrade,
            config,
            spec,
        )
        .map_err(|e| format!("Unable to open database: {:?}", e))?;
        self.store = Some(store);
        Ok(self)
    }
}

impl<E, THotStore, TColdStore> ClientBuilder<Witness<SystemTimeSlotClock, E, THotStore, TColdStore>>
where
    E: EthSpec + 'static,
    THotStore: ItemStore<E> + 'static,
    TColdStore: ItemStore<E> + 'static,
{
    /// Specifies that the slot clock should read the time from the computers system clock.
    pub fn system_time_slot_clock(mut self) -> Result<Self, String> {
        let beacon_chain_builder = self
            .beacon_chain_builder
            .as_ref()
            .ok_or("system_time_slot_clock requires a beacon_chain_builder")?;

        let genesis_time = beacon_chain_builder
            .genesis_time
            .ok_or("system_time_slot_clock requires an initialized beacon state")?;

        let spec = self
            .chain_spec
            .clone()
            .ok_or("system_time_slot_clock requires a chain spec")?;

        let slot_clock = SystemTimeSlotClock::new(
            spec.genesis_slot,
            Duration::from_secs(genesis_time),
            Duration::from_secs(spec.seconds_per_slot),
        );

        self.slot_clock = Some(slot_clock);
        Ok(self)
    }
}

/// Obtain the genesis state from the `eth2_network_config` in `context`.
async fn genesis_state<E: EthSpec>(
    context: &RuntimeContext<E>,
    config: &ClientConfig,
) -> Result<BeaconState<E>, String> {
    let eth2_network_config = context
        .eth2_network_config
        .as_ref()
        .ok_or("An eth2_network_config is required to obtain the genesis state")?;
    eth2_network_config
        .genesis_state::<E>(
            config.genesis_state_url.as_deref(),
            config.genesis_state_url_timeout,
        )
        .await?
        .ok_or_else(|| "Genesis state is unknown".to_string())
}
