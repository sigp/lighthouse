use crate::config::{ClientGenesis, Config as ClientConfig};
use crate::notifier::spawn_notifier;
use crate::Client;
use beacon_chain::proposer_prep_service::start_proposer_prep_service;
use beacon_chain::schema_change::migrate_schema;
use beacon_chain::{
    builder::{BeaconChainBuilder, Witness},
    eth1_chain::{CachingEth1Backend, Eth1Chain},
    slot_clock::{SlotClock, SystemTimeSlotClock},
    state_advance_timer::spawn_state_advance_timer,
    store::{HotColdDB, ItemStore, LevelDB, StoreConfig},
    BeaconChain, BeaconChainTypes, Eth1ChainBackend, ServerSentEventHandler,
};
use environment::RuntimeContext;
use eth1::{Config as Eth1Config, Service as Eth1Service};
use eth2::{
    types::{BlockId, StateId},
    BeaconNodeHttpClient, Error as ApiError, Timeouts,
};
use execution_layer::ExecutionLayer;
use genesis::{interop_genesis_state, Eth1GenesisService, DEFAULT_ETH1_BLOCK_HASH};
use lighthouse_network::{prometheus_client::registry::Registry, NetworkGlobals};
use monitoring_api::{MonitoringHttpClient, ProcessType};
use network::{NetworkConfig, NetworkMessage, NetworkService};
use slasher::Slasher;
use slasher_service::SlasherService;
use slog::{debug, info, warn, Logger};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use timer::spawn_timer;
use tokio::sync::{mpsc::UnboundedSender, oneshot};
use types::{
    test_utils::generate_deterministic_keypairs, BeaconState, ChainSpec, EthSpec,
    ExecutionBlockHash, Hash256, SignedBeaconBlock,
};

/// Interval between polling the eth1 node for genesis information.
pub const ETH1_GENESIS_UPDATE_INTERVAL_MILLIS: u64 = 7_000;

/// Timeout for checkpoint sync HTTP requests.
pub const CHECKPOINT_SYNC_HTTP_TIMEOUT: Duration = Duration::from_secs(60);

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
    chain_spec: Option<ChainSpec>,
    beacon_chain_builder: Option<BeaconChainBuilder<T>>,
    beacon_chain: Option<Arc<BeaconChain<T>>>,
    eth1_service: Option<Eth1Service>,
    network_globals: Option<Arc<NetworkGlobals<T::EthSpec>>>,
    network_send: Option<UnboundedSender<NetworkMessage<T::EthSpec>>>,
    gossipsub_registry: Option<Registry>,
    db_path: Option<PathBuf>,
    freezer_db_path: Option<PathBuf>,
    http_api_config: http_api::Config,
    http_metrics_config: http_metrics::Config,
    slasher: Option<Arc<Slasher<T::EthSpec>>>,
    eth_spec_instance: T::EthSpec,
}

impl<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>
    ClientBuilder<Witness<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>>
where
    TSlotClock: SlotClock + Clone + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
{
    /// Instantiates a new, empty builder.
    ///
    /// The `eth_spec_instance` parameter is used to concretize `TEthSpec`.
    pub fn new(eth_spec_instance: TEthSpec) -> Self {
        Self {
            slot_clock: None,
            store: None,
            runtime_context: None,
            chain_spec: None,
            beacon_chain_builder: None,
            beacon_chain: None,
            eth1_service: None,
            network_globals: None,
            network_send: None,
            gossipsub_registry: None,
            db_path: None,
            freezer_db_path: None,
            http_api_config: <_>::default(),
            http_metrics_config: <_>::default(),
            slasher: None,
            eth_spec_instance,
        }
    }

    /// Specifies the runtime context (tokio executor, logger, etc) for client services.
    pub fn runtime_context(mut self, context: RuntimeContext<TEthSpec>) -> Self {
        self.runtime_context = Some(context);
        self
    }

    /// Specifies the `ChainSpec`.
    pub fn chain_spec(mut self, spec: ChainSpec) -> Self {
        self.chain_spec = Some(spec);
        self
    }

    pub fn slasher(mut self, slasher: Arc<Slasher<TEthSpec>>) -> Self {
        self.slasher = Some(slasher);
        self
    }

    /// Initializes the `BeaconChainBuilder`. The `build_beacon_chain` method will need to be
    /// called later in order to actually instantiate the `BeaconChain`.
    pub async fn beacon_chain_builder(
        mut self,
        client_genesis: ClientGenesis,
        config: ClientConfig,
    ) -> Result<Self, String> {
        let store = self.store.clone();
        let chain_spec = self.chain_spec.clone();
        let runtime_context = self.runtime_context.clone();
        let eth_spec_instance = self.eth_spec_instance.clone();
        let chain_config = config.chain.clone();
        let graffiti = config.graffiti;

        let store = store.ok_or("beacon_chain_start_method requires a store")?;
        let runtime_context =
            runtime_context.ok_or("beacon_chain_start_method requires a runtime context")?;
        let context = runtime_context.service_context("beacon".into());
        let spec = chain_spec.ok_or("beacon_chain_start_method requires a chain spec")?;
        let event_handler = if self.http_api_config.enabled {
            Some(ServerSentEventHandler::new(context.log().clone()))
        } else {
            None
        };

        let execution_layer = if let Some(config) = config.execution_layer {
            let context = runtime_context.service_context("exec".into());
            let execution_layer = ExecutionLayer::from_config(
                config,
                context.executor.clone(),
                context.log().clone(),
            )
            .map_err(|e| format!("unable to start execution layer endpoints: {:?}", e))?;
            Some(execution_layer)
        } else {
            None
        };

        let builder = BeaconChainBuilder::new(eth_spec_instance)
            .logger(context.log().clone())
            .store(store)
            .task_executor(context.executor.clone())
            .custom_spec(spec.clone())
            .chain_config(chain_config)
            .graffiti(graffiti)
            .event_handler(event_handler)
            .execution_layer(execution_layer)
            .monitor_validators(
                config.validator_monitor_auto,
                config.validator_monitor_pubkeys.clone(),
                runtime_context
                    .service_context("val_mon".to_string())
                    .log()
                    .clone(),
            );

        let builder = if let Some(slasher) = self.slasher.clone() {
            builder.slasher(slasher)
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
            info!(context.log(), "Defaulting to deposit contract genesis");

            ClientGenesis::DepositContract
        } else if chain_exists {
            if matches!(client_genesis, ClientGenesis::WeakSubjSszBytes { .. })
                || matches!(client_genesis, ClientGenesis::CheckpointSyncUrl { .. })
            {
                info!(
                    context.log(),
                    "Refusing to checkpoint sync";
                    "msg" => "database already exists, use --purge-db to force checkpoint sync"
                );
            }

            ClientGenesis::FromStore
        } else {
            client_genesis
        };

        let (beacon_chain_builder, eth1_service_option) = match client_genesis {
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
                builder.genesis_state(genesis_state).map(|v| (v, None))?
            }
            ClientGenesis::SszBytes {
                genesis_state_bytes,
            } => {
                info!(
                    context.log(),
                    "Starting from known genesis state";
                );

                let genesis_state = BeaconState::from_ssz_bytes(&genesis_state_bytes, &spec)
                    .map_err(|e| format!("Unable to parse genesis state SSZ: {:?}", e))?;

                builder.genesis_state(genesis_state).map(|v| (v, None))?
            }
            ClientGenesis::WeakSubjSszBytes {
                anchor_state_bytes,
                anchor_block_bytes,
                genesis_state_bytes,
            } => {
                info!(context.log(), "Starting checkpoint sync");

                let anchor_state = BeaconState::from_ssz_bytes(&anchor_state_bytes, &spec)
                    .map_err(|e| format!("Unable to parse weak subj state SSZ: {:?}", e))?;
                let anchor_block = SignedBeaconBlock::from_ssz_bytes(&anchor_block_bytes, &spec)
                    .map_err(|e| format!("Unable to parse weak subj block SSZ: {:?}", e))?;
                let genesis_state = BeaconState::from_ssz_bytes(&genesis_state_bytes, &spec)
                    .map_err(|e| format!("Unable to parse genesis state SSZ: {:?}", e))?;

                builder
                    .weak_subjectivity_state(anchor_state, anchor_block, genesis_state)
                    .map(|v| (v, None))?
            }
            ClientGenesis::CheckpointSyncUrl {
                genesis_state_bytes,
                url,
            } => {
                info!(
                    context.log(),
                    "Starting checkpoint sync";
                    "remote_url" => %url,
                );

                let remote =
                    BeaconNodeHttpClient::new(url, Timeouts::set_all(CHECKPOINT_SYNC_HTTP_TIMEOUT));
                let slots_per_epoch = TEthSpec::slots_per_epoch();

                debug!(context.log(), "Downloading finalized block");

                // Find a suitable finalized block on an epoch boundary.
                let mut block = remote
                    .get_beacon_blocks_ssz::<TEthSpec>(BlockId::Finalized, &spec)
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

                debug!(context.log(), "Downloaded finalized block");

                let mut block_slot = block.slot();

                while block.slot() % slots_per_epoch != 0 {
                    block_slot = (block_slot / slots_per_epoch - 1) * slots_per_epoch;

                    debug!(
                        context.log(),
                        "Searching for aligned checkpoint block";
                        "block_slot" => block_slot,
                    );

                    debug!(
                        context.log(),
                        "Searching for aligned checkpoint block";
                        "block_slot" => block_slot
                    );

                    if let Some(found_block) = remote
                        .get_beacon_blocks_ssz::<TEthSpec>(BlockId::Slot(block_slot), &spec)
                        .await
                        .map_err(|e| {
                            format!("Error fetching block at slot {}: {:?}", block_slot, e)
                        })?
                    {
                        block = found_block;
                    }
                }

                debug!(
                    context.log(),
                    "Downloaded aligned finalized block";
                    "block_root" => ?block.canonical_root(),
                    "block_slot" => block.slot(),
                );

                let state_root = block.state_root();
                debug!(
                    context.log(),
                    "Downloading finalized state";
                    "state_root" => ?state_root
                );
                let state = remote
                    .get_debug_beacon_states_ssz::<TEthSpec>(StateId::Root(state_root), &spec)
                    .await
                    .map_err(|e| {
                        format!(
                            "Error loading checkpoint state from remote {:?}: {:?}",
                            state_root, e
                        )
                    })?
                    .ok_or_else(|| {
                        format!("Checkpoint state missing from remote: {:?}", state_root)
                    })?;

                debug!(context.log(), "Downloaded finalized state");

                let genesis_state = BeaconState::from_ssz_bytes(&genesis_state_bytes, &spec)
                    .map_err(|e| format!("Unable to parse genesis state SSZ: {:?}", e))?;

                info!(
                    context.log(),
                    "Loaded checkpoint block and state";
                    "slot" => block.slot(),
                    "block_root" => ?block.canonical_root(),
                    "state_root" => ?state_root,
                );

                builder
                    .weak_subjectivity_state(state, block, genesis_state)
                    .map(|v| (v, None))?
            }
            ClientGenesis::DepositContract => {
                info!(
                    context.log(),
                    "Waiting for eth2 genesis from eth1";
                    "eth1_endpoints" => format!("{:?}", &config.eth1.endpoints),
                    "contract_deploy_block" => config.eth1.deposit_contract_deploy_block,
                    "deposit_contract" => &config.eth1.deposit_contract_address
                );

                let genesis_service = Eth1GenesisService::new(
                    config.eth1,
                    context.log().clone(),
                    context.eth2_config().spec.clone(),
                );

                // If the HTTP API server is enabled, start an instance of it where it only
                // contains a reference to the eth1 service (all non-eth1 endpoints will fail
                // gracefully).
                //
                // Later in this function we will shutdown this temporary "waiting for genesis"
                // server so the real one can be started later.
                let (exit_tx, exit_rx) = oneshot::channel::<()>();
                let http_listen_opt = if self.http_api_config.enabled {
                    #[allow(clippy::type_complexity)]
                    let ctx: Arc<
                        http_api::Context<
                            Witness<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>,
                        >,
                    > = Arc::new(http_api::Context {
                        config: self.http_api_config.clone(),
                        chain: None,
                        network_tx: None,
                        network_globals: None,
                        eth1_service: Some(genesis_service.eth1_service.clone()),
                        log: context.log().clone(),
                    });

                    // Discard the error from the oneshot.
                    let exit_future = async {
                        let _ = exit_rx.await;
                    };

                    let (listen_addr, server) = http_api::serve(ctx, exit_future)
                        .map_err(|e| format!("Unable to start HTTP API server: {:?}", e))?;

                    let log_clone = context.log().clone();
                    let http_api_task = async move {
                        server.await;
                        debug!(log_clone, "HTTP API server task ended");
                    };

                    context
                        .clone()
                        .executor
                        .spawn_without_exit(http_api_task, "http-api");

                    Some(listen_addr)
                } else {
                    None
                };

                let genesis_state = genesis_service
                    .wait_for_genesis_state(
                        Duration::from_millis(ETH1_GENESIS_UPDATE_INTERVAL_MILLIS),
                        context.eth2_config().spec.clone(),
                    )
                    .await?;

                let _ = exit_tx.send(());

                if let Some(http_listen) = http_listen_opt {
                    // This is a bit of a hack to ensure that the HTTP server has indeed shutdown.
                    //
                    // We will restart it again after we've finished setting up for genesis.
                    while TcpListener::bind(http_listen).is_err() {
                        warn!(
                            context.log(),
                            "Waiting for HTTP server port to open";
                            "port" => http_listen
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }

                builder
                    .genesis_state(genesis_state)
                    .map(|v| (v, Some(genesis_service.into_core_service())))?
            }
            ClientGenesis::FromStore => builder.resume_from_db().map(|v| (v, None))?,
        };

        self.eth1_service = eth1_service_option;
        self.beacon_chain_builder = Some(beacon_chain_builder);
        Ok(self)
    }

    /// Starts the networking stack.
    pub async fn network(mut self, config: &NetworkConfig) -> Result<Self, String> {
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or("network requires a beacon chain")?;
        let context = self
            .runtime_context
            .as_ref()
            .ok_or("network requires a runtime_context")?
            .clone();

        // If gossipsub metrics are required we build a registry to record them
        let mut gossipsub_registry = if config.metrics_enabled {
            Some(Registry::default())
        } else {
            None
        };

        let (network_globals, network_send) = NetworkService::start(
            beacon_chain,
            config,
            context.executor,
            gossipsub_registry
                .as_mut()
                .map(|registry| registry.sub_registry_with_prefix("gossipsub")),
        )
        .await
        .map_err(|e| format!("Failed to start network: {:?}", e))?;

        self.network_globals = Some(network_globals);
        self.network_send = Some(network_send);
        self.gossipsub_registry = gossipsub_registry;

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
        let network_send = self
            .network_send
            .clone()
            .ok_or("slasher service requires a network sender")?;
        let context = self
            .runtime_context
            .as_ref()
            .ok_or("slasher requires a runtime_context")?
            .service_context("slasher_service_ctxt".into());
        SlasherService::new(beacon_chain, network_send).run(&context.executor)
    }

    /// Start the explorer client which periodically sends beacon
    /// and system metrics to the configured endpoint.
    pub fn monitoring_client(self, config: &monitoring_api::Config) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or("monitoring_client requires a runtime_context")?
            .service_context("monitoring_client".into());
        let monitoring_client = MonitoringHttpClient::new(config, context.log().clone())?;
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
    ) -> Result<Client<Witness<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>>, String>
    {
        let runtime_context = self
            .runtime_context
            .as_ref()
            .ok_or("build requires a runtime context")?;
        let log = runtime_context.log().clone();

        let http_api_listen_addr = if self.http_api_config.enabled {
            let ctx = Arc::new(http_api::Context {
                config: self.http_api_config.clone(),
                chain: self.beacon_chain.clone(),
                network_tx: self.network_send.clone(),
                network_globals: self.network_globals.clone(),
                eth1_service: self.eth1_service.clone(),
                log: log.clone(),
            });

            let exit = runtime_context.executor.exit();

            let (listen_addr, server) = http_api::serve(ctx, exit)
                .map_err(|e| format!("Unable to start HTTP API server: {:?}", e))?;

            let http_log = runtime_context.log().clone();
            let http_api_task = async move {
                server.await;
                debug!(http_log, "HTTP API server task ended");
            };

            runtime_context
                .clone()
                .executor
                .spawn_without_exit(http_api_task, "http-api");

            Some(listen_addr)
        } else {
            info!(log, "HTTP server is disabled");
            None
        };

        let http_metrics_listen_addr = if self.http_metrics_config.enabled {
            let ctx = Arc::new(http_metrics::Context {
                config: self.http_metrics_config.clone(),
                chain: self.beacon_chain.clone(),
                db_path: self.db_path.clone(),
                freezer_db_path: self.freezer_db_path.clone(),
                gossipsub_registry: self.gossipsub_registry.take().map(std::sync::Mutex::new),
                log: log.clone(),
            });

            let exit = runtime_context.executor.exit();

            let (listen_addr, server) = http_metrics::serve(ctx, exit)
                .map_err(|e| format!("Unable to start HTTP metrics server: {:?}", e))?;

            runtime_context
                .executor
                .spawn_without_exit(async move { server.await }, "http-metrics");

            Some(listen_addr)
        } else {
            debug!(log, "Metrics server is disabled");
            None
        };

        if self.slasher.is_some() {
            self.start_slasher_service()?;
        }

        if let Some(beacon_chain) = self.beacon_chain.as_ref() {
            let state_advance_context = runtime_context.service_context("state_advance".into());
            let state_advance_log = state_advance_context.log().clone();
            spawn_state_advance_timer(
                state_advance_context.executor,
                beacon_chain.clone(),
                state_advance_log,
            );

            if let Some(execution_layer) = beacon_chain.execution_layer.as_ref() {
                // Only send a head update *after* genesis.
                if let Ok(current_slot) = beacon_chain.slot() {
                    let params = beacon_chain
                        .canonical_head
                        .cached_head()
                        .forkchoice_update_parameters();
                    if params
                        .head_hash
                        .map_or(false, |hash| hash != ExecutionBlockHash::zero())
                    {
                        // Spawn a new task to update the EE without waiting for it to complete.
                        let inner_chain = beacon_chain.clone();
                        runtime_context.executor.spawn(
                            async move {
                                let result = inner_chain
                                    .update_execution_engine_forkchoice(current_slot, params)
                                    .await;

                                // No need to exit early if setting the head fails. It will be set again if/when the
                                // node comes online.
                                if let Err(e) = result {
                                    warn!(
                                        log,
                                        "Failed to update head on execution engines";
                                        "error" => ?e
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

                    // Spawns a routine that polls the `exchange_transition_configuration` endpoint.
                    execution_layer.spawn_transition_configuration_poll(beacon_chain.spec.clone());
                }
            }

            start_proposer_prep_service(runtime_context.executor.clone(), beacon_chain.clone());
        }

        Ok(Client {
            beacon_chain: self.beacon_chain,
            network_globals: self.network_globals,
            http_api_listen_addr,
            http_metrics_listen_addr,
        })
    }
}

impl<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>
    ClientBuilder<Witness<TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>>
where
    TSlotClock: SlotClock + Clone + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
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

impl<TSlotClock, TEth1Backend, TEthSpec>
    ClientBuilder<Witness<TSlotClock, TEth1Backend, TEthSpec, LevelDB<TEthSpec>, LevelDB<TEthSpec>>>
where
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
{
    /// Specifies that the `Client` should use a `HotColdDB` database.
    pub fn disk_store(
        mut self,
        datadir: &Path,
        hot_path: &Path,
        cold_path: &Path,
        config: StoreConfig,
        log: Logger,
    ) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or("disk_store requires a log")?
            .service_context("freezer_db".into());
        let spec = self
            .chain_spec
            .clone()
            .ok_or("disk_store requires a chain spec")?;

        self.db_path = Some(hot_path.into());
        self.freezer_db_path = Some(cold_path.into());

        let inner_spec = spec.clone();
        let schema_upgrade = |db, from, to| {
            migrate_schema::<Witness<TSlotClock, TEth1Backend, _, _, _>>(
                db,
                datadir,
                from,
                to,
                log,
                &inner_spec,
            )
        };

        let store = HotColdDB::open(
            hot_path,
            cold_path,
            schema_upgrade,
            config,
            spec,
            context.log().clone(),
        )
        .map_err(|e| format!("Unable to open database: {:?}", e))?;
        self.store = Some(store);
        Ok(self)
    }
}

impl<TSlotClock, TEthSpec, THotStore, TColdStore>
    ClientBuilder<
        Witness<TSlotClock, CachingEth1Backend<TEthSpec>, TEthSpec, THotStore, TColdStore>,
    >
where
    TSlotClock: SlotClock + 'static,
    TEthSpec: EthSpec + 'static,
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
{
    /// Specifies that the `BeaconChain` should cache eth1 blocks/logs from a remote eth1 node
    /// (e.g., Parity/Geth) and refer to that cache when collecting deposits or eth1 votes during
    /// block production.
    pub async fn caching_eth1_backend(mut self, config: Eth1Config) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or("caching_eth1_backend requires a runtime_context")?
            .service_context("eth1_rpc".into());
        let beacon_chain_builder = self
            .beacon_chain_builder
            .ok_or("caching_eth1_backend requires a beacon_chain_builder")?;
        let spec = self
            .chain_spec
            .clone()
            .ok_or("caching_eth1_backend requires a chain spec")?;

        let backend = if let Some(eth1_service_from_genesis) = self.eth1_service {
            eth1_service_from_genesis.update_config(config)?;

            // This cache is not useful because it's first (earliest) block likely the block that
            // triggered genesis.
            //
            // In order to vote we need to be able to go back at least 2 * `ETH1_FOLLOW_DISTANCE`
            // from the genesis-triggering block.  Presently the block cache does not support
            // importing blocks with decreasing block numbers, it only accepts them in increasing
            // order. If this turns out to be a bottleneck we can update the block cache to allow
            // adding earlier blocks too.
            eth1_service_from_genesis.drop_block_cache();

            CachingEth1Backend::from_service(eth1_service_from_genesis)
        } else if config.purge_cache {
            CachingEth1Backend::new(config, context.log().clone(), spec)
        } else {
            beacon_chain_builder
                .get_persisted_eth1_backend()?
                .map(|persisted| {
                    Eth1Chain::from_ssz_container(
                        &persisted,
                        config.clone(),
                        &context.log().clone(),
                        spec.clone(),
                    )
                    .map(|chain| chain.into_backend())
                })
                .unwrap_or_else(|| {
                    Ok(CachingEth1Backend::new(
                        config,
                        context.log().clone(),
                        spec.clone(),
                    ))
                })?
        };

        self.eth1_service = Some(backend.core.clone());

        // Starts the service that connects to an eth1 node and periodically updates caches.
        backend.start(context.executor);

        self.beacon_chain_builder = Some(beacon_chain_builder.eth1_backend(Some(backend)));

        Ok(self)
    }

    /// Do not use any eth1 backend. The client will not be able to produce beacon blocks.
    pub fn no_eth1_backend(mut self) -> Result<Self, String> {
        let beacon_chain_builder = self
            .beacon_chain_builder
            .ok_or("caching_eth1_backend requires a beacon_chain_builder")?;

        self.beacon_chain_builder = Some(beacon_chain_builder.no_eth1_backend());

        Ok(self)
    }

    /// Use an eth1 backend that can produce blocks but is not connected to an Eth1 node.
    ///
    /// This backend will never produce deposits so it's impossible to add validators after
    /// genesis. The `Eth1Data` votes will be deterministic junk data.
    ///
    /// ## Notes
    ///
    /// The client is given the `CachingEth1Backend` type, but the http backend is never started and the
    /// caches are never used.
    pub fn dummy_eth1_backend(mut self) -> Result<Self, String> {
        let beacon_chain_builder = self
            .beacon_chain_builder
            .ok_or("caching_eth1_backend requires a beacon_chain_builder")?;

        self.beacon_chain_builder = Some(beacon_chain_builder.dummy_eth1_backend()?);

        Ok(self)
    }
}

impl<TEth1Backend, TEthSpec, THotStore, TColdStore>
    ClientBuilder<Witness<SystemTimeSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>>
where
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
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
