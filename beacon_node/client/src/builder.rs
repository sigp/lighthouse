use crate::config::{ClientGenesis, Config as ClientConfig};
use crate::notifier::spawn_notifier;
use crate::Client;
use beacon_chain::events::TeeEventHandler;
use beacon_chain::{
    builder::{BeaconChainBuilder, Witness},
    eth1_chain::{CachingEth1Backend, Eth1Chain},
    migrate::{BackgroundMigrator, Migrate},
    slot_clock::{SlotClock, SystemTimeSlotClock},
    store::{HotColdDB, ItemStore, LevelDB, StoreConfig},
    BeaconChain, BeaconChainTypes, Eth1ChainBackend, EventHandler,
};
use bus::Bus;
use environment::RuntimeContext;
use eth1::{Config as Eth1Config, Service as Eth1Service};
use eth2_config::Eth2Config;
use eth2_libp2p::NetworkGlobals;
use genesis::{interop_genesis_state, Eth1GenesisService};
use network::{NetworkConfig, NetworkMessage, NetworkService};
use parking_lot::Mutex;
use slog::info;
use ssz::Decode;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use timer::spawn_timer;
use tokio::sync::mpsc::UnboundedSender;
use types::{
    test_utils::generate_deterministic_keypairs, BeaconState, ChainSpec, EthSpec,
    SignedBeaconBlockHash,
};
use websocket_server::{Config as WebSocketConfig, WebSocketSender};

/// Interval between polling the eth1 node for genesis information.
pub const ETH1_GENESIS_UPDATE_INTERVAL_MILLIS: u64 = 7_000;

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
    store_migrator: Option<T::StoreMigrator>,
    runtime_context: Option<RuntimeContext<T::EthSpec>>,
    chain_spec: Option<ChainSpec>,
    beacon_chain_builder: Option<BeaconChainBuilder<T>>,
    beacon_chain: Option<Arc<BeaconChain<T>>>,
    eth1_service: Option<Eth1Service>,
    event_handler: Option<T::EventHandler>,
    network_globals: Option<Arc<NetworkGlobals<T::EthSpec>>>,
    network_send: Option<UnboundedSender<NetworkMessage<T::EthSpec>>>,
    http_listen_addr: Option<SocketAddr>,
    websocket_listen_addr: Option<SocketAddr>,
    eth_spec_instance: T::EthSpec,
}

impl<TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler, THotStore, TColdStore>
    ClientBuilder<
        Witness<
            TStoreMigrator,
            TSlotClock,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
            THotStore,
            TColdStore,
        >,
    >
where
    TStoreMigrator: Migrate<TEthSpec, THotStore, TColdStore>,
    TSlotClock: SlotClock + Clone + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
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
            store_migrator: None,
            runtime_context: None,
            chain_spec: None,
            beacon_chain_builder: None,
            beacon_chain: None,
            eth1_service: None,
            event_handler: None,
            network_globals: None,
            network_send: None,
            http_listen_addr: None,
            websocket_listen_addr: None,
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

    /// Initializes the `BeaconChainBuilder`. The `build_beacon_chain` method will need to be
    /// called later in order to actually instantiate the `BeaconChain`.
    pub async fn beacon_chain_builder(
        mut self,
        client_genesis: ClientGenesis,
        config: ClientConfig,
    ) -> Result<Self, String> {
        let store = self.store.clone();
        let store_migrator = self.store_migrator.take();
        let chain_spec = self.chain_spec.clone();
        let runtime_context = self.runtime_context.clone();
        let eth_spec_instance = self.eth_spec_instance.clone();
        let data_dir = config.data_dir.clone();
        let disabled_forks = config.disabled_forks.clone();
        let chain_config = config.chain.clone();
        let graffiti = config.graffiti;

        let store =
            store.ok_or_else(|| "beacon_chain_start_method requires a store".to_string())?;
        let store_migrator = store_migrator
            .ok_or_else(|| "beacon_chain_start_method requires a store migrator".to_string())?;
        let context = runtime_context
            .ok_or_else(|| "beacon_chain_start_method requires a runtime context".to_string())?
            .service_context("beacon".into());
        let spec = chain_spec
            .ok_or_else(|| "beacon_chain_start_method requires a chain spec".to_string())?;

        let builder = BeaconChainBuilder::new(eth_spec_instance)
            .logger(context.log().clone())
            .store(store)
            .store_migrator(store_migrator)
            .data_dir(data_dir)
            .custom_spec(spec.clone())
            .chain_config(chain_config)
            .disabled_forks(disabled_forks)
            .graffiti(graffiti);

        let chain_exists = builder
            .store_contains_beacon_chain()
            .unwrap_or_else(|_| false);

        // If the client is expect to resume but there's no beacon chain in the database,
        // use the `DepositContract` method. This scenario is quite common when the client
        // is shutdown before finding genesis via eth1.
        //
        // Alternatively, if there's a beacon chain in the database then always resume
        // using it.
        let client_genesis = if client_genesis == ClientGenesis::FromStore && !chain_exists {
            info!(context.log(), "Defaulting to deposit contract genesis");

            ClientGenesis::DepositContract
        } else if chain_exists {
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
                let genesis_state = interop_genesis_state(&keypairs, genesis_time, &spec)?;
                builder.genesis_state(genesis_state).map(|v| (v, None))?
            }
            ClientGenesis::SszBytes {
                genesis_state_bytes,
            } => {
                info!(
                    context.log(),
                    "Starting from known genesis state";
                );

                let genesis_state = BeaconState::from_ssz_bytes(&genesis_state_bytes)
                    .map_err(|e| format!("Unable to parse genesis state SSZ: {:?}", e))?;

                builder.genesis_state(genesis_state).map(|v| (v, None))?
            }
            ClientGenesis::DepositContract => {
                info!(
                    context.log(),
                    "Waiting for eth2 genesis from eth1";
                    "eth1_endpoint" => &config.eth1.endpoint,
                    "contract_deploy_block" => config.eth1.deposit_contract_deploy_block,
                    "deposit_contract" => &config.eth1.deposit_contract_address
                );

                let genesis_service = Eth1GenesisService::new(
                    config.eth1,
                    context.log().clone(),
                    context.eth2_config().spec.clone(),
                );

                let genesis_state = genesis_service
                    .wait_for_genesis_state(
                        Duration::from_millis(ETH1_GENESIS_UPDATE_INTERVAL_MILLIS),
                        context.eth2_config().spec.clone(),
                    )
                    .await?;

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
            .ok_or_else(|| "network requires a beacon chain")?;
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "network requires a runtime_context")?
            .clone();

        let (network_globals, network_send) =
            NetworkService::start(beacon_chain, config, context.executor)
                .await
                .map_err(|e| format!("Failed to start network: {:?}", e))?;

        self.network_globals = Some(network_globals);
        self.network_send = Some(network_send);

        Ok(self)
    }

    /// Immediately starts the timer service.
    fn timer(self) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "node timer requires a runtime_context")?
            .service_context("node_timer".into());
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or_else(|| "node timer requires a beacon chain")?;
        let milliseconds_per_slot = self
            .chain_spec
            .as_ref()
            .ok_or_else(|| "node timer requires a chain spec".to_string())?
            .milliseconds_per_slot;

        spawn_timer(context.executor, beacon_chain, milliseconds_per_slot)
            .map_err(|e| format!("Unable to start node timer: {}", e))?;

        Ok(self)
    }

    /// Immediately starts the beacon node REST API http server.
    pub fn http_server(
        mut self,
        client_config: &ClientConfig,
        eth2_config: &Eth2Config,
        events: Arc<Mutex<Bus<SignedBeaconBlockHash>>>,
    ) -> Result<Self, String> {
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or_else(|| "http_server requires a beacon chain")?;
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "http_server requires a runtime_context")?
            .service_context("http".into());
        let network_globals = self
            .network_globals
            .clone()
            .ok_or_else(|| "http_server requires a libp2p network")?;
        let network_send = self
            .network_send
            .clone()
            .ok_or_else(|| "http_server requires a libp2p network sender")?;

        let network_info = rest_api::NetworkInfo {
            network_globals,
            network_chan: network_send,
        };

        let listening_addr = rest_api::start_server(
            context.executor,
            &client_config.rest_api,
            beacon_chain,
            network_info,
            client_config
                .create_db_path()
                .map_err(|_| "unable to read data dir")?,
            client_config
                .create_freezer_db_path()
                .map_err(|_| "unable to read freezer DB dir")?,
            eth2_config.clone(),
            events,
        )
        .map_err(|e| format!("Failed to start HTTP API: {:?}", e))?;

        self.http_listen_addr = Some(listening_addr);

        Ok(self)
    }

    /// Immediately starts the service that periodically logs information each slot.
    pub fn notifier(self) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "slot_notifier requires a runtime_context")?
            .service_context("slot_notifier".into());
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or_else(|| "slot_notifier requires a beacon chain")?;
        let network_globals = self
            .network_globals
            .clone()
            .ok_or_else(|| "slot_notifier requires a libp2p network")?;
        let milliseconds_per_slot = self
            .chain_spec
            .as_ref()
            .ok_or_else(|| "slot_notifier requires a chain spec".to_string())?
            .milliseconds_per_slot;

        spawn_notifier(
            context.executor,
            beacon_chain,
            network_globals,
            milliseconds_per_slot,
        )
        .map_err(|e| format!("Unable to start slot notifier: {}", e))?;

        Ok(self)
    }

    /// Consumers the builder, returning a `Client` if all necessary components have been
    /// specified.
    ///
    /// If type inference errors are being raised, see the comment on the definition of `Self`.
    pub fn build(
        self,
    ) -> Client<
        Witness<
            TStoreMigrator,
            TSlotClock,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
            THotStore,
            TColdStore,
        >,
    > {
        Client {
            beacon_chain: self.beacon_chain,
            network_globals: self.network_globals,
            http_listen_addr: self.http_listen_addr,
            websocket_listen_addr: self.websocket_listen_addr,
        }
    }
}

impl<TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler, THotStore, TColdStore>
    ClientBuilder<
        Witness<
            TStoreMigrator,
            TSlotClock,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
            THotStore,
            TColdStore,
        >,
    >
where
    TStoreMigrator: Migrate<TEthSpec, THotStore, TColdStore>,
    TSlotClock: SlotClock + Clone + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
{
    /// Consumes the internal `BeaconChainBuilder`, attaching the resulting `BeaconChain` to self.
    pub fn build_beacon_chain(mut self) -> Result<Self, String> {
        let chain = self
            .beacon_chain_builder
            .ok_or_else(|| "beacon_chain requires a beacon_chain_builder")?
            .event_handler(
                self.event_handler
                    .ok_or_else(|| "beacon_chain requires an event handler")?,
            )
            .slot_clock(
                self.slot_clock
                    .clone()
                    .ok_or_else(|| "beacon_chain requires a slot clock")?,
            )
            .build()
            .map_err(|e| format!("Failed to build beacon chain: {}", e))?;

        self.beacon_chain = Some(Arc::new(chain));
        self.beacon_chain_builder = None;
        self.event_handler = None;

        // a beacon chain requires a timer
        self.timer()
    }
}

impl<TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, THotStore, TColdStore>
    ClientBuilder<
        Witness<
            TStoreMigrator,
            TSlotClock,
            TEth1Backend,
            TEthSpec,
            TeeEventHandler<TEthSpec>,
            THotStore,
            TColdStore,
        >,
    >
where
    TStoreMigrator: Migrate<TEthSpec, THotStore, TColdStore>,
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
{
    #[allow(clippy::type_complexity)]
    /// Specifies that the `BeaconChain` should publish events using the WebSocket server.
    pub fn tee_event_handler(
        mut self,
        config: WebSocketConfig,
    ) -> Result<(Self, Arc<Mutex<Bus<SignedBeaconBlockHash>>>), String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "tee_event_handler requires a runtime_context")?
            .service_context("ws".into());

        let log = context.log().clone();
        let (sender, listening_addr): (WebSocketSender<TEthSpec>, Option<_>) = if config.enabled {
            let (sender, listening_addr) =
                websocket_server::start_server(context.executor, &config)?;
            (sender, Some(listening_addr))
        } else {
            (WebSocketSender::dummy(), None)
        };

        self.websocket_listen_addr = listening_addr;
        let (tee_event_handler, bus) = TeeEventHandler::new(log, sender)?;
        self.event_handler = Some(tee_event_handler);
        Ok((self, bus))
    }
}

impl<TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<
            TStoreMigrator,
            TSlotClock,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
            LevelDB<TEthSpec>,
            LevelDB<TEthSpec>,
        >,
    >
where
    TSlotClock: SlotClock + 'static,
    TStoreMigrator: Migrate<TEthSpec, LevelDB<TEthSpec>, LevelDB<TEthSpec>> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Specifies that the `Client` should use a `HotColdDB` database.
    pub fn disk_store(
        mut self,
        hot_path: &Path,
        cold_path: &Path,
        config: StoreConfig,
    ) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "disk_store requires a log".to_string())?
            .service_context("freezer_db".into());
        let spec = self
            .chain_spec
            .clone()
            .ok_or_else(|| "disk_store requires a chain spec".to_string())?;

        let store = HotColdDB::open(hot_path, cold_path, config, spec, context.log().clone())
            .map_err(|e| format!("Unable to open database: {:?}", e))?;
        self.store = Some(Arc::new(store));
        Ok(self)
    }
}

impl<TSlotClock, TEth1Backend, TEthSpec, TEventHandler, THotStore, TColdStore>
    ClientBuilder<
        Witness<
            BackgroundMigrator<TEthSpec, THotStore, TColdStore>,
            TSlotClock,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
            THotStore,
            TColdStore,
        >,
    >
where
    TSlotClock: SlotClock + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
{
    pub fn background_migrator(mut self) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "disk_store requires a log".to_string())?
            .service_context("freezer_db".into());
        let store = self.store.clone().ok_or_else(|| {
            "background_migrator requires the store to be initialized".to_string()
        })?;
        self.store_migrator = Some(BackgroundMigrator::new(store, context.log().clone()));
        Ok(self)
    }
}

impl<TStoreMigrator, TSlotClock, TEthSpec, TEventHandler, THotStore, TColdStore>
    ClientBuilder<
        Witness<
            TStoreMigrator,
            TSlotClock,
            CachingEth1Backend<TEthSpec>,
            TEthSpec,
            TEventHandler,
            THotStore,
            TColdStore,
        >,
    >
where
    TStoreMigrator: Migrate<TEthSpec, THotStore, TColdStore>,
    TSlotClock: SlotClock + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
{
    /// Specifies that the `BeaconChain` should cache eth1 blocks/logs from a remote eth1 node
    /// (e.g., Parity/Geth) and refer to that cache when collecting deposits or eth1 votes during
    /// block production.
    pub fn caching_eth1_backend(mut self, config: Eth1Config) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "caching_eth1_backend requires a runtime_context")?
            .service_context("eth1_rpc".into());
        let beacon_chain_builder = self
            .beacon_chain_builder
            .ok_or_else(|| "caching_eth1_backend requires a beacon_chain_builder")?;
        let spec = self
            .chain_spec
            .clone()
            .ok_or_else(|| "caching_eth1_backend requires a chain spec".to_string())?;

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

        self.eth1_service = None;

        // Starts the service that connects to an eth1 node and periodically updates caches.
        backend.start(context.executor);

        self.beacon_chain_builder = Some(beacon_chain_builder.eth1_backend(Some(backend)));

        Ok(self)
    }

    /// Do not use any eth1 backend. The client will not be able to produce beacon blocks.
    pub fn no_eth1_backend(mut self) -> Result<Self, String> {
        let beacon_chain_builder = self
            .beacon_chain_builder
            .ok_or_else(|| "caching_eth1_backend requires a beacon_chain_builder")?;

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
            .ok_or_else(|| "caching_eth1_backend requires a beacon_chain_builder")?;

        self.beacon_chain_builder = Some(beacon_chain_builder.dummy_eth1_backend()?);

        Ok(self)
    }
}

impl<TStoreMigrator, TEth1Backend, TEthSpec, TEventHandler, THotStore, TColdStore>
    ClientBuilder<
        Witness<
            TStoreMigrator,
            SystemTimeSlotClock,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
            THotStore,
            TColdStore,
        >,
    >
where
    TStoreMigrator: Migrate<TEthSpec, THotStore, TColdStore>,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
    THotStore: ItemStore<TEthSpec> + 'static,
    TColdStore: ItemStore<TEthSpec> + 'static,
{
    /// Specifies that the slot clock should read the time from the computers system clock.
    pub fn system_time_slot_clock(mut self) -> Result<Self, String> {
        let beacon_chain_builder = self
            .beacon_chain_builder
            .as_ref()
            .ok_or_else(|| "system_time_slot_clock requires a beacon_chain_builder")?;

        let genesis_time = beacon_chain_builder
            .finalized_snapshot
            .as_ref()
            .ok_or_else(|| "system_time_slot_clock requires an initialized beacon state")?
            .beacon_state
            .genesis_time;

        let spec = self
            .chain_spec
            .clone()
            .ok_or_else(|| "system_time_slot_clock requires a chain spec".to_string())?;

        let slot_clock = SystemTimeSlotClock::new(
            spec.genesis_slot,
            Duration::from_secs(genesis_time),
            Duration::from_millis(spec.milliseconds_per_slot),
        );

        self.slot_clock = Some(slot_clock);
        Ok(self)
    }
}
