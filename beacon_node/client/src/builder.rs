use crate::config::{ClientGenesis, Config as ClientConfig};
use crate::notifier::spawn_notifier;
use crate::Client;
use beacon_chain::{
    builder::{BeaconChainBuilder, Witness},
    eth1_chain::CachingEth1Backend,
    lmd_ghost::ThreadSafeReducedTree,
    slot_clock::{SlotClock, SystemTimeSlotClock},
    store::{
        migrate::{BackgroundMigrator, Migrate, NullMigrator},
        DiskStore, MemoryStore, SimpleDiskStore, Store,
    },
    BeaconChain, BeaconChainTypes, Eth1ChainBackend, EventHandler,
};
use environment::RuntimeContext;
use eth1::{Config as Eth1Config, Service as Eth1Service};
use eth2_config::Eth2Config;
use exit_future::Signal;
use futures::{future, Future, IntoFuture};
use genesis::{
    generate_deterministic_keypairs, interop_genesis_state, state_from_ssz_file, Eth1GenesisService,
};
use lighthouse_bootstrap::Bootstrapper;
use lmd_ghost::LmdGhost;
use network::{NetworkConfig, NetworkMessage, Service as NetworkService};
use slog::info;
use ssz::Decode;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;
use types::{BeaconState, ChainSpec, EthSpec};
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
    store: Option<Arc<T::Store>>,
    store_migrator: Option<T::StoreMigrator>,
    runtime_context: Option<RuntimeContext<T::EthSpec>>,
    chain_spec: Option<ChainSpec>,
    beacon_chain_builder: Option<BeaconChainBuilder<T>>,
    beacon_chain: Option<Arc<BeaconChain<T>>>,
    eth1_service: Option<Eth1Service>,
    exit_signals: Vec<Signal>,
    event_handler: Option<T::EventHandler>,
    libp2p_network: Option<Arc<NetworkService<T>>>,
    libp2p_network_send: Option<UnboundedSender<NetworkMessage>>,
    http_listen_addr: Option<SocketAddr>,
    websocket_listen_addr: Option<SocketAddr>,
    eth_spec_instance: T::EthSpec,
}

impl<TStore, TStoreMigrator, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<
            TStore,
            TStoreMigrator,
            TSlotClock,
            TLmdGhost,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec>,
    TSlotClock: SlotClock + Clone + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
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
            exit_signals: vec![],
            event_handler: None,
            libp2p_network: None,
            libp2p_network_send: None,
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
    pub fn beacon_chain_builder(
        mut self,
        client_genesis: ClientGenesis,
        config: Eth1Config,
    ) -> impl Future<Item = Self, Error = String> {
        let store = self.store.clone();
        let store_migrator = self.store_migrator.take();
        let chain_spec = self.chain_spec.clone();
        let runtime_context = self.runtime_context.clone();
        let eth_spec_instance = self.eth_spec_instance.clone();

        future::ok(())
            .and_then(move |()| {
                let store = store
                    .ok_or_else(|| "beacon_chain_start_method requires a store".to_string())?;
                let store_migrator = store_migrator.ok_or_else(|| {
                    "beacon_chain_start_method requires a store migrator".to_string()
                })?;
                let context = runtime_context
                    .ok_or_else(|| "beacon_chain_start_method requires a log".to_string())?
                    .service_context("beacon".into());
                let spec = chain_spec
                    .ok_or_else(|| "beacon_chain_start_method requires a chain spec".to_string())?;

                let builder = BeaconChainBuilder::new(eth_spec_instance)
                    .logger(context.log.clone())
                    .store(store.clone())
                    .store_migrator(store_migrator)
                    .custom_spec(spec.clone());

                Ok((builder, spec, context))
            })
            .and_then(move |(builder, spec, context)| {
                let genesis_state_future: Box<dyn Future<Item = _, Error = _> + Send> =
                    match client_genesis {
                        ClientGenesis::Interop {
                            validator_count,
                            genesis_time,
                        } => {
                            let keypairs = generate_deterministic_keypairs(validator_count);
                            let result = interop_genesis_state(&keypairs, genesis_time, &spec);

                            let future = result
                                .and_then(move |genesis_state| builder.genesis_state(genesis_state))
                                .into_future()
                                .map(|v| (v, None));

                            Box::new(future)
                        }
                        ClientGenesis::SszFile { path } => {
                            let result = state_from_ssz_file(path);

                            let future = result
                                .and_then(move |genesis_state| builder.genesis_state(genesis_state))
                                .into_future()
                                .map(|v| (v, None));

                            Box::new(future)
                        }
                        ClientGenesis::SszBytes {
                            genesis_state_bytes,
                        } => {
                            info!(
                                context.log,
                                "Starting from known genesis state";
                            );

                            let result = BeaconState::from_ssz_bytes(&genesis_state_bytes)
                                .map_err(|e| format!("Unable to parse genesis state SSZ: {:?}", e));

                            let future = result
                                .and_then(move |genesis_state| builder.genesis_state(genesis_state))
                                .into_future()
                                .map(|v| (v, None));

                            Box::new(future)
                        }
                        ClientGenesis::DepositContract => {
                            info!(
                                context.log,
                                "Waiting for eth2 genesis from eth1";
                                "eth1_node" => &config.endpoint
                            );

                            let genesis_service =
                                Eth1GenesisService::new(config, context.log.clone());

                            let future = genesis_service
                                .wait_for_genesis_state(
                                    Duration::from_millis(ETH1_GENESIS_UPDATE_INTERVAL_MILLIS),
                                    context.eth2_config().spec.clone(),
                                )
                                .and_then(move |genesis_state| builder.genesis_state(genesis_state))
                                .map(|v| (v, Some(genesis_service.into_core_service())));

                            Box::new(future)
                        }
                        ClientGenesis::RemoteNode { server, .. } => {
                            let future = Bootstrapper::connect(server.to_string(), &context.log)
                                .map_err(|e| {
                                    format!("Failed to initialize bootstrap client: {}", e)
                                })
                                .into_future()
                                .and_then(|bootstrapper| {
                                    let (genesis_state, _genesis_block) =
                                        bootstrapper.genesis().map_err(|e| {
                                            format!("Failed to bootstrap genesis state: {}", e)
                                        })?;

                                    builder.genesis_state(genesis_state)
                                })
                                .map(|v| (v, None));

                            Box::new(future)
                        }
                        ClientGenesis::Resume => {
                            let future = builder.resume_from_db().into_future().map(|v| (v, None));

                            Box::new(future)
                        }
                    };

                genesis_state_future
            })
            .map(move |(beacon_chain_builder, eth1_service_option)| {
                self.eth1_service = eth1_service_option;
                self.beacon_chain_builder = Some(beacon_chain_builder);
                self
            })
    }

    /// Immediately starts the libp2p networking stack.
    pub fn libp2p_network(mut self, config: &NetworkConfig) -> Result<Self, String> {
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or_else(|| "libp2p_network requires a beacon chain")?;
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "libp2p_network requires a runtime_context")?
            .service_context("network".into());

        let (network, network_send) =
            NetworkService::new(beacon_chain, config, &context.executor, context.log)
                .map_err(|e| format!("Failed to start libp2p network: {:?}", e))?;

        self.libp2p_network = Some(network);
        self.libp2p_network_send = Some(network_send);

        Ok(self)
    }

    /// Immediately starts the beacon node REST API http server.
    pub fn http_server(
        mut self,
        client_config: &ClientConfig,
        eth2_config: &Eth2Config,
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
        let network = self
            .libp2p_network
            .clone()
            .ok_or_else(|| "http_server requires a libp2p network")?;
        let network_send = self
            .libp2p_network_send
            .clone()
            .ok_or_else(|| "http_server requires a libp2p network sender")?;

        let network_info = rest_api::NetworkInfo {
            network_service: network.clone(),
            network_chan: network_send.clone(),
        };

        let (exit_signal, listening_addr) = rest_api::start_server(
            &client_config.rest_api,
            &context.executor,
            beacon_chain.clone(),
            network_info,
            client_config
                .create_db_path()
                .map_err(|_| "unable to read data dir")?,
            client_config
                .create_freezer_db_path()
                .map_err(|_| "unable to read freezer DB dir")?,
            eth2_config.clone(),
            context.log,
        )
        .map_err(|e| format!("Failed to start HTTP API: {:?}", e))?;

        self.exit_signals.push(exit_signal);
        self.http_listen_addr = Some(listening_addr);

        Ok(self)
    }

    /// Immediately starts the service that periodically logs information each slot.
    pub fn notifier(mut self) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "slot_notifier requires a runtime_context")?
            .service_context("slot_notifier".into());
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or_else(|| "slot_notifier requires a beacon chain")?;
        let network = self
            .libp2p_network
            .clone()
            .ok_or_else(|| "slot_notifier requires a libp2p network")?;
        let milliseconds_per_slot = self
            .chain_spec
            .as_ref()
            .ok_or_else(|| "slot_notifier requires a chain spec".to_string())?
            .milliseconds_per_slot;

        let exit_signal = spawn_notifier(context, beacon_chain, network, milliseconds_per_slot)
            .map_err(|e| format!("Unable to start slot notifier: {}", e))?;

        self.exit_signals.push(exit_signal);

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
            TStore,
            TStoreMigrator,
            TSlotClock,
            TLmdGhost,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
    > {
        Client {
            beacon_chain: self.beacon_chain,
            libp2p_network: self.libp2p_network,
            http_listen_addr: self.http_listen_addr,
            websocket_listen_addr: self.websocket_listen_addr,
            _exit_signals: self.exit_signals,
        }
    }
}

impl<TStore, TStoreMigrator, TSlotClock, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<
            TStore,
            TStoreMigrator,
            TSlotClock,
            ThreadSafeReducedTree<TStore, TEthSpec>,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec>,
    TSlotClock: SlotClock + Clone + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
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
            .reduced_tree_fork_choice()
            .map_err(|e| format!("Failed to init fork choice: {}", e))?
            .build()
            .map_err(|e| format!("Failed to build beacon chain: {}", e))?;

        self.beacon_chain = Some(Arc::new(chain));
        self.beacon_chain_builder = None;
        self.event_handler = None;

        Ok(self)
    }
}

impl<TStore, TStoreMigrator, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec>
    ClientBuilder<
        Witness<
            TStore,
            TStoreMigrator,
            TSlotClock,
            TLmdGhost,
            TEth1Backend,
            TEthSpec,
            WebSocketSender<TEthSpec>,
        >,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec>,
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
{
    /// Specifies that the `BeaconChain` should publish events using the WebSocket server.
    pub fn websocket_event_handler(mut self, config: WebSocketConfig) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "websocket_event_handler requires a runtime_context")?
            .service_context("ws".into());

        let (sender, exit_signal, listening_addr): (
            WebSocketSender<TEthSpec>,
            Option<_>,
            Option<_>,
        ) = if config.enabled {
            let (sender, exit, listening_addr) =
                websocket_server::start_server(&config, &context.executor, &context.log)?;
            (sender, Some(exit), Some(listening_addr))
        } else {
            (WebSocketSender::dummy(), None, None)
        };

        if let Some(signal) = exit_signal {
            self.exit_signals.push(signal);
        }
        self.event_handler = Some(sender);
        self.websocket_listen_addr = listening_addr;

        Ok(self)
    }
}

impl<TStoreMigrator, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<
            DiskStore<TEthSpec>,
            TStoreMigrator,
            TSlotClock,
            TLmdGhost,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TSlotClock: SlotClock + 'static,
    TStoreMigrator: store::Migrate<DiskStore<TEthSpec>, TEthSpec> + 'static,
    TLmdGhost: LmdGhost<DiskStore<TEthSpec>, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Specifies that the `Client` should use a `DiskStore` database.
    pub fn disk_store(
        mut self,
        hot_path: &Path,
        cold_path: &Path,
        slots_per_restore_point: u64,
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

        let store = DiskStore::open(
            hot_path,
            cold_path,
            slots_per_restore_point,
            spec,
            context.log,
        )
        .map_err(|e| format!("Unable to open database: {:?}", e).to_string())?;
        self.store = Some(Arc::new(store));
        Ok(self)
    }
}

impl<TStoreMigrator, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<
            SimpleDiskStore<TEthSpec>,
            TStoreMigrator,
            TSlotClock,
            TLmdGhost,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TSlotClock: SlotClock + 'static,
    TStoreMigrator: store::Migrate<SimpleDiskStore<TEthSpec>, TEthSpec> + 'static,
    TLmdGhost: LmdGhost<SimpleDiskStore<TEthSpec>, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Specifies that the `Client` should use a `DiskStore` database.
    pub fn simple_disk_store(mut self, path: &Path) -> Result<Self, String> {
        let store = SimpleDiskStore::open(path)
            .map_err(|e| format!("Unable to open database: {:?}", e).to_string())?;
        self.store = Some(Arc::new(store));
        Ok(self)
    }
}

impl<TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<
            MemoryStore<TEthSpec>,
            NullMigrator,
            TSlotClock,
            TLmdGhost,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<MemoryStore<TEthSpec>, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Specifies that the `Client` should use a `MemoryStore` database.
    ///
    /// Also sets the `store_migrator` to the `NullMigrator`, as that's the only viable choice.
    pub fn memory_store(mut self) -> Self {
        let store = MemoryStore::open();
        self.store = Some(Arc::new(store));
        self.store_migrator = Some(NullMigrator);
        self
    }
}

impl<TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<
            DiskStore<TEthSpec>,
            BackgroundMigrator<TEthSpec>,
            TSlotClock,
            TLmdGhost,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<DiskStore<TEthSpec>, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    pub fn background_migrator(mut self) -> Result<Self, String> {
        let store = self.store.clone().ok_or_else(|| {
            "background_migrator requires the store to be initialized".to_string()
        })?;
        self.store_migrator = Some(BackgroundMigrator::new(store));
        Ok(self)
    }
}

impl<TStore, TStoreMigrator, TSlotClock, TLmdGhost, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<
            TStore,
            TStoreMigrator,
            TSlotClock,
            TLmdGhost,
            CachingEth1Backend<TEthSpec, TStore>,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec>,
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
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
        let store = self
            .store
            .clone()
            .ok_or_else(|| "caching_eth1_backend requires a store".to_string())?;

        let backend = if let Some(eth1_service_from_genesis) = self.eth1_service {
            eth1_service_from_genesis.update_config(config.clone())?;

            // This cache is not useful because it's first (earliest) block likely the block that
            // triggered genesis.
            //
            // In order to vote we need to be able to go back at least 2 * `ETH1_FOLLOW_DISTANCE`
            // from the genesis-triggering block.  Presently the block cache does not support
            // importing blocks with decreasing block numbers, it only accepts them in increasing
            // order. If this turns out to be a bottleneck we can update the block cache to allow
            // adding earlier blocks too.
            eth1_service_from_genesis.drop_block_cache();

            CachingEth1Backend::from_service(eth1_service_from_genesis, store)
        } else {
            CachingEth1Backend::new(config, context.log, store)
        };

        self.eth1_service = None;

        let exit = {
            let (tx, rx) = exit_future::signal();
            self.exit_signals.push(tx);
            rx
        };

        // Starts the service that connects to an eth1 node and periodically updates caches.
        context.executor.spawn(backend.start(exit));

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

impl<TStore, TStoreMigrator, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<
            TStore,
            TStoreMigrator,
            SystemTimeSlotClock,
            TLmdGhost,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TStore: Store<TEthSpec> + 'static,
    TStoreMigrator: store::Migrate<TStore, TEthSpec>,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Specifies that the slot clock should read the time from the computers system clock.
    pub fn system_time_slot_clock(mut self) -> Result<Self, String> {
        let beacon_chain_builder = self
            .beacon_chain_builder
            .as_ref()
            .ok_or_else(|| "system_time_slot_clock requires a beacon_chain_builder")?;

        let genesis_time = beacon_chain_builder
            .finalized_checkpoint
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
