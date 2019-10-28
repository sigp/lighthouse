use crate::config::{ClientGenesis, Config as ClientConfig};
use crate::Client;
use beacon_chain::{
    builder::{BeaconChainBuilder, Witness},
    eth1_chain::JsonRpcEth1Backend,
    lmd_ghost::ThreadSafeReducedTree,
    slot_clock::{SlotClock, SystemTimeSlotClock},
    store::{DiskStore, MemoryStore, Store},
    BeaconChain, BeaconChainTypes, Eth1ChainBackend, EventHandler,
};
use environment::RuntimeContext;
use eth1::Config as Eth1Config;
use eth2_config::Eth2Config;
use exit_future::Signal;
use futures::{future, Future, IntoFuture, Stream};
use genesis::{
    generate_deterministic_keypairs, interop_genesis_state, state_from_ssz_file, Eth1GenesisService,
};
use lighthouse_bootstrap::Bootstrapper;
use lmd_ghost::LmdGhost;
use network::{NetworkConfig, NetworkMessage, Service as NetworkService};
use rpc::Config as RpcConfig;
use slog::{debug, error, info, warn};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::UnboundedSender;
use tokio::timer::Interval;
use types::{ChainSpec, EthSpec};
use websocket_server::{Config as WebSocketConfig, WebSocketSender};

/// The interval between notifier events.
pub const NOTIFIER_INTERVAL_SECONDS: u64 = 15;
/// Create a warning log whenever the peer count is at or below this value.
pub const WARN_PEER_COUNT: usize = 1;
/// Interval between polling the eth1 node for genesis information.
pub const ETH1_GENESIS_UPDATE_INTERVAL_MILLIS: u64 = 500;

pub struct ClientBuilder<T: BeaconChainTypes> {
    slot_clock: Option<T::SlotClock>,
    store: Option<Arc<T::Store>>,
    runtime_context: Option<RuntimeContext<T::EthSpec>>,
    chain_spec: Option<ChainSpec>,
    beacon_chain_builder: Option<BeaconChainBuilder<T>>,
    beacon_chain: Option<Arc<BeaconChain<T>>>,
    exit_signals: Vec<Signal>,
    event_handler: Option<T::EventHandler>,
    eth1_backend: Option<T::Eth1Chain>,
    libp2p_network: Option<Arc<NetworkService<T>>>,
    libp2p_network_send: Option<UnboundedSender<NetworkMessage>>,
    http_listen_addr: Option<SocketAddr>,
    websocket_listen_addr: Option<SocketAddr>,
    eth_spec_instance: T::EthSpec,
}

impl<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<Witness<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>>
where
    TStore: Store + 'static,
    TSlotClock: SlotClock + Clone + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    pub fn new(eth_spec_instance: TEthSpec) -> Self {
        Self {
            slot_clock: None,
            store: None,
            runtime_context: None,
            chain_spec: None,
            beacon_chain_builder: None,
            beacon_chain: None,
            exit_signals: vec![],
            event_handler: None,
            eth1_backend: None,
            libp2p_network: None,
            libp2p_network_send: None,
            http_listen_addr: None,
            websocket_listen_addr: None,
            eth_spec_instance,
        }
    }

    pub fn runtime_context(mut self, context: RuntimeContext<TEthSpec>) -> Self {
        self.runtime_context = Some(context);
        self
    }

    pub fn chain_spec(mut self, spec: ChainSpec) -> Self {
        self.chain_spec = Some(spec);
        self
    }

    pub fn beacon_chain_builder(
        mut self,
        client_genesis: ClientGenesis,
        config: Eth1Config,
    ) -> impl Future<Item = Self, Error = String> {
        let store = self.store.clone();
        let chain_spec = self.chain_spec.clone();
        let runtime_context = self.runtime_context.clone();
        let eth_spec_instance = self.eth_spec_instance.clone();

        future::ok(())
            .and_then(move |()| {
                let store = store
                    .ok_or_else(|| "beacon_chain_start_method requires a store".to_string())?;
                let context = runtime_context
                    .ok_or_else(|| "beacon_chain_start_method requires a log".to_string())?
                    .service_context("beacon");
                let spec = chain_spec
                    .ok_or_else(|| "beacon_chain_start_method requires a chain spec".to_string())?;

                let builder = BeaconChainBuilder::new(eth_spec_instance)
                    .logger(context.log.clone())
                    .store(store.clone())
                    .custom_spec(spec.clone());

                Ok((builder, spec, context))
            })
            .and_then(|(builder, spec, context)| {
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
                                .into_future();

                            Box::new(future)
                        }
                        ClientGenesis::SszFile { path } => {
                            let result = state_from_ssz_file(path);

                            let future = result
                                .and_then(move |genesis_state| builder.genesis_state(genesis_state))
                                .into_future();

                            Box::new(future)
                        }
                        ClientGenesis::DepositContract => {
                            let genesis_service = Eth1GenesisService::new(
                                Eth1Config {
                                    block_cache_truncation: None,
                                    ..config
                                },
                                context.log.clone(),
                            );

                            let future = genesis_service
                                .wait_for_genesis_state(
                                    Duration::from_millis(ETH1_GENESIS_UPDATE_INTERVAL_MILLIS),
                                    context.eth2_config().spec.clone(),
                                )
                                .and_then(move |genesis_state| {
                                    builder.genesis_state(genesis_state)
                                });

                            Box::new(future)
                        }
                        ClientGenesis::RemoteNode { server, port: _ } => {
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
                                });

                            Box::new(future)
                        }
                        ClientGenesis::Resume => {
                            let future = builder.resume_from_db().into_future();

                            Box::new(future)
                        }
                    };

                genesis_state_future
            })
            .map(move |beacon_chain_builder| {
                self.beacon_chain_builder = Some(beacon_chain_builder);
                self
            })
    }

    pub fn libp2p_network(mut self, config: &NetworkConfig) -> Result<Self, String> {
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or_else(|| "libp2p_network requires a beacon chain")?;
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "libp2p_network requires a runtime_context")?
            .service_context("network");

        let (network, network_send) =
            NetworkService::new(beacon_chain, config, &context.executor, context.log)
                .map_err(|e| format!("Failed to start libp2p network: {:?}", e))?;

        self.libp2p_network = Some(network);
        self.libp2p_network_send = Some(network_send);

        Ok(self)
    }

    pub fn grpc_server(mut self, config: &RpcConfig) -> Result<Self, String> {
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or_else(|| "grpc_server requires a beacon chain")?;
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "grpc_server requires a runtime_context")?
            .service_context("grpc");
        let network_send = self
            .libp2p_network_send
            .clone()
            .ok_or_else(|| "grpc_server requires a libp2p network")?;

        let exit_signal = rpc::start_server(
            config,
            &context.executor,
            network_send,
            beacon_chain,
            context.log,
        );

        self.exit_signals.push(exit_signal);

        Ok(self)
    }

    pub fn http_server(
        mut self,
        client_config: &ClientConfig,
        eth2_config: &Eth2Config,
    ) -> Result<Self, String> {
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or_else(|| "grpc_server requires a beacon chain")?;
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "http_server requires a runtime_context")?
            .service_context("http");
        let network = self
            .libp2p_network
            .clone()
            .ok_or_else(|| "grpc_server requires a libp2p network")?;
        let network_send = self
            .libp2p_network_send
            .clone()
            .ok_or_else(|| "grpc_server requires a libp2p network sender")?;

        let network_info = rest_api::NetworkInfo {
            network_service: network.clone(),
            network_chan: network_send.clone(),
        };

        let (exit_signal, listening_addr) = rest_api::start_server(
            &client_config.rest_api,
            &context.executor,
            beacon_chain.clone(),
            network_info,
            client_config.db_path().expect("unable to read datadir"),
            eth2_config.clone(),
            context.log,
        )
        .map_err(|e| format!("Failed to start HTTP API: {:?}", e))?;

        self.exit_signals.push(exit_signal);
        self.http_listen_addr = Some(listening_addr);

        Ok(self)
    }

    pub fn peer_count_notifier(mut self) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "peer_count_notifier requires a runtime_context")?
            .service_context("peer_notifier");
        let log = context.log.clone();
        let log_2 = context.log.clone();
        let network = self
            .libp2p_network
            .clone()
            .ok_or_else(|| "peer_notifier requires a libp2p network")?;

        let (exit_signal, exit) = exit_future::signal();

        self.exit_signals.push(exit_signal);

        let interval_future = Interval::new(
            Instant::now(),
            Duration::from_secs(NOTIFIER_INTERVAL_SECONDS),
        )
        .map_err(move |e| error!(log_2, "Notifier timer failed"; "error" => format!("{:?}", e)))
        .for_each(move |_| {
            // NOTE: Panics if libp2p is poisoned.
            let connected_peer_count = network.libp2p_service().lock().swarm.connected_peers();

            debug!(log, "Connected peer status"; "peer_count" => connected_peer_count);

            if connected_peer_count <= WARN_PEER_COUNT {
                warn!(log, "Low peer count"; "peer_count" => connected_peer_count);
            }

            Ok(())
        });

        context
            .executor
            .spawn(exit.until(interval_future).map(|_| ()));

        Ok(self)
    }

    pub fn slot_notifier(mut self) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "slot_notifier requires a runtime_context")?
            .service_context("slot_notifier");
        let log = context.log.clone();
        let log_2 = log.clone();
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or_else(|| "slot_notifier requires a libp2p network")?;
        let spec = self
            .chain_spec
            .clone()
            .ok_or_else(|| "slot_notifier requires a chain spec".to_string())?;
        let slot_duration = Duration::from_millis(spec.milliseconds_per_slot);
        let duration_to_next_slot = beacon_chain
            .slot_clock
            .duration_to_next_slot()
            .ok_or_else(|| "slot_notifier unable to determine time to next slot")?;

        let (exit_signal, exit) = exit_future::signal();

        self.exit_signals.push(exit_signal);

        let interval_future = Interval::new(Instant::now() + duration_to_next_slot, slot_duration)
            .map_err(move |e| error!(log_2, "Slot timer failed"; "error" => format!("{:?}", e)))
            .for_each(move |_| {
                let best_slot = beacon_chain.head().beacon_block.slot;
                let latest_block_root = beacon_chain.head().beacon_block_root;

                if let Ok(current_slot) = beacon_chain.slot() {
                    info!(
                        log,
                        "Slot start";
                        "skip_slots" => current_slot.saturating_sub(best_slot),
                        "best_block_root" => format!("{}", latest_block_root),
                        "best_block_slot" => best_slot,
                        "slot" => current_slot,
                    )
                } else {
                    error!(
                        log,
                        "Beacon chain running whilst slot clock is unavailable."
                    );
                };

                Ok(())
            });

        context
            .executor
            .spawn(exit.until(interval_future).map(|_| ()));

        Ok(self)
    }

    pub fn build(
        self,
    ) -> Client<Witness<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>> {
        Client {
            beacon_chain: self.beacon_chain,
            libp2p_network: self.libp2p_network,
            http_listen_addr: self.http_listen_addr,
            websocket_listen_addr: self.websocket_listen_addr,
            _exit_signals: self.exit_signals,
        }
    }
}

impl<TStore, TSlotClock, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<
            TStore,
            TSlotClock,
            ThreadSafeReducedTree<TStore, TEthSpec>,
            TEth1Backend,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TStore: Store + 'static,
    TSlotClock: SlotClock + Clone + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
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
            .eth1_backend(self.eth1_backend)
            .empty_reduced_tree_fork_choice()
            .map_err(|e| format!("Failed to init fork choice: {}", e))?
            .build()
            .map_err(|e| format!("Failed to build beacon chain: {}", e))?;

        self.beacon_chain = Some(Arc::new(chain));
        self.beacon_chain_builder = None;
        self.event_handler = None;
        self.eth1_backend = None;

        Ok(self)
    }
}

impl<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec>
    ClientBuilder<
        Witness<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, WebSocketSender<TEthSpec>>,
    >
where
    TStore: Store + 'static,
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
{
    pub fn websocket_event_handler(mut self, config: WebSocketConfig) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "websocket_event_handler requires a runtime_context")?
            .service_context("ws");

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

impl<TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<Witness<DiskStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>>
where
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<DiskStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    pub fn disk_store(mut self, path: &Path) -> Result<Self, String> {
        let store = DiskStore::open(path)
            .map_err(|e| format!("Unable to open database: {:?}", e).to_string())?;
        self.store = Some(Arc::new(store));
        Ok(self)
    }
}

impl<TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<MemoryStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>,
    >
where
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<MemoryStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    pub fn memory_store(mut self) -> Self {
        let store = MemoryStore::open();
        self.store = Some(Arc::new(store));
        self
    }
}

impl<TStore, TSlotClock, TLmdGhost, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<
            TStore,
            TSlotClock,
            TLmdGhost,
            JsonRpcEth1Backend<TEthSpec>,
            TEthSpec,
            TEventHandler,
        >,
    >
where
    TStore: Store + 'static,
    TSlotClock: SlotClock + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
    /// Sets the `BeaconChain` eth1 back-end to `JsonRpcEth1Backend`.
    ///
    /// Equivalent to calling `Self::eth1_backend` with `InteropEth1ChainBackend`.
    pub fn json_rpc_eth1_backend(
        mut self,
        config: Eth1Config,
        use_dummy_backend: bool,
    ) -> Result<Self, String> {
        let context = self
            .runtime_context
            .as_ref()
            .ok_or_else(|| "json_rpc_eth1_backend requires a runtime_context")?
            .service_context("eth1_rpc");
        let beacon_chain_builder = self
            .beacon_chain_builder
            .ok_or_else(|| "json_rpc_eth1_backend requires a beacon_chain_builder")?;

        let mut backend = JsonRpcEth1Backend::new(config, context.log);

        backend.use_dummy_backend = use_dummy_backend;

        if !use_dummy_backend {
            let exit = {
                let (tx, rx) = exit_future::signal();
                self.exit_signals.push(tx);
                rx
            };

            // Starts the service that connects to an eth1 node and periodically updates caches.
            context.executor.spawn(backend.start(exit));
        }

        let beacon_chain_builder = beacon_chain_builder.json_rpc_eth1_backend(backend);

        self.beacon_chain_builder = Some(beacon_chain_builder);

        Ok(self)
    }

    /// Do not use any eth1 backend. The client will not be able to produce beacon blocks.
    pub fn no_eth1_backend(mut self) -> Result<Self, String> {
        let beacon_chain_builder = self
            .beacon_chain_builder
            .ok_or_else(|| "json_rpc_eth1_backend requires a beacon_chain_builder")?;

        let beacon_chain_builder = beacon_chain_builder.no_eth1_backend();

        self.beacon_chain_builder = Some(beacon_chain_builder);

        Ok(self)
    }

    /// Use an eth1 backend that can produce blocks but is not connected to the an Eth1 node.
    ///
    /// This backend will never produce deposits, so it's impossible to add validators after
    /// genesis. The `Eth1Data` votes will all be for some deterministic junk data.
    ///
    /// ## Notes
    ///
    /// The client is given the `JsonRpcEth1Backend` type, but the http backend is never started and the
    /// caches are never used.
    pub fn dummy_eth1_backend(self) -> Result<Self, String> {
        self.json_rpc_eth1_backend(Eth1Config::default(), true)
    }
}

impl<TStore, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>
    ClientBuilder<
        Witness<TStore, SystemTimeSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>,
    >
where
    TStore: Store + 'static,
    TLmdGhost: LmdGhost<TStore, TEthSpec> + 'static,
    TEth1Backend: Eth1ChainBackend<TEthSpec> + 'static,
    TEthSpec: EthSpec + 'static,
    TEventHandler: EventHandler<TEthSpec> + 'static,
{
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

/* TODO: fix and reinstate.
#[cfg(test)]
mod test {
    use super::*;
    use sloggers::{null::NullLoggerBuilder, Build};
    use tokio::runtime::Runtime;
    use types::MinimalEthSpec;

    fn get_logger() -> Logger {
        let builder = NullLoggerBuilder;
        builder.build().expect("should build logger")
    }

    fn get_runtime() -> Runtime {
        Runtime::new().expect("should create runtime")
    }

    #[test]
    fn builds_client() {
        ClientBuilder::new(MinimalEthSpec)
            .logger(get_logger())
            .memory_store()
            .executor(get_runtime().executor())
            .websocket_event_handler(WebSocketConfig::default())
            .expect("should start websocket server")
            .dummy_eth1_backend()
            .beacon_checkpoint(&BeaconChainStartMethod::Generated {
                validator_count: 8,
                genesis_time: 13371377,
            })
            .expect("should find beacon checkpoint")
            .system_time_slot_clock()
            .expect("should build slot clock")
            .beacon_chain()
            .expect("should start beacon chain")
            .build();
    }
}
*/
