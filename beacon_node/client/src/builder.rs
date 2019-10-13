use crate::config::Config as ClientConfig;
use crate::Client;
use beacon_chain::{
    builder::{BeaconChainBuilder, BeaconChainStartMethod, Witness},
    lmd_ghost::ThreadSafeReducedTree,
    slot_clock::{SlotClock, SystemTimeSlotClock},
    store::{DiskStore, MemoryStore, Store},
    BeaconChain, BeaconChainTypes, Eth1ChainBackend, EventHandler, InteropEth1ChainBackend,
};
use eth2_config::Eth2Config;
use exit_future::Signal;
use lmd_ghost::LmdGhost;
use network::{NetworkConfig, NetworkMessage, Service as NetworkService};
use rpc::Config as RpcConfig;
use slog::Logger;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::runtime::TaskExecutor;
use tokio::sync::mpsc::UnboundedSender;
use types::{ChainSpec, EthSpec};
use websocket_server::{Config as WebSocketConfig, WebSocketSender};

pub struct ClientBuilder<T: BeaconChainTypes> {
    slot_clock: Option<T::SlotClock>,
    store: Option<Arc<T::Store>>,
    beacon_chain_builder: Option<BeaconChainBuilder<T>>,
    beacon_chain: Option<Arc<BeaconChain<T>>>,
    exit_signals: Vec<Signal>,
    event_handler: Option<T::EventHandler>,
    eth1_backend: Option<T::Eth1Chain>,
    libp2p_network: Option<Arc<NetworkService<T>>>,
    libp2p_network_send: Option<UnboundedSender<NetworkMessage>>,
    eth_spec_instance: T::EthSpec,
    spec: ChainSpec,
    log: Option<Logger>,
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
            beacon_chain_builder: None,
            beacon_chain: None,
            exit_signals: vec![],
            event_handler: None,
            eth1_backend: None,
            libp2p_network: None,
            libp2p_network_send: None,
            eth_spec_instance,
            spec: TEthSpec::default_spec(),
            log: None,
        }
    }

    pub fn beacon_checkpoint(mut self, method: &BeaconChainStartMethod) -> Result<Self, String> {
        let store = self
            .store
            .clone()
            .ok_or_else(|| "beacon_chain_start_method requires a store".to_string())?;
        let log = self
            .log
            .clone()
            .ok_or_else(|| "beacon_chain_start_method requires a log".to_string())?;

        let builder = BeaconChainBuilder::new(self.eth_spec_instance.clone())
            .custom_spec(self.spec.clone())
            .logger(log.clone())
            .store(store.clone())
            .initialize_state(method)
            .map_err(|e| format!("Failed to initialize beacon chain state: {}", e))?;

        self.beacon_chain_builder = Some(builder);

        Ok(self)
    }

    pub fn libp2p_network(
        mut self,
        config: &NetworkConfig,
        executor: &TaskExecutor,
    ) -> Result<Self, String> {
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or_else(|| "libp2p_network requires a beacon chain")?;
        let log = self
            .log
            .clone()
            .ok_or_else(|| "libp2p_network requires a log")?;

        let (network, network_send) = NetworkService::new(beacon_chain, config, executor, log)
            .map_err(|e| format!("Failed to start libp2p network: {:?}", e))?;

        self.libp2p_network = Some(network);
        self.libp2p_network_send = Some(network_send);

        Ok(self)
    }

    pub fn grpc_server(
        mut self,
        config: &RpcConfig,
        executor: &TaskExecutor,
    ) -> Result<Self, String> {
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or_else(|| "grpc_server requires a beacon chain")?;
        let log = self
            .log
            .clone()
            .ok_or_else(|| "grpc_server requires a log")?;
        let network_send = self
            .libp2p_network_send
            .clone()
            .ok_or_else(|| "grpc_server requires a libp2p network")?;

        let exit_signal = rpc::start_server(config, executor, network_send, beacon_chain, &log);

        self.exit_signals.push(exit_signal);

        Ok(self)
    }

    pub fn http_server(
        mut self,
        client_config: &ClientConfig,
        eth2_config: &Eth2Config,
        executor: &TaskExecutor,
    ) -> Result<Self, String> {
        let beacon_chain = self
            .beacon_chain
            .clone()
            .ok_or_else(|| "grpc_server requires a beacon chain")?;
        let log = self
            .log
            .clone()
            .ok_or_else(|| "grpc_server requires a log")?;
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

        let exit_signal = rest_api::start_server(
            &client_config.rest_api,
            executor,
            beacon_chain.clone(),
            network_info,
            client_config.db_path().expect("unable to read datadir"),
            eth2_config.clone(),
            &log,
        )
        .map_err(|e| format!("Failed to start HTTP API: {:?}", e))?;

        self.exit_signals.push(exit_signal);

        Ok(self)
    }

    pub fn build(
        self,
    ) -> Client<Witness<TStore, TSlotClock, TLmdGhost, TEth1Backend, TEthSpec, TEventHandler>> {
        Client {
            beacon_chain: self.beacon_chain,
            libp2p_network: self.libp2p_network,
            exit_signals: self.exit_signals,
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
    pub fn beacon_chain(mut self) -> Result<Self, String> {
        let chain = self
            .beacon_chain_builder
            .ok_or_else(|| "beacon_chain requires a beacon checkpoint")?
            .event_handler(
                self.event_handler
                    .ok_or_else(|| "beacon_chain requires an event handler")?,
            )
            .slot_clock(
                self.slot_clock
                    .clone()
                    .ok_or_else(|| "beacon_chain requires a slot clock")?,
            )
            .empty_reduced_tree_fork_choice()
            .map_err(|e| format!("Failed to init fork choice: {}", e))?
            .build()
            .map_err(|e| format!("Failed to build beacon chain: {}", e))?;

        self.beacon_chain = Some(Arc::new(chain));
        self.event_handler = None;

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
    pub fn websocket_event_handler(
        mut self,
        executor: &TaskExecutor,
        config: WebSocketConfig,
    ) -> Result<Self, String> {
        let log = self
            .log
            .clone()
            .ok_or_else(|| "websocket_event_handler requires a log".to_string())?;

        let (sender, exit_signal): (WebSocketSender<TEthSpec>, Option<_>) = if config.enabled {
            let (sender, exit) = websocket_server::start_server(&config, executor, &log)?;
            (sender, Some(exit))
        } else {
            (WebSocketSender::dummy(), None)
        };

        if let Some(signal) = exit_signal {
            self.exit_signals.push(signal);
        }
        self.event_handler = Some(sender);

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
            InteropEth1ChainBackend<TEthSpec>,
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
    pub fn dummy_eth1_backend(mut self) -> Self {
        self.eth1_backend = Some(InteropEth1ChainBackend::default());
        self
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
            .ok_or_else(|| "system_time_slot_clock requires a beacon chain")?;

        let genesis_time = beacon_chain_builder
            .finalized_checkpoint
            .as_ref()
            .ok_or_else(|| "system_time_slot_clock requires an initialized beacon state")?
            .beacon_state
            .genesis_time;

        let slot_clock = SystemTimeSlotClock::new(
            self.spec.genesis_slot,
            Duration::from_secs(genesis_time),
            Duration::from_millis(self.spec.milliseconds_per_slot),
        );

        self.slot_clock = Some(slot_clock);
        Ok(self)
    }
}

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
    fn sanity() {
        let runtime = get_runtime();
        let executor = &runtime.executor();
        let log = get_logger();

        let builder = ClientBuilder::new(MinimalEthSpec)
            .memory_store()
            .websocket_event_handler(executor, WebSocketConfig::default())
            .expect("should start websocket server")
            .dummy_eth1_backend()
            .system_time_slot_clock()
            .expect("should build slot clock")
            .beacon_checkpoint(&BeaconChainStartMethod::Generated {
                validator_count: 8,
                genesis_time: 13371377,
            })
            .expect("should start beacon chain");
        //
    }
}
