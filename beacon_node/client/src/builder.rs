use crate::config::{BeaconChainStartMethod, Config as ClientConfig, Eth1BackendMethod};
use crate::RuntimeBeaconChainTypes;
use beacon_chain::{
    lmd_ghost::ThreadSafeReducedTree,
    slot_clock::{SlotClock, SystemTimeSlotClock, TestingSlotClock},
    store::{DiskStore, MemoryStore, Store},
    test_utils::generate_deterministic_keypairs,
    BeaconChain, BeaconChainBuilder, BeaconChainTypes, Eth1ChainBackend, EventHandler, ForkChoice,
    InteropEth1ChainBackend,
};
use eth2_config::Eth2Config;
use exit_future::Signal;
use lmd_ghost::LmdGhost;
use slog::{crit, info, Logger};
use std::marker::PhantomData;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::runtime::TaskExecutor;
use types::{ChainSpec, EthSpec, Slot};
use websocket_server::{Config as WebSocketConfig, WebSocketSender};

pub trait ClientTypes: Send + Sync + 'static {
    type Store;
    type SlotClock;
    type LmdGhost;
    type Eth1Backend;
    type EthSpec;
    type EventHandler;
    type BeaconChain;
}

pub struct ClientBuilder<T: ClientTypes> {
    client_config: Option<ClientConfig>,
    eth2_config: Option<ClientConfig>,
    slot_clock: Option<T::SlotClock>,
    store: Option<Arc<T::Store>>,
    beacon_chain: Option<T::BeaconChain>,
    exit_signals: Vec<Signal>,
    event_handler: Option<T::EventHandler>,
    eth1_backend: Option<T::Eth1Backend>,
    fork_choice: Option<T::LmdGhost>,
    log: Logger,
}

impl<T: ClientTypes> ClientBuilder<T> {
    fn new(_spec: T::EthSpec, log: Logger) -> Self {
        Self {
            client_config: None,
            eth2_config: None,
            slot_clock: None,
            store: None,
            beacon_chain: None,
            exit_signals: vec![],
            event_handler: None,
            eth1_backend: None,
            fork_choice: None,
            log,
        }
    }
}

impl<T, E> ClientBuilder<T>
where
    E: EthSpec,
    T: ClientTypes<EventHandler = WebSocketSender<E>, EthSpec = E>,
{
    fn with_websocket_event_handler(
        mut self,
        executor: &TaskExecutor,
        config: WebSocketConfig,
    ) -> Result<Self, String> {
        let (sender, exit_signal): (WebSocketSender<E>, Option<_>) = if config.enabled {
            let (sender, exit) = websocket_server::start_server(&config, executor, &self.log)?;
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

impl<T, E> ClientBuilder<T>
where
    E: EthSpec,
    T: ClientTypes<EventHandler = WebSocketSender<E>, EthSpec = E>,
{
    fn with_null_event_handler(mut self) -> Result<Self, String> {
        self.event_handler = Some(WebSocketSender::dummy());
        Ok(self)
    }
}

impl<T> ClientBuilder<T>
where
    T: ClientTypes<Store = MemoryStore>,
{
    fn with_memory_store(mut self) -> Self {
        let store = MemoryStore::open();
        self.store = Some(Arc::new(store));
        self
    }
}

impl<T> ClientBuilder<T>
where
    T: ClientTypes<Store = DiskStore>,
{
    fn with_disk_store(mut self, path: &Path) -> Result<Self, String> {
        let store = DiskStore::open(path)
            .map_err(|e| format!("Unable to open database: {:?}", e).to_string())?;
        self.store = Some(Arc::new(store));
        Ok(self)
    }
}

impl<T, E> ClientBuilder<T>
where
    E: EthSpec,
    T: ClientTypes<Eth1Backend = InteropEth1ChainBackend<E>, EthSpec = E>,
{
    fn with_dummy_eth1_backend(mut self) -> Self {
        self.eth1_backend = Some(InteropEth1ChainBackend::default());
        self
    }
}

impl<B, E, S, T> ClientBuilder<T>
where
    E: EthSpec,
    S: Store,
    B: BeaconChainTypes,
    T: ClientTypes<
        Store = S,
        LmdGhost = ThreadSafeReducedTree<B::Store, E>,
        EthSpec = E,
        BeaconChain = BeaconChain<B>,
    >,
{
    fn with_reduced_tree_fork_choice(mut self) -> Result<Self, String> {
        if let Some(beacon_chain) = &self.beacon_chain {
            let store = beacon_chain.store.clone();

            let finalized_root = beacon_chain.head().beacon_state.finalized_checkpoint.root;
            let finalized_block = beacon_chain
                .store
                .get(&finalized_root)
                .map_err(|e| format!("Failed to read from database: {:?}", e))?
                .ok_or_else(|| "Unable to load latest finalized block from store")?;

            let fork_choice = ThreadSafeReducedTree::new(store, &finalized_block, finalized_root);
            self.fork_choice = Some(fork_choice);
            Ok(self)
        } else {
            Err("Beacon chain must be configured before fork choice".to_string())
        }
    }
}

impl<
        TClientTypes,
        TBeaconChainTypes,
        TStore,
        TSlotClock,
        TLmdGhost,
        TEth1Backend,
        TEthSpec,
        TEventHandler,
    > ClientBuilder<TClientTypes>
where
    TStore: Store,
    TSlotClock: SlotClock,
    TLmdGhost: LmdGhost<TStore, TEthSpec>,
    TEth1Backend: Eth1ChainBackend<TEthSpec>,
    TEthSpec: EthSpec,
    TEventHandler: EventHandler<TEthSpec>,
    TBeaconChainTypes: BeaconChainTypes<
        Store = TStore,
        SlotClock = TSlotClock,
        LmdGhost = TLmdGhost,
        Eth1Chain = TEth1Backend,
        EthSpec = TEthSpec,
        EventHandler = TEventHandler,
    >,
    TClientTypes: ClientTypes<
        Store = TStore,
        SlotClock = TSlotClock,
        LmdGhost = TLmdGhost,
        Eth1Backend = TEth1Backend,
        EthSpec = TEthSpec,
        EventHandler = TEventHandler,
        BeaconChain = BeaconChain<TBeaconChainTypes>,
    >,
{
    fn with_beacon_chain(
        mut self,
        start_method: &BeaconChainStartMethod,
        spec: ChainSpec,
    ) -> Result<Self, String> {
        let log = self.log.clone();

        let builder = match start_method {
            BeaconChainStartMethod::Resume => {
                info!(
                    log,
                    "Starting beacon chain";
                    "method" => "resume"
                );
                BeaconChainBuilder::from_store(spec.clone(), log.clone())
            }
            BeaconChainStartMethod::Mainnet => {
                crit!(log, "No mainnet beacon chain startup specification.");
                return Err("Mainnet launch is not yet announced.".into());
            }
            BeaconChainStartMethod::RecentGenesis {
                validator_count,
                minutes,
            } => {
                info!(
                    log,
                    "Starting beacon chain";
                    "validator_count" => validator_count,
                    "minutes" => minutes,
                    "method" => "recent"
                );
                BeaconChainBuilder::recent_genesis(
                    &generate_deterministic_keypairs(*validator_count),
                    *minutes,
                    spec.clone(),
                    log.clone(),
                )?
            }
            BeaconChainStartMethod::Generated {
                validator_count,
                genesis_time,
            } => {
                info!(
                    log,
                    "Starting beacon chain";
                    "validator_count" => validator_count,
                    "genesis_time" => genesis_time,
                    "method" => "quick"
                );
                BeaconChainBuilder::quick_start(
                    *genesis_time,
                    &generate_deterministic_keypairs(*validator_count),
                    spec.clone(),
                    log.clone(),
                )?
            }
            BeaconChainStartMethod::Yaml { file } => {
                info!(
                    log,
                    "Starting beacon chain";
                    "file" => format!("{:?}", file),
                    "method" => "yaml"
                );
                BeaconChainBuilder::yaml_state(file, spec.clone(), log.clone())?
            }
            BeaconChainStartMethod::Ssz { file } => {
                info!(
                    log,
                    "Starting beacon chain";
                    "file" => format!("{:?}", file),
                    "method" => "ssz"
                );
                BeaconChainBuilder::ssz_state(file, spec.clone(), log.clone())?
            }
            BeaconChainStartMethod::Json { file } => {
                info!(
                    log,
                    "Starting beacon chain";
                    "file" => format!("{:?}", file),
                    "method" => "json"
                );
                BeaconChainBuilder::json_state(file, spec.clone(), log.clone())?
            }
            BeaconChainStartMethod::HttpBootstrap { server, port } => {
                info!(
                    log,
                    "Starting beacon chain";
                    "port" => port,
                    "server" => server,
                    "method" => "bootstrap"
                );
                BeaconChainBuilder::http_bootstrap(server, spec.clone(), log.clone())?
            }
        };

        let store = self
            .store
            .clone()
            .ok_or_else(|| "Beacon chain requires a store.".to_string())?;
        let eth1_backend = self
            .eth1_backend
            .ok_or_else(|| "Beacon chain requires an eth1 backend.".to_string())?;
        let event_handler = self
            .event_handler
            .ok_or_else(|| "Beacon chain requires an event handler.".to_string())?;
        let fork_choice = self
            .fork_choice
            .ok_or_else(|| "Beacon chain requires an fork choice backend.".to_string())?;

        let chain = builder
            .build(store, eth1_backend, fork_choice, event_handler)
            .map_err(|e| format!("Failed to build becaon chain: {}", e))?;

        self.beacon_chain = Some(chain);

        self.event_handler = None;
        self.eth1_backend = None;
        self.fork_choice = None;

        Ok(self)
    }
}
/*

impl<S, B> ClientBuilder<S, TestingSlotClock, B> {
    fn with_testing_slot_clock(mut self) -> Self {
        let slot_clock = TestingSlotClock::new(
            Slot::new(0),
            Duration::from_secs(42),
            Duration::from_secs(6),
        );
        self.slot_clock = Some(slot_clock);
        self
    }
}

impl<S, B> ClientBuilder<S, SystemTimeSlotClock, B> {
    fn with_system_time_slot_clock(mut self) -> Self {
        let slot_clock = SystemTimeSlotClock::new(
            Slot::new(0),
            Duration::from_secs(42),
            Duration::from_secs(6),
        );
        self.slot_clock = Some(slot_clock);
        self
    }
}

impl<C, B> ClientBuilder<MemoryStore, C, B> {
    fn with_memory_store(mut self) -> Self {
        let store = MemoryStore::open();
        self.store = Some(store);
        self
    }
}

impl<C, B> ClientBuilder<DiskStore, C, B> {
    fn with_disk_store(mut self, path: &Path) -> Result<Self, String> {
        let store = DiskStore::open(path)
            .map_err(|e| format!("Unable to open database: {:?}", e).to_string())?;
        self.store = Some(store);
        Ok(self)
    }
}
*/

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
        let spec = &MinimalEthSpec::default_spec();

        let builder = ClientBuilder::new(MinimalEthSpec, log)
            .with_websocket_event_handler(executor, WebSocketConfig::default())
            .expect("should start websocket server")
            .with_memory_store()
            .with_dummy_eth1_backend()
            .with_beacon_chain(
                &BeaconChainStartMethod::Generated {
                    validator_count: 8,
                    genesis_time: 13371377,
                },
                spec.clone(),
            )
            .with_reduced_tree_fork_choice
            .expect("should start beacon chain");
        //
    }
}
