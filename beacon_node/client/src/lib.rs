extern crate slog;

mod config;

pub mod error;
pub mod notifier;

use beacon_chain::{
    lmd_ghost::ThreadSafeReducedTree, slot_clock::SystemTimeSlotClock, store::Store,
    test_utils::generate_deterministic_keypairs, BeaconChain, BeaconChainBuilder,
};
use exit_future::Signal;
use futures::{future::Future, Stream};
use network::Service as NetworkService;
use rest_api::NetworkInfo;
use slog::{crit, debug, error, info, o};
use slot_clock::SlotClock;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;
use types::EthSpec;
use websocket_server::WebSocketSender;

pub use beacon_chain::{BeaconChainTypes, Eth1ChainBackend, InteropEth1ChainBackend};
pub use config::{BeaconChainStartMethod, Config as ClientConfig, Eth1BackendMethod};
pub use eth2_config::Eth2Config;

#[derive(Clone)]
pub struct RuntimeBeaconChainTypes<S: Store, E: EthSpec> {
    _phantom_s: PhantomData<S>,
    _phantom_e: PhantomData<E>,
}

impl<S, E> BeaconChainTypes for RuntimeBeaconChainTypes<S, E>
where
    S: Store + 'static,
    E: EthSpec,
{
    type Store = S;
    type SlotClock = SystemTimeSlotClock;
    type LmdGhost = ThreadSafeReducedTree<S, E>;
    type Eth1Chain = InteropEth1ChainBackend<E>;
    type EthSpec = E;
    type EventHandler = WebSocketSender<E>;
}

/// Main beacon node client service. This provides the connection and initialisation of the clients
/// sub-services in multiple threads.
pub struct Client<S, E>
where
    S: Store + Clone + 'static,
    E: EthSpec,
{
    /// Configuration for the lighthouse client.
    _client_config: ClientConfig,
    /// The beacon chain for the running client.
    beacon_chain: Arc<BeaconChain<RuntimeBeaconChainTypes<S, E>>>,
    /// Reference to the network service.
    pub network: Arc<NetworkService<RuntimeBeaconChainTypes<S, E>>>,
    /// Signal to terminate the RPC server.
    pub rpc_exit_signal: Option<Signal>,
    /// Signal to terminate the slot timer.
    pub slot_timer_exit_signal: Option<Signal>,
    /// Signal to terminate the API
    pub api_exit_signal: Option<Signal>,
    /// Signal to terminate the websocket server
    pub websocket_exit_signal: Option<Signal>,
    /// The clients logger.
    log: slog::Logger,
}

impl<S, E> Client<S, E>
where
    S: Store + Clone + 'static,
    E: EthSpec,
{
    /// Generate an instance of the client. Spawn and link all internal sub-processes.
    pub fn new(
        client_config: ClientConfig,
        eth2_config: Eth2Config,
        store: S,
        log: slog::Logger,
        executor: &TaskExecutor,
    ) -> error::Result<Self> {
        let store = Arc::new(store);
        let milliseconds_per_slot = eth2_config.spec.milliseconds_per_slot;

        let spec = &eth2_config.spec.clone();

        let beacon_chain_builder = match &client_config.beacon_chain_start_method {
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

        let eth1_backend =
            InteropEth1ChainBackend::new(String::new()).map_err(|e| format!("{:?}", e))?;

        // Start the websocket server.
        let (websocket_sender, websocket_exit_signal): (WebSocketSender<E>, Option<_>) =
            if client_config.websocket_server.enabled {
                let (sender, exit) = websocket_server::start_server(
                    &client_config.websocket_server,
                    executor,
                    &log,
                )?;
                (sender, Some(exit))
            } else {
                (WebSocketSender::dummy(), None)
            };

        let beacon_chain: Arc<BeaconChain<RuntimeBeaconChainTypes<S, E>>> = Arc::new(
            beacon_chain_builder
                .build(store, eth1_backend, websocket_sender)
                .map_err(error::Error::from)?,
        );

        let since_epoch = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Unable to read system time: {}", e))?;
        let since_genesis = Duration::from_secs(beacon_chain.head().beacon_state.genesis_time);

        if since_genesis > since_epoch {
            info!(
                log,
                "Starting node prior to genesis";
                "now" => since_epoch.as_secs(),
                "genesis_seconds" => since_genesis.as_secs(),
            );
        }

        let network_config = &client_config.network;
        let (network, network_send) =
            NetworkService::new(beacon_chain.clone(), network_config, executor, log.clone())?;

        // spawn the RPC server
        let rpc_exit_signal = if client_config.rpc.enabled {
            Some(rpc::start_server(
                &client_config.rpc,
                executor,
                network_send.clone(),
                beacon_chain.clone(),
                &log,
            ))
        } else {
            None
        };

        // Start the `rest_api` service
        let api_exit_signal = if client_config.rest_api.enabled {
            let network_info = NetworkInfo {
                network_service: network.clone(),
                network_chan: network_send.clone(),
            };
            match rest_api::start_server(
                &client_config.rest_api,
                executor,
                beacon_chain.clone(),
                network_info,
                client_config.db_path().expect("unable to read datadir"),
                eth2_config.clone(),
                &log,
            ) {
                Ok(s) => Some(s),
                Err(e) => {
                    error!(log, "API service failed to start."; "error" => format!("{:?}",e));
                    None
                }
            }
        } else {
            None
        };

        let (slot_timer_exit_signal, exit) = exit_future::signal();
        if let Some(duration_to_next_slot) = beacon_chain.slot_clock.duration_to_next_slot() {
            // set up the validator work interval - start at next slot and proceed every slot
            let interval = {
                // Set the interval to start at the next slot, and every slot after
                let slot_duration = Duration::from_millis(milliseconds_per_slot);
                //TODO: Handle checked add correctly
                Interval::new(Instant::now() + duration_to_next_slot, slot_duration)
            };

            let chain = beacon_chain.clone();
            let log = log.new(o!("Service" => "SlotTimer"));
            executor.spawn(
                exit.until(
                    interval
                        .for_each(move |_| {
                            log_new_slot(&chain, &log);

                            Ok(())
                        })
                        .map_err(|_| ()),
                )
                .map(|_| ()),
            );
        }

        Ok(Client {
            _client_config: client_config,
            beacon_chain,
            rpc_exit_signal,
            slot_timer_exit_signal: Some(slot_timer_exit_signal),
            api_exit_signal,
            websocket_exit_signal,
            log,
            network,
        })
    }
}

impl<S: Store + Clone, E: EthSpec> Drop for Client<S, E> {
    fn drop(&mut self) {
        // Save the beacon chain to it's store before dropping.
        let _result = self.beacon_chain.persist();
    }
}

fn log_new_slot<T: BeaconChainTypes>(chain: &Arc<BeaconChain<T>>, log: &slog::Logger) {
    let best_slot = chain.head().beacon_block.slot;
    let latest_block_root = chain.head().beacon_block_root;

    if let Ok(current_slot) = chain.slot() {
        info!(
            log,
            "Slot start";
            "best_slot" => best_slot,
            "slot" => current_slot,
        );
        debug!(
            log,
            "Slot info";
            "skip_slots" => current_slot.saturating_sub(best_slot),
            "best_block_root" => format!("{}", latest_block_root),
            "slot" => current_slot,
        );
    } else {
        error!(
            log,
            "Beacon chain running whilst slot clock is unavailable."
        );
    };
}
