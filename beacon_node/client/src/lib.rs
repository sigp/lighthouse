extern crate slog;

mod config;

pub mod error;
pub mod notifier;

use beacon_chain::{
    lmd_ghost::ThreadSafeReducedTree, slot_clock::SystemTimeSlotClock, store::Store, BeaconChain,
    BeaconChainBuilder,
};
use exit_future::Signal;
use futures::{future::Future, Stream};
use network::Service as NetworkService;
use slog::{crit, error, info, o};
use slot_clock::SlotClock;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;
use types::EthSpec;

pub use beacon_chain::BeaconChainTypes;
pub use config::{BeaconChainStartMethod, Config as ClientConfig};
pub use eth2_config::Eth2Config;

#[derive(Clone)]
pub struct ClientType<S: Store, E: EthSpec> {
    _phantom_t: PhantomData<S>,
    _phantom_u: PhantomData<E>,
}

impl<S, E> BeaconChainTypes for ClientType<S, E>
where
    S: Store + 'static,
    E: EthSpec,
{
    type Store = S;
    type SlotClock = SystemTimeSlotClock;
    type LmdGhost = ThreadSafeReducedTree<S, E>;
    type EthSpec = E;
}

/// Main beacon node client service. This provides the connection and initialisation of the clients
/// sub-services in multiple threads.
pub struct Client<T: BeaconChainTypes> {
    /// Configuration for the lighthouse client.
    _client_config: ClientConfig,
    /// The beacon chain for the running client.
    beacon_chain: Arc<BeaconChain<T>>,
    /// Reference to the network service.
    pub network: Arc<NetworkService<T>>,
    /// Signal to terminate the RPC server.
    pub rpc_exit_signal: Option<Signal>,
    /// Signal to terminate the slot timer.
    pub slot_timer_exit_signal: Option<Signal>,
    /// Signal to terminate the API
    pub api_exit_signal: Option<Signal>,
    /// The clients logger.
    log: slog::Logger,
    /// Marker to pin the beacon chain generics.
    phantom: PhantomData<T>,
}

impl<T> Client<T>
where
    T: BeaconChainTypes + Clone,
{
    /// Generate an instance of the client. Spawn and link all internal sub-processes.
    pub fn new(
        client_config: ClientConfig,
        eth2_config: Eth2Config,
        store: T::Store,
        log: slog::Logger,
        executor: &TaskExecutor,
    ) -> error::Result<Self> {
        let store = Arc::new(store);
        let milliseconds_per_slot = eth2_config.spec.milliseconds_per_slot;

        let spec = &eth2_config.spec.clone();

        let beacon_chain_builder = match &client_config.beacon_chain_start_method {
            BeaconChainStartMethod::Resume => {
                BeaconChainBuilder::from_store(spec.clone(), log.clone())
            }
            BeaconChainStartMethod::Mainnet => {
                crit!(log, "No mainnet beacon chain startup specification.");
                return Err("Mainnet is not yet specified. We're working on it.".into());
            }
            BeaconChainStartMethod::RecentGenesis {
                validator_count,
                minutes,
            } => BeaconChainBuilder::recent_genesis(
                *validator_count,
                *minutes,
                spec.clone(),
                log.clone(),
            ),
            BeaconChainStartMethod::Generated {
                validator_count,
                genesis_time,
            } => BeaconChainBuilder::quick_start(
                *genesis_time,
                *validator_count,
                spec.clone(),
                log.clone(),
            ),
            BeaconChainStartMethod::Yaml { file } => {
                BeaconChainBuilder::yaml_state(file, spec.clone(), log.clone())?
            }
            BeaconChainStartMethod::HttpBootstrap { server, .. } => {
                BeaconChainBuilder::http_bootstrap(server, spec.clone(), log.clone())?
            }
        };

        let beacon_chain: Arc<BeaconChain<T>> = Arc::new(
            beacon_chain_builder
                .build(store)
                .map_err(error::Error::from)?,
        );

        if beacon_chain.slot().is_err() {
            panic!("Cannot start client before genesis!")
        }

        // Block starting the client until we have caught the state up to the current slot.
        //
        // If we don't block here we create an initial scenario where we're unable to process any
        // blocks and we're basically useless.
        {
            let state_slot = beacon_chain.head().beacon_state.slot;
            let wall_clock_slot = beacon_chain
                .slot()
                .expect("Cannot start client before genesis");
            let slots_since_genesis = beacon_chain.slots_since_genesis().unwrap();
            info!(
                log,
                "BeaconState cache init";
                "state_slot" => state_slot,
                "wall_clock_slot" => wall_clock_slot,
                "slots_since_genesis" => slots_since_genesis,
                "catchup_distance" => wall_clock_slot - state_slot,
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
            match rest_api::start_server(
                &client_config.rest_api,
                executor,
                beacon_chain.clone(),
                network.clone(),
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
            log,
            network,
            phantom: PhantomData,
        })
    }
}

impl<T: BeaconChainTypes> Drop for Client<T> {
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
}
