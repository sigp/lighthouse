extern crate slog;

mod beacon_chain_types;
mod bootstrapper;
mod config;

pub mod error;
pub mod notifier;

use beacon_chain::BeaconChain;
use exit_future::Signal;
use futures::{future::Future, Stream};
use network::Service as NetworkService;
use slog::{error, info, o};
use slot_clock::SlotClock;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;

pub use beacon_chain::BeaconChainTypes;
pub use beacon_chain_types::ClientType;
pub use beacon_chain_types::InitialiseBeaconChain;
pub use bootstrapper::Bootstrapper;
pub use config::{Config as ClientConfig, GenesisState};
pub use eth2_config::Eth2Config;

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
    T: BeaconChainTypes + InitialiseBeaconChain<T> + Clone,
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
        let seconds_per_slot = eth2_config.spec.seconds_per_slot;

        // Load a `BeaconChain` from the store, or create a new one if it does not exist.
        let beacon_chain = Arc::new(T::initialise_beacon_chain(
            store,
            &client_config,
            eth2_config.spec.clone(),
            log.clone(),
        )?);

        if beacon_chain.read_slot_clock().is_none() {
            panic!("Cannot start client before genesis!")
        }

        // Block starting the client until we have caught the state up to the current slot.
        //
        // If we don't block here we create an initial scenario where we're unable to process any
        // blocks and we're basically useless.
        {
            let state_slot = beacon_chain.head().beacon_state.slot;
            let wall_clock_slot = beacon_chain.read_slot_clock().unwrap();
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
        do_state_catchup(&beacon_chain, &log);

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
        if let Ok(Some(duration_to_next_slot)) = beacon_chain.slot_clock.duration_to_next_slot() {
            // set up the validator work interval - start at next slot and proceed every slot
            let interval = {
                // Set the interval to start at the next slot, and every slot after
                let slot_duration = Duration::from_secs(seconds_per_slot);
                //TODO: Handle checked add correctly
                Interval::new(Instant::now() + duration_to_next_slot, slot_duration)
            };

            let chain = beacon_chain.clone();
            let log = log.new(o!("Service" => "SlotTimer"));
            executor.spawn(
                exit.until(
                    interval
                        .for_each(move |_| {
                            do_state_catchup(&chain, &log);

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

fn do_state_catchup<T: BeaconChainTypes>(chain: &Arc<BeaconChain<T>>, log: &slog::Logger) {
    // Only attempt to `catchup_state` if we can read the slot clock.
    if let Some(current_slot) = chain.read_slot_clock() {
        let state_catchup_result = chain.catchup_state();

        let best_slot = chain.head().beacon_block.slot;
        let latest_block_root = chain.head().beacon_block_root;

        let common = o!(
            "skip_slots" => current_slot.saturating_sub(best_slot),
            "best_block_root" => format!("{}", latest_block_root),
            "best_block_slot" => best_slot,
            "slot" => current_slot,
        );

        if let Err(e) = state_catchup_result {
            error!(
                log,
                "State catchup failed";
                "error" => format!("{:?}", e),
                common
            )
        } else {
            info!(
                log,
                "Slot start";
                common
            )
        }
    } else {
        error!(
            log,
            "Beacon chain running whilst slot clock is unavailable."
        );
    };
}
