extern crate slog;

mod beacon_chain_types;
mod client_config;
pub mod error;
pub mod notifier;

use beacon_chain::BeaconChain;
use beacon_chain_types::InitialiseBeaconChain;
use exit_future::Signal;
use futures::{future::Future, Stream};
use network::Service as NetworkService;
use prometheus::Registry;
use slog::{error, info, o};
use slot_clock::SlotClock;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;

pub use beacon_chain::BeaconChainTypes;
pub use beacon_chain_types::{TestnetDiskBeaconChainTypes, TestnetMemoryBeaconChainTypes};
pub use client_config::{ClientConfig, DBType};

/// Main beacon node client service. This provides the connection and initialisation of the clients
/// sub-services in multiple threads.
pub struct Client<T: BeaconChainTypes> {
    /// Configuration for the lighthouse client.
    _config: ClientConfig,
    /// The beacon chain for the running client.
    beacon_chain: Arc<BeaconChain<T>>,
    /// Reference to the network service.
    pub network: Arc<NetworkService<T>>,
    /// Signal to terminate the RPC server.
    pub rpc_exit_signal: Option<Signal>,
    /// Signal to terminate the HTTP server.
    pub http_exit_signal: Option<Signal>,
    /// Signal to terminate the slot timer.
    pub slot_timer_exit_signal: Option<Signal>,
    /// The clients logger.
    log: slog::Logger,
    /// Marker to pin the beacon chain generics.
    phantom: PhantomData<T>,
}

impl<T> Client<T>
where
    T: BeaconChainTypes + InitialiseBeaconChain<T> + Clone + 'static,
{
    /// Generate an instance of the client. Spawn and link all internal sub-processes.
    pub fn new(
        config: ClientConfig,
        store: T::Store,
        log: slog::Logger,
        executor: &TaskExecutor,
    ) -> error::Result<Self> {
        let metrics_registry = Registry::new();
        let store = Arc::new(store);

        // Load a `BeaconChain` from the store, or create a new one if it does not exist.
        let beacon_chain = Arc::new(T::initialise_beacon_chain(store, log.clone()));
        // Registry all beacon chain metrics with the global registry.
        beacon_chain
            .metrics
            .register(&metrics_registry)
            .expect("Failed to registry metrics");

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
                "Initializing state";
                "state_slot" => state_slot,
                "wall_clock_slot" => wall_clock_slot,
                "slots_since_genesis" => slots_since_genesis,
                "catchup_distance" => wall_clock_slot - state_slot,
            );
        }
        do_state_catchup(&beacon_chain, &log);
        info!(
            log,
            "State initialized";
            "state_slot" => beacon_chain.head().beacon_state.slot,
            "wall_clock_slot" => beacon_chain.read_slot_clock().unwrap(),
        );

        // Start the network service, libp2p and syncing threads
        // TODO: Add beacon_chain reference to network parameters
        let network_config = &config.net_conf;
        let network_logger = log.new(o!("Service" => "Network"));
        let (network, network_send) = NetworkService::new(
            beacon_chain.clone(),
            network_config,
            executor,
            network_logger,
        )?;

        // spawn the RPC server
        let rpc_exit_signal = if config.rpc_conf.enabled {
            Some(rpc::start_server(
                &config.rpc_conf,
                executor,
                network_send.clone(),
                beacon_chain.clone(),
                &log,
            ))
        } else {
            None
        };

        // Start the `http_server` service.
        //
        // Note: presently we are ignoring the config and _always_ starting a HTTP server.
        let http_exit_signal = if config.http_conf.enabled {
            Some(http_server::start_service(
                &config.http_conf,
                executor,
                network_send,
                beacon_chain.clone(),
                config.db_name.clone(),
                metrics_registry,
                &log,
            ))
        } else {
            None
        };

        let (slot_timer_exit_signal, exit) = exit_future::signal();
        if let Ok(Some(duration_to_next_slot)) = beacon_chain.slot_clock.duration_to_next_slot() {
            // set up the validator work interval - start at next slot and proceed every slot
            let interval = {
                // Set the interval to start at the next slot, and every slot after
                let slot_duration = Duration::from_secs(config.spec.seconds_per_slot);
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
            _config: config,
            beacon_chain,
            http_exit_signal,
            rpc_exit_signal,
            slot_timer_exit_signal: Some(slot_timer_exit_signal),
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
        dbg!("Saved BeaconChain to store");
    }
}

fn do_state_catchup<T: BeaconChainTypes>(chain: &Arc<BeaconChain<T>>, log: &slog::Logger) {
    if let Some(genesis_height) = chain.slots_since_genesis() {
        let result = chain.catchup_state();

        let common = o!(
            "best_slot" => chain.head().beacon_block.slot,
            "latest_block_root" => format!("{}", chain.head().beacon_block_root),
            "wall_clock_slot" => chain.read_slot_clock().unwrap(),
            "state_slot" => chain.head().beacon_state.slot,
            "slots_since_genesis" => genesis_height,
        );

        match result {
            Ok(_) => info!(
                log,
                "NewSlot";
                common
            ),
            Err(e) => error!(
                log,
                "StateCatchupFailed";
                "error" => format!("{:?}", e),
                common
            ),
        };
    }
}
