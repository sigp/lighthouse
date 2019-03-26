extern crate slog;

mod client_config;
pub mod client_types;
pub mod error;
pub mod notifier;

use beacon_chain::BeaconChain;
pub use client_config::ClientConfig;
pub use client_types::ClientTypes;
use exit_future::Signal;
use futures::{future::Future, Stream};
use network::Service as NetworkService;
use slog::{error, info, o};
use slot_clock::SlotClock;
use ssz::TreeHash;
use std::marker::PhantomData;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::TaskExecutor;
use tokio::timer::Interval;
use types::Hash256;

/// Main beacon node client service. This provides the connection and initialisation of the clients
/// sub-services in multiple threads.
pub struct Client<T: ClientTypes> {
    /// Configuration for the lighthouse client.
    config: ClientConfig,
    /// The beacon chain for the running client.
    beacon_chain: Arc<BeaconChain<T::DB, T::SlotClock, T::ForkChoice>>,
    /// Reference to the network service.
    pub network: Arc<NetworkService>,
    /// Signal to terminate the RPC server.
    pub rpc_exit_signal: Option<Signal>,
    /// Signal to terminate the slot timer.
    pub slot_timer_exit_signal: Option<Signal>,
    /// The clients logger.
    log: slog::Logger,
    /// Marker to pin the beacon chain generics.
    phantom: PhantomData<T>,
}

impl<TClientType: ClientTypes> Client<TClientType> {
    /// Generate an instance of the client. Spawn and link all internal sub-processes.
    pub fn new(
        config: ClientConfig,
        log: slog::Logger,
        executor: &TaskExecutor,
    ) -> error::Result<Self> {
        // generate a beacon chain
        let beacon_chain = TClientType::initialise_beacon_chain(&config);

        {
            let state = beacon_chain.state.read();
            let state_root = Hash256::from_slice(&state.hash_tree_root());
            info!(
                log,
                "ChainInitialized";
                "state_root" => format!("{}", state_root),
                "genesis_time" => format!("{}", state.genesis_time),
            );
        }

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

        let mut rpc_exit_signal = None;
        // spawn the RPC server
        if config.rpc_conf.enabled {
            rpc_exit_signal = Some(rpc::start_server(
                &config.rpc_conf,
                executor,
                network_send,
                beacon_chain.clone(),
                &log,
            ));
        }

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

            let state_slot = chain.state.read().slot;
            let wall_clock_slot = chain.read_slot_clock().unwrap();
            let slots_since_genesis = chain.slots_since_genesis().unwrap();
            info!(
                log,
                "Starting SlotTimer";
                "state_slot" => state_slot,
                "wall_clock_slot" => wall_clock_slot,
                "slots_since_genesis" => slots_since_genesis,
                "catchup_distance" => wall_clock_slot - state_slot,
            );
            executor.spawn(
                exit.until(
                    interval
                        .for_each(move |_| {
                            if let Some(genesis_height) = chain.slots_since_genesis() {
                                match chain.catchup_state() {
                                    Ok(_) => info!(
                                        log,
                                        "NewSlot";
                                        "slot" => chain.state.read().slot,
                                        "slots_since_genesis" => genesis_height,
                                    ),
                                    Err(e) => error!(
                                        log,
                                        "StateCatchupFailed";
                                        "state_slot" => chain.state.read().slot,
                                        "slots_since_genesis" => genesis_height,
                                        "error" => format!("{:?}", e),
                                    ),
                                };
                            }

                            Ok(())
                        })
                        .map_err(|_| ()),
                )
                .map(|_| ()),
            );
        }

        Ok(Client {
            config,
            beacon_chain,
            rpc_exit_signal,
            slot_timer_exit_signal: Some(slot_timer_exit_signal),
            log,
            network,
            phantom: PhantomData,
        })
    }
}
