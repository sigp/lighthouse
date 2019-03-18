extern crate slog;

mod client_config;

pub mod client_types;
pub mod error;
pub mod notifier;

pub use client_config::ClientConfig;
pub use client_types::ClientTypes;

//use beacon_chain::BeaconChain;
use beacon_chain::BeaconChain;
use exit_future::{Exit, Signal};
use network::Service as NetworkService;
use slog::o;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::runtime::TaskExecutor;

/// Main beacon node client service. This provides the connection and initialisation of the clients
/// sub-services in multiple threads.
pub struct Client<T: ClientTypes> {
    /// Configuration for the lighthouse client.
    config: ClientConfig,
    /// The beacon chain for the running client.
    beacon_chain: Arc<BeaconChain<T::DB, T::SlotClock, T::ForkChoice>>,
    /// Reference to the network service.
    pub network: Arc<NetworkService>,
    /// Future to stop and begin shutdown of the Client.
    //TODO: Decide best way to handle shutdown
    pub exit: exit_future::Exit,
    /// The sending future to call to terminate the Client.
    //TODO: Decide best way to handle shutdown
    pub exit_signal: Signal,
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
        let (exit_signal, exit) = exit_future::signal();

        // generate a beacon chain
        let beacon_chain = TClientType::initialise_beacon_chain(&config);

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

        Ok(Client {
            config,
            beacon_chain,
            exit,
            exit_signal: exit_signal,
            log,
            network: network,
            phantom: PhantomData,
        })
    }
}
