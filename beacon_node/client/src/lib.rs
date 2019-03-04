extern crate slog;

mod client_config;

pub mod client_types;
pub mod error;
pub mod notifier;

pub use client_config::ClientConfig;
pub use client_types::ClientTypes;

//use beacon_chain::BeaconChain;
use exit_future::{Exit, Signal};
use std::marker::PhantomData;
//use std::sync::Arc;
use network::NetworkService;
use tokio::runtime::TaskExecutor;

/// Main beacon node client service. This provides the connection and initialisation of the clients
/// sub-services in multiple threads.
pub struct Client<T: ClientTypes> {
    config: ClientConfig,
    // beacon_chain: Arc<BeaconChain<T, U, F>>,
    network: Option<Arc<NetworkService>>,
    exit: exit_future::Exit,
    exit_signal: Option<Signal>,
    log: slog::Logger,
    phantom: PhantomData<T>,
}

impl<T: ClientTypes> Client<T> {
    /// Generate an instance of the client. Spawn and link all internal subprocesses.
    pub fn new(
        config: ClientConfig,
        log: slog::Logger,
        executor: TaskExecutor,
    ) -> error::Result<Self> {
        let (exit_signal, exit) = exit_future::signal();

        // TODO: generate a beacon_chain service.

        // start the network service, libp2p and syncing threads
        // TODO: Add beacon_chain reference to network parameters
        let network_config = config.net_config;
        let network_logger = client.log.new(o!("Service" => "Network"));
        let (network, network_send) = NetworkService::new(network_config, network_logger);

        Ok(Client {
            config,
            exit,
            exit_signal: Some(exit_signal),
            log,
            network: Some(network),
            phantom: PhantomData,
        })
    }
}
