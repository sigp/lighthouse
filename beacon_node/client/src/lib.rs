extern crate slog;

mod client_config;

pub mod client_types;
pub mod error;
pub mod notifier;

pub use client_config::ClientConfig;
pub use client_types::ClientTypes;

//use beacon_chain::BeaconChain;
use exit_future::{Exit, Signal};
use network::Service as NetworkService;
use slog::o;
use std::marker::PhantomData;
use std::sync::Arc;
use tokio::runtime::TaskExecutor;

/// Main beacon node client service. This provides the connection and initialisation of the clients
/// sub-services in multiple threads.
pub struct Client<T: ClientTypes> {
    config: ClientConfig,
    // beacon_chain: Arc<BeaconChain<T, U, F>>,
    pub network: Arc<NetworkService>,
    pub exit: exit_future::Exit,
    pub exit_signal: Signal,
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

        // Start the network service, libp2p and syncing threads
        // TODO: Add beacon_chain reference to network parameters
        let network_config = config.net_conf.clone();
        let network_logger = log.new(o!("Service" => "Network"));
        let (network, network_send) =
            NetworkService::new(network_config, executor, network_logger)?;

        Ok(Client {
            config,
            exit,
            exit_signal: exit_signal,
            log,
            network: network,
            phantom: PhantomData,
        })
    }
}
