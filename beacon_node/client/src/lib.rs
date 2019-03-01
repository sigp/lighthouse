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
use tokio::runtime::TaskExecutor;

//use network::NetworkService;

pub struct Client<T: ClientTypes> {
    config: ClientConfig,
    // beacon_chain: Arc<BeaconChain<T, U, F>>,
    // network: Option<Arc<NetworkService>>,
    exit: exit_future::Exit,
    exit_signal: Option<Signal>,
    log: slog::Logger,
    phantom: PhantomData<T>,
}

impl<T: ClientTypes> Client<T> {
    pub fn new(
        config: ClientConfig,
        log: slog::Logger,
        executor: TaskExecutor,
    ) -> error::Result<Self> {
        let (exit_signal, exit) = exit_future::signal();

        Ok(Client {
            config,
            exit,
            exit_signal: Some(exit_signal),
            log,
            phantom: PhantomData,
        })
    }

    pub fn logger(&self) -> slog::Logger {
        self.log.clone()
    }
}
