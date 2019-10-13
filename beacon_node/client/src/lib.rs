extern crate slog;

mod config;

pub mod builder;
pub mod error;

use beacon_chain::BeaconChain;
use exit_future::Signal;
use network::Service as NetworkService;
use std::sync::Arc;

pub use beacon_chain::{BeaconChainTypes, Eth1ChainBackend, InteropEth1ChainBackend};
pub use config::{Config as ClientConfig, Eth1BackendMethod};
pub use eth2_config::Eth2Config;

/// The core "beacon node" client.
///
/// Holds references to running services, cleanly shutting them down when it is dropped.
pub struct Client<T: BeaconChainTypes> {
    beacon_chain: Option<Arc<BeaconChain<T>>>,
    _libp2p_network: Option<Arc<NetworkService<T>>>,
    _exit_signals: Vec<Signal>,
}

impl<T: BeaconChainTypes> Drop for Client<T> {
    fn drop(&mut self) {
        if let Some(beacon_chain) = &self.beacon_chain {
            let _result = beacon_chain.persist();
        }
    }
}
