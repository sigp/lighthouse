extern crate slog;

mod address_change_broadcast;
pub mod config;
mod metrics;
mod notifier;

pub mod builder;
pub mod error;

use beacon_chain::BeaconChain;
use lighthouse_network::{Enr, Multiaddr, NetworkGlobals};
use std::net::SocketAddr;
use std::sync::Arc;

pub use beacon_chain::{BeaconChainTypes, Eth1ChainBackend};
pub use builder::ClientBuilder;
pub use config::{ClientGenesis, Config as ClientConfig};
pub use eth2_config::Eth2Config;

/// The core "beacon node" client.
///
/// Holds references to running services, cleanly shutting them down when dropped.
pub struct Client<T: BeaconChainTypes> {
    beacon_chain: Option<Arc<BeaconChain<T>>>,
    network_globals: Option<Arc<NetworkGlobals<T::EthSpec>>>,
    /// Listen address for the standard eth2.0 API, if the service was started.
    http_api_listen_addr: Option<SocketAddr>,
    /// Listen address for the HTTP server which serves Prometheus metrics.
    http_metrics_listen_addr: Option<SocketAddr>,
}

impl<T: BeaconChainTypes> Client<T> {
    /// Returns an `Arc` reference to the client's `BeaconChain`, if it was started.
    pub fn beacon_chain(&self) -> Option<Arc<BeaconChain<T>>> {
        self.beacon_chain.clone()
    }

    /// Returns the address of the client's standard eth2.0 API server, if it was started.
    pub fn http_api_listen_addr(&self) -> Option<SocketAddr> {
        self.http_api_listen_addr
    }

    /// Returns the address of the client's HTTP Prometheus metrics server, if it was started.
    pub fn http_metrics_listen_addr(&self) -> Option<SocketAddr> {
        self.http_metrics_listen_addr
    }

    /// Returns the list of libp2p addresses the client is listening to.
    pub fn libp2p_listen_addresses(&self) -> Option<Vec<Multiaddr>> {
        self.network_globals.as_ref().map(|n| n.listen_multiaddrs())
    }

    /// Returns the local libp2p ENR of this node, for network discovery.
    pub fn enr(&self) -> Option<Enr> {
        self.network_globals.as_ref().map(|n| n.local_enr())
    }
}
