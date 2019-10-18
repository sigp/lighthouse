#[macro_use]
extern crate clap;

mod cli;
mod config;

pub use beacon_chain;
pub use cli::cli_app;
pub use client::{Client, ClientBuilder, ClientConfig};
pub use eth2_config::Eth2Config;

use beacon_chain::{
    builder::Witness, eth1_chain::InteropEth1ChainBackend, events::WebSocketSender,
    lmd_ghost::ThreadSafeReducedTree, slot_clock::SystemTimeSlotClock,
};
use clap::ArgMatches;
use config::get_configs;
use environment::Environment;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use store::DiskStore;
use types::EthSpec;

/// A type-alias to the tighten the definition of a production-intended `Client`.
pub type ProductionClient<E> = Client<
    Witness<
        DiskStore,
        SystemTimeSlotClock,
        ThreadSafeReducedTree<DiskStore, E>,
        InteropEth1ChainBackend<E>,
        E,
        WebSocketSender<E>,
    >,
>;

/// The beacon node `Client` that will be used in production.
///
/// Generic over some `EthSpec`.
///
/// ## Notes:
///
/// Despite being titled `Production...`, this code is not ready for production. The name
/// demonstrates an intention, not a promise.
pub struct ProductionBeaconNode<E: EthSpec>(ProductionClient<E>);

impl<E: EthSpec> ProductionBeaconNode<E> {
    /// Starts a new beacon node `Client` in the given `environment`.
    ///
    /// Client behaviour is defined by the given `client_config`.
    pub fn new(
        environment: &Environment<E>,
        client_config: ClientConfig,
        eth2_config: Eth2Config,
    ) -> Result<Self, String> {
        let log = environment.beacon_node_log();

        let db_path: PathBuf = client_config
            .db_path()
            .ok_or_else(|| "Unable to access database path".to_string())?;

        let client = ClientBuilder::new(environment.eth_spec_instance().clone())
            .logger(log.clone())
            .disk_store(&db_path)?
            .executor(environment.executor())
            .beacon_checkpoint(&client_config.beacon_chain_start_method)?
            .system_time_slot_clock()?
            .dummy_eth1_backend()
            .websocket_event_handler(client_config.websocket_server.clone())?
            .beacon_chain()?
            .libp2p_network(&client_config.network)?
            .http_server(&client_config, &eth2_config)?
            .grpc_server(&client_config.rpc)?
            .peer_count_notifier()?
            .slot_notifier()?
            .build();

        Ok(Self(client))
    }

    /// Starts a new beacon node `Client` in the given `environment`.
    ///
    /// Identical to `start_from_client_config`, however the `client_config` is generated from the
    /// given `matches` and potentially configuration files on the local filesystem or other
    /// configurations hosted remotely.
    pub fn new_from_cli<'a>(
        matches: &ArgMatches<'a>,
        environment: &Environment<E>,
    ) -> Result<ProductionBeaconNode<E>, String> {
        let log = environment.beacon_node_log();

        // FIXME: the eth2 config in the env is being completely ignored.
        let (client_config, eth2_config, _log) = get_configs(&matches, log)?;

        Self::new(environment, client_config, eth2_config)
    }

    pub fn into_inner(self) -> ProductionClient<E> {
        self.0
    }
}

impl<E: EthSpec> Deref for ProductionBeaconNode<E> {
    type Target = ProductionClient<E>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<E: EthSpec> DerefMut for ProductionBeaconNode<E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
