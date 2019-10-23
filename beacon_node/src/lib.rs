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
use environment::RuntimeContext;
use futures::{Future, IntoFuture};
use genesis::{Eth1Config, Eth1GenesisService};
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::time::Duration;
use store::DiskStore;
use types::{BeaconState, EthSpec};

const ETH1_GENESIS_UPDATE_INTERVAL_MILLIS: u64 = 1_000;

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
    /// Identical to `start_from_client_config`, however the `client_config` is generated from the
    /// given `matches` and potentially configuration files on the local filesystem or other
    /// configurations hosted remotely.
    pub fn new_from_cli<'a, 'b>(
        context: RuntimeContext<E>,
        matches: &ArgMatches<'b>,
    ) -> impl Future<Item = Self, Error = String> + 'a {
        let log = context.log.clone();

        // FIXME: the eth2 config in the env is being completely ignored.
        get_configs(&matches, log).into_future().and_then(
            move |(client_config, eth2_config, _log)| {
                Self::with_eth1_connection(context, client_config, eth2_config)
            },
        )
    }

    pub fn with_eth1_connection<'a>(
        context: RuntimeContext<E>,
        client_config: ClientConfig,
        eth2_config: Eth2Config,
    ) -> impl Future<Item = Self, Error = String> + 'a {
        let genesis_context = context.service_context("eth1_genesis");

        let genesis_service = Eth1GenesisService::new(
            Eth1Config {
                block_cache_truncation: None,
                ..client_config.eth1.clone()
            },
            genesis_context.log,
        );

        genesis_service
            .wait_for_genesis_state(
                Duration::from_millis(ETH1_GENESIS_UPDATE_INTERVAL_MILLIS),
                eth2_config.spec.clone(),
            )
            .map_err(|e| format!("Unable to start beacon chain from eth1 node: {}", e))
            .and_then(move |genesis_state| {
                Self::from_genesis(context, genesis_state, client_config, eth2_config)
            })
    }

    /// Starts a new beacon node `Client` in the given `environment`.
    ///
    /// Client behaviour is defined by the given `client_config`.
    pub fn from_genesis(
        context: RuntimeContext<E>,
        genesis_state: BeaconState<E>,
        client_config: ClientConfig,
        eth2_config: Eth2Config,
    ) -> Result<Self, String> {
        let db_path: PathBuf = client_config
            .db_path()
            .ok_or_else(|| "Unable to access database path".to_string())?;

        let client = ClientBuilder::new(context.eth_spec_instance)
            .logger(context.log)
            .disk_store(&db_path)?
            .executor(context.executor)
            .beacon_genesis(genesis_state)?
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
