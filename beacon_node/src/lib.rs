#[macro_use]
extern crate clap;

mod cli;
mod config;

pub use beacon_chain;
pub use cli::cli_app;
pub use client::{Client, ClientBuilder, ClientConfig, ClientGenesis};
pub use eth2_config::Eth2Config;

use beacon_chain::{
    builder::Witness, eth1_chain::JsonRpcEth1Backend, events::WebSocketSender,
    lmd_ghost::ThreadSafeReducedTree, slot_clock::SystemTimeSlotClock,
};
use clap::ArgMatches;
use config::get_configs;
use environment::RuntimeContext;
use futures::{Future, IntoFuture};
use slog::{info, warn};
use std::ops::{Deref, DerefMut};
use store::DiskStore;
use types::EthSpec;

/// A type-alias to the tighten the definition of a production-intended `Client`.
pub type ProductionClient<E> = Client<
    Witness<
        DiskStore,
        SystemTimeSlotClock,
        ThreadSafeReducedTree<DiskStore, E>,
        JsonRpcEth1Backend<E>,
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
                Self::new(context, client_config, eth2_config)
            },
        )
    }

    /// Starts a new beacon node `Client` in the given `environment`.
    ///
    /// Client behaviour is defined by the given `client_config`.
    pub fn new(
        context: RuntimeContext<E>,
        client_config: ClientConfig,
        eth2_config: Eth2Config,
    ) -> impl Future<Item = Self, Error = String> {
        let http_eth2_config = eth2_config.clone();
        let genesis_eth1_config = client_config.eth1.clone();
        let client_genesis = client_config.genesis.clone();
        let log = context.log.clone();

        client_config
            .db_path()
            .ok_or_else(|| "Unable to access database path".to_string())
            .into_future()
            .and_then(move |db_path| {
                Ok(ClientBuilder::new(context.eth_spec_instance.clone())
                    .runtime_context(context)
                    .disk_store(&db_path)?
                    .chain_spec(eth2_config.spec.clone()))
            })
            .and_then(move |builder| {
                builder.beacon_chain_builder(client_genesis, genesis_eth1_config)
            })
            .and_then(move |builder| {
                let builder = if client_config.sync_eth1_chain && !client_config.dummy_eth1_backend
                {
                    builder.json_rpc_eth1_backend(client_config.eth1.clone())?
                } else if client_config.dummy_eth1_backend {
                    warn!(log, "Using the \"interop\" eth1 backend");
                    builder.dummy_eth1_backend()?
                } else {
                    info!(
                        log,
                        "Block production disabled";
                        "reason" => "no eth1 backend configured"
                    );
                    builder.no_eth1_backend()?
                };

                let builder = builder
                    .system_time_slot_clock()?
                    .websocket_event_handler(client_config.websocket_server.clone())?
                    .build_beacon_chain()?
                    .libp2p_network(&client_config.network)?
                    .http_server(&client_config, &http_eth2_config)?
                    .grpc_server(&client_config.rpc)?
                    .peer_count_notifier()?
                    .slot_notifier()?;

                Ok(Self(builder.build()))
            })
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
