#[macro_use]
extern crate clap;

mod cli;
mod config;

pub use beacon_chain;
pub use cli::cli_app;
pub use client::{Client, ClientBuilder, ClientConfig, ClientGenesis};
pub use config::{get_data_dir, get_eth2_testnet_config, set_network_config};
pub use eth2_config::Eth2Config;

use beacon_chain::events::TeeEventHandler;
use beacon_chain::migrate::BackgroundMigrator;
use beacon_chain::store::LevelDB;
use beacon_chain::{
    builder::Witness, eth1_chain::CachingEth1Backend, slot_clock::SystemTimeSlotClock,
};
use clap::ArgMatches;
use config::get_config;
use environment::RuntimeContext;
use slog::{info, warn};
use std::ops::{Deref, DerefMut};
use types::EthSpec;

/// A type-alias to the tighten the definition of a production-intended `Client`.
pub type ProductionClient<E> = Client<
    Witness<
        BackgroundMigrator<E, LevelDB<E>, LevelDB<E>>,
        SystemTimeSlotClock,
        CachingEth1Backend<E>,
        E,
        TeeEventHandler<E>,
        LevelDB<E>,
        LevelDB<E>,
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
    pub async fn new_from_cli(
        context: RuntimeContext<E>,
        matches: &ArgMatches<'_>,
    ) -> Result<Self, String> {
        let client_config = get_config::<E>(
            &matches,
            &context.eth2_config.spec_constants,
            &context.eth2_config().spec,
            context.log().clone(),
        )?;
        Self::new(context, client_config).await
    }

    /// Starts a new beacon node `Client` in the given `environment`.
    ///
    /// Client behaviour is defined by the given `client_config`.
    pub async fn new(
        context: RuntimeContext<E>,
        mut client_config: ClientConfig,
    ) -> Result<Self, String> {
        let http_eth2_config = context.eth2_config().clone();
        let spec = context.eth2_config().spec.clone();
        let client_config_1 = client_config.clone();
        let client_genesis = client_config.genesis.clone();
        let store_config = client_config.store.clone();
        let log = context.log().clone();

        let db_path = client_config.create_db_path()?;
        let freezer_db_path_res = client_config.create_freezer_db_path();

        let executor = context.executor.clone();

        let builder = ClientBuilder::new(context.eth_spec_instance.clone())
            .runtime_context(context)
            .chain_spec(spec)
            .disk_store(&db_path, &freezer_db_path_res?, store_config)?
            .background_migrator()?;

        let builder = builder
            .beacon_chain_builder(client_genesis, client_config_1)
            .await?;
        let builder = if client_config.sync_eth1_chain && !client_config.dummy_eth1_backend {
            info!(
                log,
                "Block production enabled";
                "endpoint" => &client_config.eth1.endpoint,
                "method" => "json rpc via http"
            );
            builder
                .caching_eth1_backend(client_config.eth1.clone())
                .await?
        } else if client_config.dummy_eth1_backend {
            warn!(
                log,
                "Block production impaired";
                "reason" => "dummy eth1 backend is enabled"
            );
            builder.dummy_eth1_backend()?
        } else {
            info!(
                log,
                "Block production disabled";
                "reason" => "no eth1 backend configured"
            );
            builder.no_eth1_backend()?
        };

        let (builder, events) = builder
            .system_time_slot_clock()?
            .tee_event_handler(client_config.websocket_server.clone())?;

        // Inject the executor into the discv5 network config.
        client_config.network.discv5_config.executor = Some(Box::new(executor));

        let builder = builder
            .build_beacon_chain()?
            .network(&client_config.network)
            .await?
            .notifier()?;

        let builder = if client_config.rest_api.enabled {
            builder.http_server(&client_config, &http_eth2_config, events)?
        } else {
            builder
        };

        Ok(Self(builder.build()))
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
