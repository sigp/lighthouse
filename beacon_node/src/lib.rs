#[macro_use]
extern crate clap;

mod cli;
mod config;

pub use beacon_chain;
use beacon_chain::store::LevelDB;
use beacon_chain::{
    builder::Witness, eth1_chain::CachingEth1Backend, slot_clock::SystemTimeSlotClock,
    TimeoutRwLock,
};
use clap::ArgMatches;
pub use cli::cli_app;
pub use client::{Client, ClientBuilder, ClientConfig, ClientGenesis};
pub use config::{get_config, get_data_dir, get_slots_per_restore_point, set_network_config};
use environment::RuntimeContext;
pub use eth2_config::Eth2Config;
use slasher::Slasher;
use slog::{info, warn};
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use types::EthSpec;

/// A type-alias to the tighten the definition of a production-intended `Client`.
pub type ProductionClient<E> =
    Client<Witness<SystemTimeSlotClock, CachingEth1Backend<E>, E, LevelDB<E>, LevelDB<E>>>;

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
        matches: ArgMatches<'static>,
    ) -> Result<Self, String> {
        let client_config = get_config::<E>(&matches, &context)?;
        Self::new(context, client_config).await
    }

    /// Starts a new beacon node `Client` in the given `environment`.
    ///
    /// Client behaviour is defined by the given `client_config`.
    pub async fn new(
        context: RuntimeContext<E>,
        mut client_config: ClientConfig,
    ) -> Result<Self, String> {
        let spec = context.eth2_config().spec.clone();
        let client_genesis = client_config.genesis.clone();
        let store_config = client_config.store.clone();
        let log = context.log().clone();
        let _datadir = client_config.create_data_dir()?;
        let db_path = client_config.create_db_path()?;
        let freezer_db_path = client_config.create_freezer_db_path()?;
        let blobs_db_path = client_config.create_blobs_db_path()?;
        let executor = context.executor.clone();

        if let Some(legacy_dir) = client_config.get_existing_legacy_data_dir() {
            warn!(
                log,
                "Legacy datadir location";
                "msg" => "this occurs when using relative paths for a datadir location",
                "location" => ?legacy_dir,
            )
        }

        if !client_config.chain.enable_lock_timeouts {
            info!(log, "Disabling lock timeouts globally");
            TimeoutRwLock::disable_timeouts()
        }

        let builder = ClientBuilder::new(context.eth_spec_instance.clone())
            .runtime_context(context)
            .chain_spec(spec)
            .http_api_config(client_config.http_api.clone())
            .disk_store(
                &db_path,
                &freezer_db_path,
                blobs_db_path,
                store_config,
                log.clone(),
            )?;

        let builder = if let Some(slasher_config) = client_config.slasher.clone() {
            let slasher = Arc::new(
                Slasher::open(slasher_config, log.new(slog::o!("service" => "slasher")))
                    .map_err(|e| format!("Slasher open error: {:?}", e))?,
            );
            builder.slasher(slasher)
        } else {
            builder
        };

        let builder = if let Some(monitoring_config) = &mut client_config.monitoring_api {
            monitoring_config.db_path = Some(db_path);
            monitoring_config.freezer_db_path = Some(freezer_db_path);
            builder.monitoring_client(monitoring_config)?
        } else {
            builder
        };

        let builder = builder
            .beacon_chain_builder(client_genesis, client_config.clone())
            .await?;
        let builder = if client_config.sync_eth1_chain && !client_config.dummy_eth1_backend {
            info!(
                log,
                "Block production enabled";
                "endpoint" => format!("{:?}", &client_config.eth1.endpoint),
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

        let builder = builder.system_time_slot_clock()?;

        // Inject the executor into the discv5 network config.
        let discv5_executor = Discv5Executor(executor);
        client_config.network.discv5_config.executor = Some(Box::new(discv5_executor));

        builder
            .build_beacon_chain()?
            .network(&client_config.network)
            .await?
            .notifier()?
            .http_metrics_config(client_config.http_metrics.clone())
            .build()
            .map(Self)
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

// Implements the Discv5 Executor trait over our global executor
#[derive(Clone)]
struct Discv5Executor(task_executor::TaskExecutor);

impl lighthouse_network::discv5::Executor for Discv5Executor {
    fn spawn(&self, future: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>) {
        self.0.spawn(future, "discv5")
    }
}
