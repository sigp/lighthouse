mod api;
mod key;
mod metrics;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use clap::ArgMatches;
use futures::Future;
use iron::prelude::*;
use network::NetworkMessage;
use prometheus::Registry;
use router::Router;
use serde_derive::{Deserialize, Serialize};
use slog::{info, o, warn};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::TaskExecutor;
use tokio::sync::mpsc;

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct HttpServerConfig {
    pub enabled: bool,
    pub listen_address: String,
    pub listen_port: String,
}

impl Default for HttpServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_address: "127.0.0.1".to_string(),
            listen_port: "5052".to_string(),
        }
    }
}

impl HttpServerConfig {
    pub fn apply_cli_args(&mut self, args: &ArgMatches) -> Result<(), &'static str> {
        if args.is_present("http") {
            self.enabled = true;
        }

        if let Some(listen_address) = args.value_of("http-address") {
            self.listen_address = listen_address.to_string();
        }

        if let Some(listen_port) = args.value_of("http-port") {
            self.listen_port = listen_port.to_string();
        }

        Ok(())
    }
}

/// Build the `iron` HTTP server, defining the core routes.
pub fn create_iron_http_server<T: BeaconChainTypes + 'static>(
    beacon_chain: Arc<BeaconChain<T>>,
    db_path: PathBuf,
    metrics_registry: Registry,
) -> Iron<Router> {
    let mut router = Router::new();

    // A `GET` request to `/metrics` is handled by the `metrics` module.
    router.get(
        "/metrics",
        metrics::build_handler(beacon_chain.clone(), db_path, metrics_registry),
        "metrics",
    );

    // Any request to all other endpoints is handled by the `api` module.
    router.any("/*", api::build_handler(beacon_chain.clone()), "api");

    Iron::new(router)
}

/// Start the HTTP service on the tokio `TaskExecutor`.
pub fn start_service<T: BeaconChainTypes + 'static>(
    config: &HttpServerConfig,
    executor: &TaskExecutor,
    _network_chan: mpsc::UnboundedSender<NetworkMessage<T::EthSpec>>,
    beacon_chain: Arc<BeaconChain<T>>,
    db_path: PathBuf,
    metrics_registry: Registry,
    log: &slog::Logger,
) -> exit_future::Signal {
    let log = log.new(o!("Service"=>"HTTP"));

    // Create:
    //  - `shutdown_trigger` a one-shot to shut down this service.
    //  - `wait_for_shutdown` a future that will wait until someone calls shutdown.
    let (shutdown_trigger, wait_for_shutdown) = exit_future::signal();

    // Create an `iron` http, without starting it yet.
    let iron = create_iron_http_server(beacon_chain, db_path, metrics_registry);

    // Create a HTTP server future.
    //
    // 1. Start the HTTP server
    // 2. Build an exit future that will shutdown the server when requested.
    // 3. Return the exit future, so the caller may shutdown the service when desired.
    let http_service = {
        let listen_address = format!("{}:{}", config.listen_address, config.listen_port);
        // Start the HTTP server
        let server_start_result = iron.http(listen_address.clone());

        if server_start_result.is_ok() {
            info!(log, "HTTP server running on {}", listen_address);
        } else {
            warn!(log, "HTTP server failed to start on {}", listen_address);
        }

        // Build a future that will shutdown the HTTP server when the `shutdown_trigger` is
        // triggered.
        wait_for_shutdown.and_then(move |_| {
            info!(log, "HTTP server shutting down");

            if let Ok(mut server) = server_start_result {
                // According to the documentation, `server.close()` "doesn't work" and the server
                // keeps listening.
                //
                // It is being called anyway, because it seems like the right thing to do. If you
                // know this has negative side-effects, please create an issue to discuss.
                //
                // See: https://docs.rs/iron/0.6.0/iron/struct.Listening.html#impl
                match server.close() {
                    _ => (),
                };
            }
            info!(log, "HTTP server shutdown complete.");
            Ok(())
        })
    };

    // Attach the HTTP server to the executor.
    executor.spawn(http_service);

    shutdown_trigger
}

/// Helper function for mapping a failure to read state to a 500 server error.
fn map_persistent_err_to_500(e: persistent::PersistentError) -> iron::error::IronError {
    iron::error::IronError {
        error: Box::new(e),
        response: iron::Response::with(iron::status::Status::InternalServerError),
    }
}
