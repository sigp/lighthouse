//! This crate provides a HTTP server that is solely dedicated to serving the `/metrics` endpoint.
//!
//! For other endpoints, see the `http_api` crate.
mod metrics;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_version::version_with_platform;
use serde::{Deserialize, Serialize};
use slog::{crit, info, Logger};
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::path::PathBuf;
use std::sync::Arc;
use warp::{http::Response, Filter};

#[derive(Debug)]
pub enum Error {
    Warp(warp::Error),
    Other(String),
}

impl From<warp::Error> for Error {
    fn from(e: warp::Error) -> Self {
        Error::Warp(e)
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Other(e)
    }
}

/// A wrapper around all the items required to spawn the HTTP server.
///
/// The server will gracefully handle the case where any fields are `None`.
pub struct Context<T: BeaconChainTypes> {
    pub config: Config,
    pub chain: Option<Arc<BeaconChain<T>>>,
    pub db_path: Option<PathBuf>,
    pub freezer_db_path: Option<PathBuf>,
    pub log: Logger,
}

/// Configuration for the HTTP server.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    pub listen_addr: Ipv4Addr,
    pub listen_port: u16,
    pub allow_origin: Option<String>,
    pub allocator_metrics_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: Ipv4Addr::new(127, 0, 0, 1),
            listen_port: 5054,
            allow_origin: None,
            allocator_metrics_enabled: true,
        }
    }
}

/// Creates a server that will serve requests using information from `ctx`.
///
/// The server will shut down gracefully when the `shutdown` future resolves.
///
/// ## Returns
///
/// This function will bind the server to the provided address and then return a tuple of:
///
/// - `SocketAddr`: the address that the HTTP server will listen on.
/// - `Future`: the actual server future that will need to be awaited.
///
/// ## Errors
///
/// Returns an error if the server is unable to bind or there is another error during
/// configuration.
pub fn serve<T: BeaconChainTypes>(
    ctx: Arc<Context<T>>,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()>), Error> {
    let config = &ctx.config;
    let log = ctx.log.clone();

    // Configure CORS.
    let cors_builder = {
        let builder = warp::cors()
            .allow_method("GET")
            .allow_headers(vec!["Content-Type"]);

        warp_utils::cors::set_builder_origins(
            builder,
            config.allow_origin.as_deref(),
            (config.listen_addr, config.listen_port),
        )?
    };

    // Sanity check.
    if !config.enabled {
        crit!(log, "Cannot start disabled metrics HTTP server");
        return Err(Error::Other(
            "A disabled metrics server should not be started".to_string(),
        ));
    }

    let inner_ctx = ctx.clone();
    let routes = warp::get()
        .and(warp::path("metrics"))
        .map(move || inner_ctx.clone())
        .and_then(|ctx: Arc<Context<T>>| async move {
            Ok::<_, warp::Rejection>(
                metrics::gather_prometheus_metrics(&ctx)
                    .map(|body| Response::builder().status(200).body(body).unwrap())
                    .unwrap_or_else(|e| {
                        Response::builder()
                            .status(500)
                            .header("Content-Type", "text/plain")
                            .body(format!("Unable to gather metrics: {:?}", e))
                            .unwrap()
                    }),
            )
        })
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", &version_with_platform()))
        .with(cors_builder.build());

    let (listening_socket, server) = warp::serve(routes).try_bind_with_graceful_shutdown(
        SocketAddrV4::new(config.listen_addr, config.listen_port),
        async {
            shutdown.await;
        },
    )?;

    info!(
        log,
        "Metrics HTTP server started";
        "listen_address" => listening_socket.to_string(),
    );

    Ok((listening_socket, server))
}
