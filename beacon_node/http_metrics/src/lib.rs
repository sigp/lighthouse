//! This crate provides a HTTP server that is solely dedicated to serving the `/metrics` endpoint.
//!
//! For other endpoints, see the `http_api` crate.
mod metrics;

use axum::{
    Router,
    extract::State,
    http::{Method, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use axum_utils::{Server, cors::build_cors_layer, middleware::add_server_header};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use lighthouse_network::prometheus_client::registry::Registry;
use logging::crit;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Builder error: {0}")]
    Builder(#[from] axum_utils::server::BuilderError),
    #[error("Server error: {0}")]
    Server(#[from] axum_utils::server::ServerError),
    #[error("CORS error: {0}")]
    Cors(#[from] axum_utils::cors::CorsError),
    #[error("{0}")]
    Other(String),
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
    pub gossipsub_registry: Option<std::sync::Mutex<Registry>>,
}

/// Configuration for the HTTP server.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub enabled: bool,
    pub listen_addr: IpAddr,
    pub listen_port: u16,
    pub allow_origin: Option<String>,
    pub allocator_metrics_enabled: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
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
pub async fn serve<T: BeaconChainTypes>(
    ctx: Arc<Context<T>>,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()>), Error> {
    let config = &ctx.config;

    // Sanity check.
    if !config.enabled {
        crit!("Cannot start disabled metrics HTTP server");
        return Err(Error::Other(
            "A disabled metrics server should not be started".to_string(),
        ));
    }

    let cors_layer = build_cors_layer(
        config.allow_origin.as_deref(),
        config.listen_addr,
        config.listen_port,
    )?
    .allow_methods([Method::GET])
    .allow_headers([header::CONTENT_TYPE]);

    let server_header: header::HeaderValue = lighthouse_version::version_with_platform()
        .parse()
        .map_err(|e| Error::Other(format!("invalid version header value: {e}")))?;

    let router = Router::new()
        .route("/metrics", get(metrics_handler::<T>))
        .with_state(ctx.clone())
        .layer(add_server_header(server_header))
        .layer(cors_layer);

    let address = SocketAddr::new(config.listen_addr, config.listen_port);
    let server = Server::builder(router, address).build().await?;

    let (address, server) = server.serve_with_shutdown(shutdown).await?;

    info!(
        listen_address = %address,
        "Metrics HTTP server started"
    );

    let server_future = async move {
        if let Err(e) = server.await {
            error!(error = ?e, "Metrics HTTP server error");
        }
    };

    Ok((address, server_future))
}

async fn metrics_handler<T: BeaconChainTypes>(
    State(ctx): State<Arc<Context<T>>>,
) -> impl IntoResponse {
    match metrics::gather_prometheus_metrics(&ctx) {
        Ok(body) => (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain")], body),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain")],
            format!("Unable to gather metrics: {:?}", e),
        ),
    }
}
