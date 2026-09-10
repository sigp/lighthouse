//! This crate provides a HTTP server that is solely dedicated to serving the `/metrics` endpoint.
//!
//! For other endpoints, see the `http_api` crate.

use axum::{
    Router,
    extract::State,
    http::{Method, StatusCode, header},
    response::IntoResponse,
    routing::get,
};
use axum_utils::{Server, cors::build_cors_layer, middleware::add_server_header};
use lighthouse_validator_store::LighthouseValidatorStore;
use logging::crit;
use malloc_utils::scrape_allocator_metrics;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use slot_clock::{SlotClock, SystemTimeSlotClock};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info};
use types::EthSpec;
use validator_services::duties_service::DutiesService;

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

type ValidatorStore<E> = LighthouseValidatorStore<SystemTimeSlotClock, E>;

/// Contains objects which have shared access from inside/outside of the metrics server.
pub struct Shared<E> {
    pub validator_store: Option<Arc<ValidatorStore<E>>>,
    pub duties_service: Option<Arc<DutiesService<ValidatorStore<E>, SystemTimeSlotClock>>>,
    pub genesis_time: Option<u64>,
}

/// A wrapper around all the items required to spawn the HTTP server.
///
/// The server will gracefully handle the case where any fields are `None`.
pub struct Context<E> {
    pub config: Config,
    pub shared: RwLock<Shared<E>>,
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
            listen_port: 5064,
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
pub async fn serve<E: EthSpec>(
    ctx: Arc<Context<E>>,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()>), Error> {
    let config = &ctx.config;

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
        .route("/metrics", get(metrics_handler::<E>))
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

async fn metrics_handler<E: EthSpec>(State(ctx): State<Arc<Context<E>>>) -> impl IntoResponse {
    match gather_prometheus_metrics(&ctx) {
        Ok(body) => (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain")], body),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            [(header::CONTENT_TYPE, "text/plain")],
            format!("Unable to gather metrics: {:?}", e),
        ),
    }
}

pub fn gather_prometheus_metrics<E: EthSpec>(
    ctx: &Context<E>,
) -> std::result::Result<String, String> {
    use validator_metrics::*;
    let mut buffer = vec![];
    let encoder = TextEncoder::new();

    {
        let shared = ctx.shared.read();

        if let Some(genesis_time) = shared.genesis_time
            && let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH)
        {
            let distance = now.as_secs() as i64 - genesis_time as i64;
            set_gauge(&GENESIS_DISTANCE, distance);
        }

        if let Some(duties_service) = &shared.duties_service
            && let Some(slot) = duties_service.slot_clock.now()
        {
            let current_epoch = slot.epoch(E::slots_per_epoch());
            let next_epoch = current_epoch + 1;

            set_int_gauge(
                &PROPOSER_COUNT,
                &[CURRENT_EPOCH],
                duties_service.proposer_count(current_epoch) as i64,
            );
            set_int_gauge(
                &ATTESTER_COUNT,
                &[CURRENT_EPOCH],
                duties_service.attester_count(current_epoch) as i64,
            );
            set_int_gauge(
                &ATTESTER_COUNT,
                &[NEXT_EPOCH],
                duties_service.attester_count(next_epoch) as i64,
            );
            set_int_gauge(
                &PTC_COUNT,
                &[CURRENT_EPOCH],
                duties_service.ptc_count(current_epoch) as i64,
            );
            set_int_gauge(
                &PTC_COUNT,
                &[NEXT_EPOCH],
                duties_service.ptc_count(next_epoch) as i64,
            );
        }
    }

    // It's important to ensure these metrics are explicitly enabled in the case that users aren't
    // using glibc and this function causes panics.
    if ctx.config.allocator_metrics_enabled {
        scrape_allocator_metrics();
    }

    health_metrics::metrics::scrape_health_metrics();

    encoder
        .encode(&metrics::gather(), &mut buffer)
        .map_err(|e| format!("{e:?}"))?;

    String::from_utf8(buffer).map_err(|e| format!("Failed to encode prometheus info: {:?}", e))
}
