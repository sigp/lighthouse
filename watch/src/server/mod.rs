use crate::block_packing::block_packing_routes;
use crate::block_rewards::block_rewards_routes;
use crate::blockprint::blockprint_routes;
use crate::config::Config as FullConfig;
use crate::database::{self, PgPool};
use crate::suboptimal_attestations::{attestation_routes, blockprint_attestation_routes};
use axum::{
    handler::Handler,
    http::{StatusCode, Uri},
    routing::get,
    Extension, Json, Router,
};
use eth2::types::ErrorMessage;
use log::info;
use std::future::Future;
use std::net::SocketAddr;
use tokio::sync::oneshot;

pub use config::Config;
pub use error::Error;

mod config;
mod error;
mod handler;

pub async fn serve(config: FullConfig, shutdown: oneshot::Receiver<()>) -> Result<(), Error> {
    let db = database::build_connection_pool(&config.database)?;
    let (_, slots_per_epoch) = database::get_active_config(&mut database::get_connection(&db)?)?
        .ok_or_else(|| {
            Error::Other(
                "Database not found. Please run the updater prior to starting the server"
                    .to_string(),
            )
        })?;

    let server = start_server(&config, slots_per_epoch as u64, db, async {
        let _ = shutdown.await;
    })?;

    server.await?;

    Ok(())
}

/// Creates a server that will serve requests using information from `config`.
///
/// The server will create its own connection pool to serve connections to the database.
/// This is separate to the connection pool that is used for the `updater`.
///
/// The server will shut down gracefully when the `shutdown` future resolves.
///
/// ## Returns
///
/// This function will bind the server to the address specified in the config and then return a
/// Future representing the actual server that will need to be awaited.
///
/// ## Errors
///
/// Returns an error if the server is unable to bind or there is another error during
/// configuration.
pub fn start_server(
    config: &FullConfig,
    slots_per_epoch: u64,
    pool: PgPool,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> Result<impl Future<Output = Result<(), hyper::Error>> + 'static, Error> {
    let mut routes = Router::new()
        .route("/v1/slots", get(handler::get_slots_by_range))
        .route("/v1/slots/:slot", get(handler::get_slot))
        .route("/v1/slots/lowest", get(handler::get_slot_lowest))
        .route("/v1/slots/highest", get(handler::get_slot_highest))
        .route("/v1/slots/:slot/block", get(handler::get_block))
        .route("/v1/blocks", get(handler::get_blocks_by_range))
        .route("/v1/blocks/:block", get(handler::get_block))
        .route("/v1/blocks/lowest", get(handler::get_block_lowest))
        .route("/v1/blocks/highest", get(handler::get_block_highest))
        .route(
            "/v1/blocks/:block/previous",
            get(handler::get_block_previous),
        )
        .route("/v1/blocks/:block/next", get(handler::get_block_next))
        .route(
            "/v1/blocks/:block/proposer",
            get(handler::get_block_proposer),
        )
        .route("/v1/validators/:validator", get(handler::get_validator))
        .route("/v1/validators/all", get(handler::get_all_validators))
        .route(
            "/v1/validators/:validator/latest_proposal",
            get(handler::get_validator_latest_proposal),
        )
        .route("/v1/clients", get(handler::get_client_breakdown))
        .route(
            "/v1/clients/percentages",
            get(handler::get_client_breakdown_percentages),
        )
        .merge(attestation_routes())
        .merge(blockprint_routes())
        .merge(block_packing_routes())
        .merge(block_rewards_routes());

    if config.blockprint.enabled && config.updater.attestations {
        routes = routes.merge(blockprint_attestation_routes())
    }

    let app = routes
        .fallback(route_not_found.into_service())
        .layer(Extension(pool))
        .layer(Extension(slots_per_epoch));

    let addr = SocketAddr::new(config.server.listen_addr, config.server.listen_port);

    let server = axum::Server::try_bind(&addr)?.serve(app.into_make_service());

    let server = server.with_graceful_shutdown(async {
        shutdown.await;
    });

    info!("HTTP server listening on {}", addr);

    Ok(server)
}

// The default route indicating that no available routes matched the request.
async fn route_not_found(uri: Uri) -> (StatusCode, Json<ErrorMessage>) {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(ErrorMessage {
            code: StatusCode::METHOD_NOT_ALLOWED.as_u16(),
            message: format!("No route for {uri}"),
            stacktraces: vec![],
        }),
    )
}
