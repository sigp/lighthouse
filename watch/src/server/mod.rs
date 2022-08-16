use crate::config::Config as FullConfig;
use crate::database::{self, get_connection, PgPool};
use error::Error;
use eth2::types::{BlockId, Epoch};
use log::{debug, info};
use serde::Serialize;
use std::future::Future;
use std::net::SocketAddr;
use tokio::sync::oneshot;
use warp::{reject, reply, Filter};

pub use config::Config;

mod config;
mod error;
mod handler;

#[derive(Debug)]
struct MissingIdField;

impl warp::reject::Reject for MissingIdField {}

pub async fn serve(config: FullConfig, shutdown: oneshot::Receiver<()>) -> Result<(), Error> {
    let db = database::build_connection_pool(&config.database)?;

    let (_socket_addr, server) = start_server(&config.server, config.slots_per_epoch, db, async {
        let _ = shutdown.await;
    })?;

    server.await;

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
/// This function will bind the server to the provided address and then return a tuple of:
///
/// - `SocketAddr`: the address that the HTTP server will listen on.
/// - `Future`: the actual server future that will need to be awaited.
///
/// ## Errors
///
/// Returns an error if the server is unable to bind or there is another error during
/// configuration.
pub fn start_server(
    config: &Config,
    slots_per_epoch: u64,
    pool: PgPool,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()>), Error> {
    // Routes

    let slot = warp::path("v1")
        .and(warp::path("canonical_slots"))
        .and(warp::path::param::<BlockId>())
        .and(warp::path::end())
        .and(handler::with_db(pool.clone()))
        .and_then(|block_id, pool: PgPool| async move {
            let mut conn = get_connection(&pool).map_err(Error::Database)?;
            let response = handler::get_slot(&mut conn, block_id);
            respond_opt(response)
        });

    let lowest_slot = warp::path("v1")
        .and(warp::path("canonical_slots"))
        .and(warp::path("lowest"))
        .and(warp::path::end())
        .and(handler::with_db(pool.clone()))
        .and_then(|pool: PgPool| async move {
            let mut conn = get_connection(&pool).map_err(Error::Database)?;
            let response = handler::get_lowest_slot(&mut conn);
            respond_opt(response)
        });

    let highest_slot = warp::path("v1")
        .and(warp::path("canonical_slots"))
        .and(warp::path("highest"))
        .and(warp::path::end())
        .and(handler::with_db(pool.clone()))
        .and_then(|pool: PgPool| async move {
            let mut conn = get_connection(&pool).map_err(Error::Database)?;
            let response = handler::get_highest_slot(&mut conn);
            respond_opt(response)
        });

    let beacon_blocks = warp::path("v1")
        .and(warp::path("beacon_blocks"))
        .and(warp::path::param::<BlockId>())
        .and(warp::path::end())
        .and(handler::with_db(pool.clone()))
        .and_then(|block_id, pool: PgPool| async move {
            let mut conn = get_connection(&pool).map_err(Error::Database)?;
            let response = handler::get_block(&mut conn, block_id);
            respond_opt(response)
        });

    let lowest_block = warp::path("v1")
        .and(warp::path("beacon_blocks"))
        .and(warp::path("lowest"))
        .and(warp::path::end())
        .and(handler::with_db(pool.clone()))
        .and_then(|pool: PgPool| async move {
            let mut conn = get_connection(&pool).map_err(Error::Database)?;
            let response = handler::get_lowest_beacon_block(&mut conn);
            respond_opt(response)
        });

    let highest_block = warp::path("v1")
        .and(warp::path("beacon_blocks"))
        .and(warp::path("highest"))
        .and(warp::path::end())
        .and(handler::with_db(pool.clone()))
        .and_then(|pool: PgPool| async move {
            let mut conn = get_connection(&pool).map_err(Error::Database)?;
            let response = handler::get_highest_beacon_block(&mut conn);
            respond_opt(response)
        });

    let next_block = warp::path("v1")
        .and(warp::path("beacon_blocks"))
        .and(warp::path::param::<BlockId>())
        .and(warp::path("next"))
        .and(warp::path::end())
        .and(handler::with_db(pool.clone()))
        .and_then(|parent, pool: PgPool| async move {
            let mut conn = get_connection(&pool).map_err(Error::Database)?;
            let response = handler::get_next_beacon_block(&mut conn, parent);
            respond_opt(response)
        });

    let validator = warp::path("v1")
        .and(warp::path("validator"))
        .and(warp::path::param::<i32>())
        .and(warp::path::end())
        .and(handler::with_db(pool.clone()))
        .and_then(|index, pool: PgPool| async move {
            let mut conn = get_connection(&pool).map_err(Error::Database)?;
            let response = handler::get_validator_by_index(&mut conn, index);
            respond_opt(response)
        });

    let validator_attestations = warp::path("v1")
        .and(warp::path("validator"))
        .and(warp::path::param::<i32>())
        .and(warp::path("attestations"))
        .and(warp::path::param::<Epoch>())
        .and(warp::path::end())
        .and(handler::with_db(pool.clone()))
        .and(handler::with_slots_per_epoch(slots_per_epoch))
        .and_then(|index, epoch, pool: PgPool, slots_per_epoch| async move {
            let mut conn = get_connection(&pool).map_err(Error::Database)?;
            let response =
                handler::get_validator_attestation(&mut conn, index, epoch, slots_per_epoch);
            respond_opt(response)
        });

    let proposer_info = warp::path("v1")
        .and(warp::path("proposer_info"))
        .and(warp::path::param::<BlockId>())
        .and(warp::path::end())
        .and(handler::with_db(pool.clone()))
        .and_then(|block_id, pool: PgPool| async move {
            let mut conn = get_connection(&pool).map_err(Error::Database)?;
            let response = handler::get_proposer_info(&mut conn, block_id);
            respond_opt(response)
        });

    let block_rewards = warp::path("v1")
        .and(warp::path("block_rewards"))
        .and(warp::path::param::<BlockId>())
        .and(warp::path::end())
        .and(handler::with_db(pool.clone()))
        .and_then(|block_id, pool: PgPool| async move {
            let mut conn = get_connection(&pool).map_err(Error::Database)?;
            let response = handler::get_block_reward(&mut conn, block_id);
            respond_opt(response)
        });

    let block_packing = warp::path("v1")
        .and(warp::path("block_packing"))
        .and(warp::path::param::<BlockId>())
        .and(warp::path::end())
        .and(handler::with_db(pool))
        .and_then(|block_id, pool: PgPool| async move {
            let mut conn = get_connection(&pool).map_err(Error::Database)?;
            let response = handler::get_block_packing(&mut conn, block_id);
            respond_opt(response)
        });

    let routes = warp::get()
        .and(
            slot.or(lowest_slot)
                .or(highest_slot)
                .or(next_block)
                // `next_block` must come before beacon_blocks, otherwise `beacon_blocks`
                // will always resolve instead.
                .or(beacon_blocks)
                .or(lowest_block)
                .or(highest_block)
                .or(validator)
                .or(validator_attestations)
                .or(proposer_info)
                .or(block_rewards)
                .or(block_packing),
        )
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", "lighthouse-watch"));

    let (listening_socket, server) = warp::serve(routes).try_bind_with_graceful_shutdown(
        SocketAddr::new(config.listen_addr, config.listen_port),
        async {
            shutdown.await;
        },
    )?;

    info!("HTTP server listening on {}", listening_socket);

    Ok((listening_socket, server))
}

fn respond_opt<T: Serialize>(
    result: Result<Option<T>, Error>,
) -> Result<reply::Json, reject::Rejection> {
    match result {
        Ok(Some(t)) => Ok(reply::json(&t)),
        Ok(None) => Err(reject::not_found()),
        Err(e) => {
            #[cfg(test)] // If testing, print errors for troubleshooting.
            dbg!(&e);

            debug!("Request returned error: {:?}", e);
            Err(reject::custom(e))
        }
    }
}
