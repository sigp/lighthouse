use crate::database::{self, Config};
use eth2::types::BlockId;
use log::info;
use serde_json;
use std::future::Future;
use std::marker::PhantomData;
use std::net::{SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::sync::oneshot;
use types::EthSpec;
use warp::{
    http::{self},
    reject, reply, Filter,
};

mod handler;

#[derive(Debug)]
pub enum Error {
    Warp(warp::Error),
    Serde(serde_json::Error),
    Database(database::Error),
    Http(http::Error),
    Other(String),
}

impl warp::reject::Reject for Error {}

impl From<warp::Error> for Error {
    fn from(e: warp::Error) -> Self {
        Error::Warp(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

impl From<database::Error> for Error {
    fn from(e: database::Error) -> Self {
        Error::Database(e)
    }
}

impl From<http::Error> for Error {
    fn from(e: http::Error) -> Self {
        Error::Http(e)
    }
}

impl From<String> for Error {
    fn from(e: String) -> Self {
        Error::Other(e)
    }
}

#[derive(Debug)]
struct MissingIdField;

impl warp::reject::Reject for MissingIdField {}

/// A wrapper around all the items required to spawn the HTTP server.
///
/// The server will gracefully handle the case where any fields are `None`.
pub struct Context<T: EthSpec> {
    pub config: Config,
    pub _phantom: PhantomData<T>,
}

pub async fn serve<T: EthSpec>(
    config: Config,
    shutdown: oneshot::Receiver<()>,
) -> Result<(), Error> {
    let ctx: Context<T> = Context {
        config,
        _phantom: <_>::default(),
    };

    let (_socket_addr, server) = start_server(Arc::new(ctx), async {
        let _ = shutdown.await;
    })?;

    server.await;

    Ok(())
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
pub fn start_server<T: EthSpec>(
    ctx: Arc<Context<T>>,
    shutdown: impl Future<Output = ()> + Send + Sync + 'static,
) -> Result<(SocketAddr, impl Future<Output = ()>), Error> {
    let config = &ctx.config;

    let inner_ctx = ctx.clone();
    let ctx_filter = warp::any().map(move || inner_ctx.clone());

    let beacon_blocks = warp::path("v1")
        .and(warp::path("beacon_blocks"))
        .and(warp::path::param::<BlockId>())
        .and(ctx_filter.clone())
        .and_then(|block_id, ctx: Arc<Context<T>>| async move {
            match handler::with_db(&ctx.config, |mut db| async move {
                handler::get_block(&mut db, block_id).await
            })
            .await
            {
                Ok(Some(block)) => Ok(reply::json(&block)),
                Ok(None) => Err(reject::not_found()),
                Err(e) => Err(reject::custom(e)),
            }
        });

    let other = warp::path("v1")
        .and(warp::path("canonical_slots"))
        .and(warp::path::param::<BlockId>())
        .and(ctx_filter)
        .and_then(|block_id: BlockId, ctx: Arc<Context<T>>| async move {
            Ok::<_, warp::reject::Rejection>(
                warp::http::Response::builder().status(200).body("cat"),
            )
        });

    let routes = warp::get()
        .and(beacon_blocks.or(other))
        // Add a `Server` header.
        .map(|reply| warp::reply::with_header(reply, "Server", "lighthouse-watch"));

    let (listening_socket, server) = warp::serve(routes).try_bind_with_graceful_shutdown(
        SocketAddrV4::new(config.server_listen_addr, config.server_listen_port),
        async {
            shutdown.await;
        },
    )?;

    info!("HTTP server listening on {}", listening_socket);

    Ok((listening_socket, server))
}
