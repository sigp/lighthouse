mod errors;
mod response_builder;
mod router;
mod status;
mod validator;
mod wallet;

use crate::{Config, ValidatorStore};
use environment::TaskExecutor;
use futures::future::TryFutureExt;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Server};
use parking_lot::RwLock;
use remote_beacon_node::RemoteBeaconNode;
use router::RouterContext;
use slog::{info, warn};
use slot_clock::SlotClock;
use std::net::SocketAddr;
use std::sync::Arc;
use types::EthSpec;
pub use validator::{AddValidatorRequest, ValidatorRequest};

pub fn start_server<T: SlotClock + Clone + 'static, E: EthSpec>(
    config: &Config,
    executor: &TaskExecutor,
    validator_store: ValidatorStore<T, E>,
    beacon_node: RemoteBeaconNode<E>,
    log: slog::Logger,
) -> Result<SocketAddr, hyper::Error> {
    let inner_log = log.clone();

    let secrets_dir = config.secrets_dir.clone();
    let wallets_dir = config.wallets_dir.clone();

    // Define the function that will build the request handler.
    let make_service = make_service_fn(move |_socket: &AddrStream| {
        let context = Arc::new(RwLock::new(RouterContext {
            validator_store: Some(Arc::new(validator_store.clone())),
            beacon_node: Some(beacon_node.clone()),
            secrets_dir: secrets_dir.clone(),
            wallets_dir: wallets_dir.clone(),
            log: inner_log.clone(),
        }));

        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                router::route(req, context.clone())
            }))
        }
    });

    let bind_addr = (config.api_listen_address, config.api_port).into();
    let server = Server::bind(&bind_addr).serve(make_service);

    // Determine the address the server is actually listening on.
    //
    // This may be different to `bind_addr` if bind port was 0 (this allows the OS to choose a free
    // port).
    let actual_listen_addr = server.local_addr();

    // Build a channel to kill the HTTP server.
    let exit = executor.exit();
    let inner_log = log.clone();
    let server_exit = async move {
        let _ = exit.await;
        info!(inner_log, "HTTP service shutdown");
    };

    // Configure the `hyper` server to gracefully shutdown when the shutdown channel is triggered.
    let inner_log = log.clone();
    let server_future = server
        .with_graceful_shutdown(async {
            server_exit.await;
        })
        .map_err(move |e| {
            warn!(
            inner_log,
            "HTTP server failed to start, Unable to bind"; "address" => format!("{:?}", e)
            )
        })
        .unwrap_or_else(|_| ());

    info!(
        log,
        "HTTP API started";
        "address" => format!("{}", actual_listen_addr.ip()),
        "port" => actual_listen_addr.port(),
    );

    executor.spawn_without_exit(server_future, "http");

    Ok(actual_listen_addr)
}
