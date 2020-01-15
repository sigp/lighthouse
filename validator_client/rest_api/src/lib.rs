pub mod config;
mod errors;
mod response_builder;
mod router;
mod status;
mod validator;

use config::Config;
use errors::{ApiError, ApiResult};
use hyper::rt::Future;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use remote_beacon_node::RemoteBeaconNode;
use slog::{info, warn};
use slot_clock::SlotClock;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::runtime::TaskExecutor;
use types::EthSpec;
use validator_store::ValidatorStore;

pub type BoxFut = Box<dyn Future<Item = Response<Body>, Error = ApiError> + Send>;

pub fn start_server<T: SlotClock + 'static, E: EthSpec>(
    config: &Config,
    executor: &TaskExecutor,
    validator_client: Arc<ValidatorStore<T, E>>,
    beacon_node: Arc<RemoteBeaconNode<E>>,
    log: slog::Logger,
) -> Result<(exit_future::Signal, SocketAddr), hyper::Error> {
    let inner_log = log.clone();

    // Define the function that will build the request handler.
    let make_service = make_service_fn(move |_socket: &AddrStream| {
        let validator_client = validator_client.clone();
        let beacon_node = beacon_node.clone();
        let log = inner_log.clone();

        service_fn(move |req: Request<Body>| {
            router::route(
                req,
                validator_client.clone(),
                beacon_node.clone(),
                log.clone(),
            )
        })
    });

    let bind_addr = (config.listen_address, config.port).into();
    let server = Server::bind(&bind_addr).serve(make_service);

    // Determine the address the server is actually listening on.
    //
    // This may be different to `bind_addr` if bind port was 0 (this allows the OS to choose a free
    // port).
    let actual_listen_addr = server.local_addr();

    // Build a channel to kill the HTTP server.
    let (exit_signal, exit) = exit_future::signal();
    let inner_log = log.clone();
    let server_exit = exit.and_then(move |_| {
        info!(inner_log, "HTTP service shutdown");
        Ok(())
    });
    // Configure the `hyper` server to gracefully shutdown when the shutdown channel is triggered.
    let inner_log = log.clone();
    let server_future = server
        .with_graceful_shutdown(server_exit)
        .map_err(move |e| {
            warn!(
            inner_log,
            "HTTP server failed to start, Unable to bind"; "address" => format!("{:?}", e)
            )
        });

    info!(
        log,
        "HTTP API started";
        "address" => format!("{}", actual_listen_addr.ip()),
        "port" => actual_listen_addr.port(),
    );

    executor.spawn(server_future);

    Ok((exit_signal, actual_listen_addr))
}
