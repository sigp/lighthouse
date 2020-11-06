use crate::config::Config;
use client_backend::{Backend, Storage};
use futures::future::TryFutureExt;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Server};
use slog::{info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use task_executor::TaskExecutor;
use types::{ChainSpec, EthSpec};

pub struct Context<E: EthSpec, S: Send + Sync> {
    pub config: Config,
    pub executor: TaskExecutor,
    pub log: slog::Logger,
    pub backend: Backend<S>,
    pub eth_spec_instance: E,
    pub spec: ChainSpec,
}

pub fn start_server<E: EthSpec, S: Storage>(
    executor: TaskExecutor,
    config: Config,
    backend: Backend<S>,
    eth_spec_instance: E,
) -> Result<SocketAddr, hyper::Error> {
    let log = executor.log();

    let context = Arc::new(Context {
        executor: executor.clone(),
        log: log.clone(),
        config: config.clone(),
        backend,
        eth_spec_instance,
        spec: E::default_spec(),
    });

    // Define the function that will build the request handler.
    let make_service = make_service_fn(move |_socket: &AddrStream| {
        let ctx = context.clone();

        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                crate::router::on_http_request(req, ctx.clone())
            }))
        }
    });

    let bind_addr = (config.listen_address, config.port).into();
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
