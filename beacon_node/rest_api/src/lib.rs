#[macro_use]
extern crate lazy_static;
mod router;
extern crate network as client_network;

mod beacon;
pub mod config;
mod consensus;
mod helpers;
mod lighthouse;
mod metrics;
mod node;
mod url_query;
mod validator;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use bus::Bus;
use client_network::NetworkMessage;
pub use config::ApiEncodingFormat;
use eth2_config::Eth2Config;
use eth2_libp2p::NetworkGlobals;
use futures::future::TryFutureExt;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Server};
use parking_lot::Mutex;
use rest_types::ApiError;
use slog::{info, warn};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;
use types::SignedBeaconBlockHash;
use url_query::UrlQuery;

pub use crate::helpers::parse_pubkey_bytes;
pub use config::Config;
pub use router::Context;

pub type NetworkChannel<T> = mpsc::UnboundedSender<NetworkMessage<T>>;

pub struct NetworkInfo<T: BeaconChainTypes> {
    pub network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    pub network_chan: NetworkChannel<T::EthSpec>,
}

// Allowing more than 7 arguments.
#[allow(clippy::too_many_arguments)]
pub fn start_server<T: BeaconChainTypes>(
    executor: environment::TaskExecutor,
    config: &Config,
    beacon_chain: Arc<BeaconChain<T>>,
    network_info: NetworkInfo<T>,
    db_path: PathBuf,
    freezer_db_path: PathBuf,
    eth2_config: Eth2Config,
    events: Arc<Mutex<Bus<SignedBeaconBlockHash>>>,
) -> Result<SocketAddr, hyper::Error> {
    let log = executor.log();
    let eth2_config = Arc::new(eth2_config);

    let context = Arc::new(Context {
        executor: executor.clone(),
        config: config.clone(),
        beacon_chain,
        network_globals: network_info.network_globals.clone(),
        network_chan: network_info.network_chan,
        eth2_config,
        log: log.clone(),
        db_path,
        freezer_db_path,
        events,
    });

    // Define the function that will build the request handler.
    let make_service = make_service_fn(move |_socket: &AddrStream| {
        let ctx = context.clone();

        async move {
            Ok::<_, hyper::Error>(service_fn(move |req: Request<Body>| {
                router::on_http_request(req, ctx.clone())
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
