#[macro_use]
mod macros;
#[macro_use]
extern crate lazy_static;
extern crate network as client_network;

mod advanced;
mod beacon;
pub mod config;
mod consensus;
mod error;
mod helpers;
mod lighthouse;
mod metrics;
mod network;
mod node;
mod response_builder;
mod router;
mod spec;
mod url_query;
mod validator;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use client_network::NetworkMessage;
pub use config::ApiEncodingFormat;
use error::{ApiError, ApiResult};
use eth2_config::Eth2Config;
use eth2_libp2p::NetworkGlobals;
use hyper::rt::Future;
use hyper::server::conn::AddrStream;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server};
use slog::{info, warn};
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::TaskExecutor;
use tokio::sync::{mpsc, oneshot};
use url_query::UrlQuery;

pub use crate::helpers::parse_pubkey_bytes;
pub use config::Config;

pub type BoxFut = Box<dyn Future<Item = Response<Body>, Error = ApiError> + Send>;
pub type NetworkChannel<T> = mpsc::UnboundedSender<NetworkMessage<T>>;

pub struct NetworkInfo<T: BeaconChainTypes> {
    pub network_globals: Arc<NetworkGlobals<T::EthSpec>>,
    pub network_chan: NetworkChannel<T::EthSpec>,
}

// Allowing more than 7 arguments.
#[allow(clippy::too_many_arguments)]
pub fn start_server<T: BeaconChainTypes>(
    config: &Config,
    executor: &TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    network_info: NetworkInfo<T>,
    db_path: PathBuf,
    freezer_db_path: PathBuf,
    eth2_config: Eth2Config,
    log: slog::Logger,
) -> Result<(oneshot::Sender<()>, SocketAddr), hyper::Error> {
    let inner_log = log.clone();
    let eth2_config = Arc::new(eth2_config);

    // Define the function that will build the request handler.
    let make_service = make_service_fn(move |_socket: &AddrStream| {
        let beacon_chain = beacon_chain.clone();
        let log = inner_log.clone();
        let eth2_config = eth2_config.clone();
        let network_globals = network_info.network_globals.clone();
        let network_channel = network_info.network_chan.clone();
        let db_path = db_path.clone();
        let freezer_db_path = freezer_db_path.clone();

        service_fn(move |req: Request<Body>| {
            router::route(
                req,
                beacon_chain.clone(),
                network_globals.clone(),
                network_channel.clone(),
                eth2_config.clone(),
                log.clone(),
                db_path.clone(),
                freezer_db_path.clone(),
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
    let (exit_signal, exit) = oneshot::channel();
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

#[derive(Clone)]
pub struct DBPath(PathBuf);

impl Deref for DBPath {
    type Target = PathBuf;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
