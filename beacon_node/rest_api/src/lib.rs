#[macro_use]
mod macros;
#[macro_use]
extern crate lazy_static;
extern crate network as client_network;

mod beacon;
pub mod config;
mod error;
pub mod helpers;
mod metrics;
mod network;
mod node;
mod response_builder;
mod spec;
mod url_query;
mod validator;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use client_network::NetworkMessage;
use client_network::Service as NetworkService;
pub use config::ApiEncodingFormat;
use error::{ApiError, ApiResult};
use eth2_config::Eth2Config;
use futures::future::IntoFuture;
use hyper::rt::Future;
use hyper::service::Service;
use hyper::{Body, Method, Request, Response, Server};
use parking_lot::RwLock;
use slog::{info, warn};
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::runtime::TaskExecutor;
use tokio::sync::mpsc;
use url_query::UrlQuery;

pub use crate::helpers::parse_pubkey;
pub use beacon::{BlockResponse, HeadResponse, StateResponse};
pub use config::Config;
pub use validator::ValidatorDuty;

type BoxFut = Box<dyn Future<Item = Response<Body>, Error = ApiError> + Send>;

pub struct ApiService<T: BeaconChainTypes + 'static> {
    log: slog::Logger,
    beacon_chain: Arc<BeaconChain<T>>,
    db_path: DBPath,
    network_service: Arc<NetworkService<T>>,
    network_channel: Arc<RwLock<mpsc::UnboundedSender<NetworkMessage>>>,
    eth2_config: Arc<Eth2Config>,
}

pub struct NetworkInfo<T: BeaconChainTypes> {
    pub network_service: Arc<NetworkService<T>>,
    pub network_chan: mpsc::UnboundedSender<NetworkMessage>,
}

fn into_boxfut<F: IntoFuture + 'static>(item: F) -> BoxFut
where
    F: IntoFuture<Item = Response<Body>, Error = ApiError>,
    F::Future: Send,
{
    Box::new(item.into_future())
}

impl<T: BeaconChainTypes> Service for ApiService<T> {
    type ReqBody = Body;
    type ResBody = Body;
    type Error = ApiError;
    type Future = BoxFut;

    fn call(&mut self, mut req: Request<Body>) -> Self::Future {
        metrics::inc_counter(&metrics::REQUEST_COUNT);
        let timer = metrics::start_timer(&metrics::REQUEST_RESPONSE_TIME);

        // Add all the useful bits into the request, so that we can pull them out in the individual
        // functions.
        req.extensions_mut()
            .insert::<slog::Logger>(self.log.clone());
        req.extensions_mut()
            .insert::<Arc<BeaconChain<T>>>(self.beacon_chain.clone());
        req.extensions_mut().insert::<DBPath>(self.db_path.clone());
        req.extensions_mut()
            .insert::<Arc<NetworkService<T>>>(self.network_service.clone());
        req.extensions_mut()
            .insert::<Arc<RwLock<mpsc::UnboundedSender<NetworkMessage>>>>(
                self.network_channel.clone(),
            );
        req.extensions_mut()
            .insert::<Arc<Eth2Config>>(self.eth2_config.clone());

        let path = req.uri().path().to_string();

        // Route the request to the correct handler.
        let result = match (req.method(), path.as_ref()) {
            // Methods for Client
            (&Method::GET, "/node/version") => into_boxfut(node::get_version(req)),
            (&Method::GET, "/node/genesis_time") => into_boxfut(node::get_genesis_time::<T>(req)),
            (&Method::GET, "/node/syncing") => {
                into_boxfut(helpers::implementation_pending_response(req))
            }

            // Methods for Network
            (&Method::GET, "/network/enr") => into_boxfut(network::get_enr::<T>(req)),
            (&Method::GET, "/network/peer_count") => into_boxfut(network::get_peer_count::<T>(req)),
            (&Method::GET, "/network/peer_id") => into_boxfut(network::get_peer_id::<T>(req)),
            (&Method::GET, "/network/peers") => into_boxfut(network::get_peer_list::<T>(req)),
            (&Method::GET, "/network/listen_port") => {
                into_boxfut(network::get_listen_port::<T>(req))
            }
            (&Method::GET, "/network/listen_addresses") => {
                into_boxfut(network::get_listen_addresses::<T>(req))
            }

            // Methods for Beacon Node
            (&Method::GET, "/beacon/head") => into_boxfut(beacon::get_head::<T>(req)),
            (&Method::GET, "/beacon/block") => into_boxfut(beacon::get_block::<T>(req)),
            (&Method::GET, "/beacon/block_root") => into_boxfut(beacon::get_block_root::<T>(req)),
            (&Method::GET, "/beacon/blocks") => {
                into_boxfut(helpers::implementation_pending_response(req))
            }
            (&Method::GET, "/beacon/fork") => into_boxfut(beacon::get_fork::<T>(req)),
            (&Method::GET, "/beacon/attestations") => {
                into_boxfut(helpers::implementation_pending_response(req))
            }
            (&Method::GET, "/beacon/attestations/pending") => {
                into_boxfut(helpers::implementation_pending_response(req))
            }

            (&Method::GET, "/beacon/validators") => into_boxfut(beacon::get_validators::<T>(req)),
            (&Method::GET, "/beacon/validators/indicies") => {
                into_boxfut(helpers::implementation_pending_response(req))
            }
            (&Method::GET, "/beacon/validators/pubkeys") => {
                into_boxfut(helpers::implementation_pending_response(req))
            }

            // Methods for Validator
            (&Method::GET, "/validator/duties") => {
                into_boxfut(validator::get_validator_duties::<T>(req))
            }
            (&Method::GET, "/validator/block") => {
                into_boxfut(validator::get_new_beacon_block::<T>(req))
            }
            (&Method::POST, "/validator/block") => validator::publish_beacon_block::<T>(req),
            (&Method::GET, "/validator/attestation") => {
                into_boxfut(validator::get_new_attestation::<T>(req))
            }
            (&Method::POST, "/validator/attestation") => validator::publish_attestation::<T>(req),

            (&Method::GET, "/beacon/state") => into_boxfut(beacon::get_state::<T>(req)),
            (&Method::GET, "/beacon/state_root") => into_boxfut(beacon::get_state_root::<T>(req)),
            (&Method::GET, "/beacon/state/current_finalized_checkpoint") => {
                into_boxfut(beacon::get_current_finalized_checkpoint::<T>(req))
            }
            (&Method::GET, "/beacon/state/genesis") => {
                into_boxfut(beacon::get_genesis_state::<T>(req))
            }
            //TODO: Add aggreggate/filtered state lookups here, e.g. /beacon/validators/balances

            // Methods for bootstrap and checking configuration
            (&Method::GET, "/spec") => into_boxfut(spec::get_spec::<T>(req)),
            (&Method::GET, "/spec/slots_per_epoch") => {
                into_boxfut(spec::get_slots_per_epoch::<T>(req))
            }
            (&Method::GET, "/spec/deposit_contract") => {
                into_boxfut(helpers::implementation_pending_response(req))
            }
            (&Method::GET, "/spec/eth2_config") => into_boxfut(spec::get_eth2_config::<T>(req)),

            (&Method::GET, "/metrics") => into_boxfut(metrics::get_prometheus::<T>(req)),

            _ => Box::new(futures::future::err(ApiError::NotFound(
                "Request path and/or method not found.".to_owned(),
            ))),
        };

        let response = match result.wait() {
            // Return the `hyper::Response`.
            Ok(response) => {
                metrics::inc_counter(&metrics::SUCCESS_COUNT);
                slog::debug!(self.log, "Request successful: {:?}", path);
                response
            }
            // Map the `ApiError` into `hyper::Response`.
            Err(e) => {
                slog::debug!(self.log, "Request failure: {:?}", path);
                e.into()
            }
        };

        metrics::stop_timer(timer);

        Box::new(futures::future::ok(response))
    }
}

pub fn start_server<T: BeaconChainTypes>(
    config: &Config,
    executor: &TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    network_info: NetworkInfo<T>,
    db_path: PathBuf,
    eth2_config: Eth2Config,
    log: slog::Logger,
) -> Result<(exit_future::Signal, SocketAddr), hyper::Error> {
    // build a channel to kill the HTTP server
    let (exit_signal, exit) = exit_future::signal();

    let exit_log = log.clone();
    let server_exit = exit.and_then(move |_| {
        info!(exit_log, "API service shutdown");
        Ok(())
    });

    let db_path = DBPath(db_path);

    // Get the address to bind to
    let bind_addr = (config.listen_address, config.port).into();

    // Clone our stateful objects, for use in service closure.
    let server_log = log.clone();
    let server_bc = beacon_chain.clone();
    let eth2_config = Arc::new(eth2_config);

    let service = move || -> futures::future::FutureResult<ApiService<T>, String> {
        futures::future::ok(ApiService {
            log: server_log.clone(),
            beacon_chain: server_bc.clone(),
            db_path: db_path.clone(),
            network_service: network_info.network_service.clone(),
            network_channel: Arc::new(RwLock::new(network_info.network_chan.clone())),
            eth2_config: eth2_config.clone(),
        })
    };

    let log_clone = log.clone();
    let server = Server::bind(&bind_addr).serve(service);

    let actual_listen_addr = server.local_addr();

    let server_future = server
        .with_graceful_shutdown(server_exit)
        .map_err(move |e| {
            warn!(
            log_clone,
            "API failed to start, Unable to bind"; "address" => format!("{:?}", e)
            )
        });

    info!(
        log,
        "REST API started";
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
