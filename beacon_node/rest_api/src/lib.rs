extern crate futures;
extern crate hyper;
mod beacon_node;
pub mod config;

use beacon_chain::{BeaconChain, BeaconChainTypes};
use beacon_node::{APIService};
pub use config::Config as APIConfig;

use slog::{error, info, o, warn};
use std::sync::Arc;
use tokio::runtime::TaskExecutor;

use futures::future;
use hyper::rt::Future;
use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper_router::{Route, Router, RouterBuilder, RouterService};

// == Taken from official Hyper examples. ==
// We need to return different futures depending on the route matched,
// and we can do that with an enum, such as `futures::Either`, or with
// trait objects.
//
// A boxed Future (trait object) is used as it is easier to understand
// and extend with more types. Advanced users could switch to `Either`.
type BoxFut = Box<dyn Future<Item = Response<Body>, Error = hyper::Error> + Send>;

pub fn start_server<T: BeaconChainTypes + Clone + 'static>(
    config: &APIConfig,
    executor: &TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    log: &slog::Logger,
) -> Result<exit_future::Signal, hyper::Error> {
    let log = log.new(o!("Service"=>"REST API"));

    // build a channel to kill the HTTP server
    let (exit_signal, exit) = exit_future::signal();

    let bind_addr = (config.listen_address, config.port).into();

    let router = || { router_service(beacon_chain.clone(), &log) };

    let server = Server::bind(&bind_addr)
        .serve(router)
        .map_err(move |e| warn!(log, "Unable to bind to address: {:?}", e));

    executor.spawn(server);

    Ok(exit_signal)
}

fn router_service<T: BeaconChainTypes>(beacon_chain: Arc<BeaconChain<T>>, log: &slog::Logger) -> Result<RouterService, hyper::Error> {
    let mut router_builder = RouterBuilder::new();

    let mut bn_service = beacon_node::BeaconNodeServiceInstance {
        chain: beacon_chain.clone(),
        log,
    };

    bn_service.add_routes(&mut router_builder)?;

    Ok(RouterService::new(router_builder.build()))
}

/*
fn handle_request(req: Request<Body>) -> BoxFut {
let mut split_path = req.uri().path().split("/");
let mut response = Response::new(Body::empty());

match (split_path.next()) {
("node") => {
    // Pass to beacon_node service
    rest_api::bu
}
("validator") => {
    // Pass to validator_support
    None
}
        _ => *response.status_mut() = StatusCode::NOT_FOUND,
    }
    Box::new(future::ok(response))
}*/
