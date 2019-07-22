extern crate futures;
extern crate hyper;
#[macro_use]
mod macros;
mod beacon_node;
pub mod config;

use beacon_chain::{BeaconChain, BeaconChainTypes};
pub use config::Config as APIConfig;

use slog::{error, info, o, warn};
use std::sync::Arc;
use tokio::runtime::TaskExecutor;

use crate::beacon_node::BeaconNodeServiceInstance;
use core::borrow::{Borrow, BorrowMut};
use futures::future;
use hyper::rt::Future;
use hyper::service::{service_fn, Service};
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

pub type APIError = hyper::http::Error;

pub type APIResult = Result<Response<Body>, http::Error>;

impl Into<Response<Body>> for APIError {
    fn into(self) -> Response<Body> {
        match self {
            http::method::InvalidMethod { _priv: () } => {
                Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Body::empty()).expect("Response should always be created.")
            },
        }
    }
}

pub trait APIService {
    fn add_routes(&mut self, router_builder: RouterBuilder) -> Result<RouterBuilder, hyper::Error>;
}

/*
pub enum LukeError {
    Custom(Response<Body>)
}
*/

pub fn start_server<T: BeaconChainTypes + Clone + 'static>(
    config: &APIConfig,
    executor: &TaskExecutor,
    beacon_chain: Arc<BeaconChain<T>>,
    log: &slog::Logger,
) -> Result<exit_future::Signal, hyper::Error> {
    let log = log.new(o!("Service" => "API"));

    // build a channel to kill the HTTP server
    let (exit_signal, exit) = exit_future::signal();

    // Get the address to bind to
    let bind_addr = (config.listen_address, config.port).into();

    // Clone our stateful objects, for use in service closure.
    let server_log = log.clone();
    let server_bc = beacon_chain.clone();

    // Create the service closure
    let service = move || {
        //TODO: This router must be moved out of this closure, so it isn't rebuilt for every connection.
        let mut router = build_router_service::<T>();

        // Clone our stateful objects, for use in handler closure
        let service_log = server_log.clone();
        let service_bc = server_bc.clone();

        // Create a simlple handler for the router, inject our stateful objects into the request.
        service_fn(move |mut req| {
            req.extensions_mut()
                .insert::<slog::Logger>(service_log.clone());
            req.extensions_mut()
                .insert::<Arc<BeaconChain<T>>>(service_bc.clone());
            router.call(req)
        })
    };

    let server = Server::bind(&bind_addr)
        .serve(service)
        .map_err(move |e| warn!(log, "Unable to bind to address: {:?}", e));

    executor.spawn(server);

    Ok(exit_signal)
}

fn build_router_service<T: BeaconChainTypes + 'static>() -> RouterService {
    let mut router_builder = RouterBuilder::new();

    let mut bn_service: BeaconNodeServiceInstance<T> = BeaconNodeServiceInstance {
        marker: std::marker::PhantomData,
    };

    router_builder = bn_service
        .add_routes(router_builder)
        .expect("The routes should always be made.");

    RouterService::new(router_builder.build())
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
