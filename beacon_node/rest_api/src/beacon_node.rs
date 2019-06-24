use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::Future;
use hyper::{Body, Request};
use slog::{trace, warn};
use std::sync::Arc;
use version;

use hyper::{Body, Method, Request, Response, Server, StatusCode};

#[derive(Clone)]
pub struct BeaconNodeServiceInstance<T: BeaconChainTypes> {
    pub chain: Arc<BeaconChain<T>>,
    pub log: slog::Logger,
}

impl<T: BeaconChainTypes> BeaconNodeService for BeaconNodeServiceInstance<T> {
    /// Provides basic node information.
    fn handle_request(&mut self, endpoint: &str, req: Request<Body>) {
        trace!(self.log, "API call made to beacon_node service.");

        let mut response = Response::new(Body::empty());

        if (req.method() != &Method::GET) {
            *response.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        }

        match (endpoint) {
            ("version") => {
                let ver = version::version();
            }
            ("genesis_time") => {}
            ("syncing") => {}
            ("fork") => {}
            _ => {}
        }
    }
}
