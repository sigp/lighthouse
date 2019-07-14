use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::Future;
use http;
use serde_derive::{Deserialize, Serialize};
use slog::{info, trace, warn};
use std::sync::Arc;
use version;

use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper_router::{Route, RouterBuilder, RouterService};

#[derive(Clone)]
pub struct BeaconNodeServiceInstance<T: BeaconChainTypes> {
    pub chain: Arc<BeaconChain<T>>,
    pub log: slog::Logger,
}

pub trait BeaconNodeService {
    fn version(self, req: Request<Body>) -> Result<Response<Body>, http::Error>;
}

pub trait APIService {
    fn add_routes(self, router_builder: RouterBuilder) -> Result<(), hyper::Error>;
    fn validate_request(self, req: &Request<Body>, resp: http::response::Builder)
        -> Result<(), ()>;
}

/// A string which uniquely identifies the client implementation and its version; similar to [HTTP User-Agent](https://tools.ietf.org/html/rfc7231#section-5.5.3).
#[derive(Debug, Clone, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct Version(String);
impl ::std::convert::From<String> for Version {
    fn from(x: String) -> Self {
        Version(x)
    }
}
/*
impl std::str::FromStr for Version {
    type Err = ParseError;
    fn from_str(x: &str) -> Result<Self, Self::Err> {
        Ok(Version(x.to_string()))
    }
}
impl ::std::convert::From<Version> for String {
    fn from(x: Version) -> Self {
        x.0
    }
}
impl ::std::ops::Deref for Version {
    type Target = String;
    fn deref(&self) -> &String {
        &self.0
    }
}
impl ::std::ops::DerefMut for Version {
    fn deref_mut(&mut self) -> &mut String {
        &mut self.0
    }
}
*/

impl<T: BeaconChainTypes> BeaconNodeService for BeaconNodeServiceInstance<T> {
    fn version(&mut self, req: Request<Body>) -> Result<Response<Body>, http::Error> {
        let mut response_builder = Response::builder();
        if let Err(e) = self.validate_request(&req, response_builder) {
            info!(self.log, "Invalid Request");
            response_builder.body(Body::empty())
        };
        let ver = Version::from(version::version());
        let json = serde_json::to_string(&ver)?;
        response_builder.body(Body::from(json))
    }
}

impl<T: BeaconChainTypes> APIService for BeaconNodeServiceInstance<T> {
    fn add_routes(mut self, &mut router_builder: RouterBuilder) -> Result<(), hyper::Error> {
        *router_builder
            .add(Route::get("/version"))
            .using(self.version);
        Ok(())
    }

    fn validate_request(
        &mut self,
        req: &Request<Body>,
        &mut resp: http::response::Builder,
    ) -> Result<(), ()> {
        if req.method() != &Method::GET {
            *resp.status(StatusCode::METHOD_NOT_ALLOWED);
            info!(self.log, "Method Not Allowed");
            Err(())
        }
        Ok(())
    }
}
