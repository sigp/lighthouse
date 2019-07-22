use beacon_chain::{BeaconChain, BeaconChainTypes};
use futures::Future;
use http;
use serde::{Deserialize, Serialize};
use slog::{info, trace, warn};
use std::sync::Arc;
use version;

use super::{APIError, APIResult, APIService};

use hyper::service::service_fn;
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper_router::{Route, RouterBuilder, RouterService};

#[derive(Clone)]
pub struct BeaconNodeServiceInstance<T: BeaconChainTypes + 'static> {
    pub marker: std::marker::PhantomData<T>,
}

/// A string which uniquely identifies the client implementation and its version; similar to [HTTP User-Agent](https://tools.ietf.org/html/rfc7231#section-5.5.3).
#[derive(Serialize)]
pub struct Version(String);
impl ::std::convert::From<String> for Version {
    fn from(x: String) -> Self {
        Version(x)
    }
}

/// The genesis_time configured for the beacon node, which is the unix time at which the Eth2.0 chain began.
#[derive(Serialize)]
pub struct GenesisTime(u64);
impl ::std::convert::From<u64> for GenesisTime {
    fn from(x: u64) -> Self {
        GenesisTime(x)
    }
}



impl<T: BeaconChainTypes + 'static> APIService for BeaconNodeServiceInstance<T> {
    fn add_routes(&mut self, router_builder: RouterBuilder) -> Result<RouterBuilder, hyper::Error> {
        let router_builder = router_builder
            .add(Route::get("/version").using(wrappy!(get_version)))
            .add(Route::get("/genesis_time").using(wrappy!(get_genesis_time::<T>)));
        Ok(router_builder)
    }
}

//TODO: Validate request stuff can be turned into a macro.
fn validate_request(
    req: &Request<Body>,
) -> Result<(), APIError> {
    let log = req.extensions().get::<slog::Logger>().unwrap();
    if req.method() != &Method::GET {
        info!(log, "Invalid request method: {}", req.uri().path_and_query().as_str());
        Err(http::method::InvalidMethod { _priv: () })
    }
    Ok(())
}

fn get_version(req: Request<Body>) -> APIResult {
    let log = req.extensions().get::<slog::Logger>().unwrap();
    validate_request(&req)?;
    let mut response_builder = Response::builder();
    response_builder.status(StatusCode::OK);
    let ver = Version::from(version::version());
    let body = Body::from(serde_json::to_string(&ver).unwrap()).expect("Version should always convert to a JSON body.");
    info!(log, "Request successful.");
    Ok(response_builder.body(body).unwrap())
}

/*
fn wrapper<T: BeaconChainTypes + 'static, F, I>(inner: I) -> F
where
    F: Fn(Request<Body>) -> Response<Body>,
    I: Fn() -> u64,
{
    let x = |req| {
        let mut response_builder = Response::builder();
        response_builder.body(Body::empty()).unwrap()
    };

    x
}

pub enum LukeError {
    BadCats(String)
}

impl<T> Into<Response<T>> for LukeError {
    fn into(self) -> Response<T> {
        let mut response_builder = Response::builder();
        // TODO: make this a 500 error or something..
        response_builder.body(Body::empty()).unwrap()
    }
}

type LukeResult<T> = Result<Response<T>, LukeError>;

fn my_end_point(req: Request<Body>) -> LukeResult<Body> {
    let mut response_builder = Response::builder();

    if req.method() != &Method::GET {
        Ok(response_builder.body(Body::empty()).unwrap())
    } else {
        Err(LukeError::BadCats("Lol".to_string()))
    }
}

fn wrapper<T: BeaconChainTypes + 'static>(req: Request<Body>) -> Response<Body> {
*/

fn get_genesis_time<T: BeaconChainTypes + 'static>(req: Request<Body>) -> APIResult {
    let log = req.extensions().get::<slog::Logger>().unwrap();
    let beacon_chain = req.extensions().get::<Arc<BeaconChain<T>>>().unwrap();
    let mut response_builder = Response::builder();
    let body = if let Err(e) = validate_request(&req) {
        info!(log, "API GET /genesis_time: Invalid request");
        Body::empty()
    } else {
        response_builder.status(StatusCode::OK);
        info!(log, "API GET /genesis_time: Request successful");
        let gen_time = {
            let state = beacon_chain.current_state();
            state.genesis_time
        };
        Body::from(
            serde_json::to_string(&gen_time)
                .expect("Genesis time always have a valid JSON serialization."),
        )
    };
    Ok(response_builder.body(body).unwrap())
}
