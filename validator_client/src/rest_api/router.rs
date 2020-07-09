use super::errors::{ApiError, ApiResult};
use super::validator;
use crate::ValidatorStore;
use hyper::{Body, Error, Method, Request, Response};
use parking_lot::RwLock;
use remote_beacon_node::RemoteBeaconNode;
use slog::{debug, Logger};
use slot_clock::SlotClock;
use std::sync::Arc;
use types::EthSpec;

pub struct RouterContext<T: SlotClock + 'static, E: EthSpec> {
    pub validator_client: Option<Arc<ValidatorStore<T, E>>>,
    pub beacon_node: Option<RemoteBeaconNode<E>>,
    pub log: Logger,
}

impl<T: SlotClock + 'static, E: EthSpec> RouterContext<T, E> {
    pub fn validator_client(&self) -> Result<Arc<ValidatorStore<T, E>>, ApiError> {
        self.validator_client.clone().ok_or_else(|| {
            ApiError::MethodNotAllowed("validator_client not initialized".to_string())
        })
    }

    pub fn beacon_node(&self) -> Result<RemoteBeaconNode<E>, ApiError> {
        self.beacon_node
            .clone()
            .ok_or_else(|| ApiError::MethodNotAllowed("beacon_node not initialized".to_string()))
    }
}

pub fn implementation_pending_response(_req: Request<Body>) -> ApiResult {
    Err(ApiError::NotImplemented(
        "API endpoint has not yet been implemented, but is planned to be soon.".to_owned(),
    ))
}

pub async fn route<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    context: Arc<RwLock<RouterContext<T, E>>>,
) -> Result<Response<Body>, Error> {
    let path = req.uri().path().to_string();

    let log = context.read().log.clone();

    debug!(log, "HTTP API request"; "path" => &path);

    // Map the Rust-friendly `Result` in to a http-friendly response. In effect, this ensures that
    // any `Err` returned from our response handlers becomes a valid http response to the client
    // (e.g., a response with a 404 or 500 status).
    match route_to_api_result(&path, req, context).await {
        // request_result.then(move |result| match result {
        Ok(response) => {
            debug!(log, "HTTP API request successful"; "path" => path);

            Ok(response)
        }
        Err(e) => {
            let error_response = e.into();

            debug!(log, "HTTP API request failure"; "path" => path);

            Ok(error_response)
        }
    }
}

pub async fn route_to_api_result<T: SlotClock + 'static, E: EthSpec>(
    path: &str,
    req: Request<Body>,
    context: Arc<RwLock<RouterContext<T, E>>>,
) -> ApiResult {
    let (validator_client, beacon_node) = {
        let context = context.read();
        (context.validator_client()?, context.beacon_node()?)
    };

    match (req.method(), path) {
        // Methods for Validator
        (&Method::GET, "/validators/") => {
            validator::get_validators::<T, E>(req, validator_client, beacon_node).await
        }
        (&Method::POST, "/validators/add") => {
            validator::add_new_validator::<T, E>(req, validator_client).await
        }
        (&Method::POST, "/validators/remove") => {
            validator::remove_validator::<T, E>(req, validator_client).await
        }
        (&Method::POST, "/validators/start") => {
            validator::start_validator::<T, E>(req, validator_client).await
        }
        (&Method::POST, "/validators/stop") => {
            validator::stop_validator::<T, E>(req, validator_client).await
        }
        (&Method::POST, "/validators/exit") => {
            validator::exit_validator::<T, E>(req, validator_client, beacon_node).await
        }
        (&Method::POST, "/validators/withdraw") => implementation_pending_response(req),

        // Methods for beacon node status
        (&Method::GET, "/status/beacon_node") => implementation_pending_response(req),

        _ => Err(ApiError::NotFound(
            "Request path and/or method not found.".to_owned(),
        )),
    }
}
