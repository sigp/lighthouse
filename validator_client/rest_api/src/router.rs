use super::errors::ApiError;
use super::errors::BoxFut;
use super::status;
use super::validator;
use futures::{Future, IntoFuture};
use hyper::{Body, Error, Method, Request, Response};
use remote_beacon_node::RemoteBeaconNode;
use slog::debug;
use slot_clock::SlotClock;
use std::sync::Arc;
use types::EthSpec;
use validator_store::ValidatorStore;

fn into_boxfut<F: IntoFuture + 'static>(item: F) -> BoxFut
where
    F: IntoFuture<Item = Response<Body>, Error = ApiError>,
    F::Future: Send,
{
    Box::new(item.into_future())
}

pub fn route<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ValidatorStore<T, E>>,
    beacon_node: Arc<RemoteBeaconNode<E>>,
    local_log: slog::Logger,
) -> impl Future<Item = Response<Body>, Error = Error> {
    let path = req.uri().path().to_string();

    let log = local_log.clone();
    let request_result: Box<dyn Future<Item = Response<_>, Error = _> + Send> =
        match (req.method(), path.as_ref()) {
            // Methods for Validator
            (&Method::GET, "/validators/") => {
                into_boxfut(validator::get_validators::<T, E>(req, validator_client))
            }
            (&Method::POST, "/validators/add") => {
                validator::add_new_validator::<T, E>(req, validator_client)
            }
            (&Method::POST, "/validators/remove") => {
                validator::remove_validator::<T, E>(req, validator_client)
            }
            (&Method::POST, "/validators/start") => {
                validator::start_validator::<T, E>(req, validator_client)
            }
            (&Method::POST, "/validators/stop") => {
                validator::stop_validator::<T, E>(req, validator_client)
            }
            (&Method::POST, "/validators/exit") => {
                into_boxfut(validator::exit_validator::<T, E>(req, validator_client))
            }
            (&Method::POST, "/validators/withdraw") => {
                into_boxfut(validator::withdraw_validator::<T, E>(req, validator_client))
            }

            // Methods for beacon node status
            (&Method::GET, "/status/beacon_node") => {
                into_boxfut(status::beacon_node_status::<E>(req, beacon_node))
            }

            _ => Box::new(futures::future::err(ApiError::NotFound(
                "Request path and/or method not found.".to_owned(),
            ))),
        };

    // Map the Rust-friendly `Result` in to a http-friendly response. In effect, this ensures that
    // any `Err` returned from our response handlers becomes a valid http response to the client
    // (e.g., a response with a 404 or 500 status).
    request_result.then(move |result| match result {
        Ok(response) => {
            debug!(local_log, "HTTP API request successful"; "path" => path);

            Ok(response)
        }
        Err(e) => {
            let error_response = e.into();

            debug!(local_log, "HTTP API request failure"; "path" => path);

            Ok(error_response)
        }
    })
}
