use super::errors::{ApiError, ApiResult};
use super::{validator, wallet};
use crate::{DutiesService, ValidatorStore};
use hyper::{Body, Error, Method, Request, Response};
use remote_beacon_node::RemoteBeaconNode;
use slog::{debug, Logger};
use slot_clock::SlotClock;
use std::path::PathBuf;
use std::sync::Arc;
use types::{ChainSpec, EthSpec};

pub struct RouterContext<T: SlotClock + 'static, E: EthSpec> {
    pub validator_store: Option<ValidatorStore<T, E>>,
    pub duties_service: Option<DutiesService<T, E>>,
    pub beacon_node: Option<RemoteBeaconNode<E>>,
    pub wallets_dir: PathBuf,
    pub validators_dir: PathBuf,
    pub secrets_dir: PathBuf,
    pub spec: Arc<ChainSpec>,
    pub log: Logger,
}

impl<T: SlotClock + 'static, E: EthSpec> RouterContext<T, E> {
    pub fn duties_service(&self) -> Result<&DutiesService<T, E>, ApiError> {
        self.duties_service
            .as_ref()
            .ok_or_else(|| ApiError::MethodNotAllowed("duties_service not initialized".to_string()))
    }

    pub fn validator_store(&self) -> Result<&ValidatorStore<T, E>, ApiError> {
        self.validator_store.as_ref().ok_or_else(|| {
            ApiError::MethodNotAllowed("validator_store not initialized".to_string())
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
    context: Arc<RouterContext<T, E>>,
) -> Result<Response<Body>, Error> {
    let path = req.uri().path().to_string();

    let log = context.log.clone();

    debug!(log, "HTTP API request"; "path" => &path);

    // Map the Rust-friendly `Result` in to a http-friendly response. In effect, this ensures that
    // any `Err` returned from our response handlers becomes a valid http response to the client
    // (e.g., a response with a 404 or 500 status).
    match route_to_api_result(&path, req, &context).await {
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
    context: &RouterContext<T, E>,
) -> ApiResult {
    match (req.method(), path) {
        (&Method::GET, "/validators") => {
            validator::get_validators::<T, E>(
                req,
                context.validator_store()?,
                context.beacon_node()?,
                context.duties_service()?,
                &context.spec,
            )
            .await
        }
        (&Method::POST, "/validators/create/wallet") => {
            validator::create_validator_from_wallet::<T, E>(
                req,
                context.validator_store()?,
                &context.wallets_dir,
                &context.validators_dir,
                &context.secrets_dir,
                &context.spec,
            )
            .await
        }
        (&Method::GET, "/wallets") => wallet::list_wallets::<T, E>(req, &context.wallets_dir).await,
        (&Method::POST, "/wallets") => {
            wallet::create_wallet::<T, E>(req, &context.wallets_dir, &context.secrets_dir).await
        }
        /*
        (&Method::POST, "/validators/add") => {
            validator::add_new_validator::<T, E>(req, validator_store).await
        }
        (&Method::POST, "/validators/remove") => {
            validator::remove_validator::<T, E>(req, validator_store).await
        }
        (&Method::POST, "/validators/start") => {
            validator::start_validator::<T, E>(req, validator_store).await
        }
        (&Method::POST, "/validators/stop") => {
            validator::stop_validator::<T, E>(req, validator_store).await
        }
        (&Method::POST, "/validators/exit") => {
            validator::exit_validator::<T, E>(req, validator_store, beacon_node).await
        }
        */
        (&Method::POST, "/validators/withdraw") => implementation_pending_response(req),

        // Methods for beacon node status
        (&Method::GET, "/status/beacon_node") => implementation_pending_response(req),
        _ => Err(ApiError::NotFound(
            "Request path and/or method not found.".to_owned(),
        )),
    }
}
