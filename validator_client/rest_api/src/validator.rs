use super::errors::{ApiError, ApiResult, BoxFut};
use super::response_builder::ResponseBuilder;
use bls::PublicKey;
use futures::future::Future;
use futures::stream::Stream;
use hyper::{Body, Request};
use serde_derive::{Deserialize, Serialize};
use slot_clock::SlotClock;
use std::sync::Arc;
use types::EthSpec;
use validator_store::ValidatorStore;

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ValidatorRequest {
    validator: PublicKey,
}

pub fn get_validators<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: ValidatorStore<T, E>,
) -> ApiResult {
    let validators = validator_store.voting_pubkeys();
    ResponseBuilder::new(&req)?.body(&validators)
}

pub fn add_new_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: ValidatorStore<T, E>,
) -> ApiResult {
    // let
    unimplemented!()
}

pub fn remove_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    mut validator_store: ValidatorStore<T, E>,
) -> BoxFut {
    let response_builder = ResponseBuilder::new(&req);
    let future =
        req.into_body()
            .concat2()
            .map_err(|e| ApiError::ServerError(format!("Unable to get request body: {:?}", e)))
            .and_then(|chunks| {
                serde_json::from_slice::<ValidatorRequest>(&chunks).map_err(|e| {
                    ApiError::BadRequest(format!(
                        "Unable to parse JSON into ValidatorRequest: {:?}",
                        e
                    ))
                })
            })
            .and_then(move |body| {
                let validator_pubkey = body.validator;
                validator_store.remove_validator(&validator_pubkey).ok_or(
                    ApiError::ProcessingError(format!("Validator pubkey not present")),
                )
            })
            .and_then(|_| response_builder?.body_empty());
    Box::new(future)
}

pub fn start_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: ValidatorStore<T, E>,
) -> ApiResult {
    unimplemented!()
}

pub fn stop_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: ValidatorStore<T, E>,
) -> ApiResult {
    unimplemented!()
}

pub fn exit_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: ValidatorStore<T, E>,
) -> ApiResult {
    unimplemented!()
}

pub fn withdraw_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: ValidatorStore<T, E>,
) -> ApiResult {
    unimplemented!()
}
