use super::errors::{ApiError, ApiResult, BoxFut};
use super::response_builder::ResponseBuilder;
use hyper::{Body, Request};
use slot_clock::SlotClock;
use std::sync::Arc;
use types::EthSpec;
use validator_store::ValidatorStore;

pub fn get_validators<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    let validators = validator_store.voting_pubkeys();
    ResponseBuilder::new(&req)?.body(&validators)
}

pub fn add_new_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    // let
    unimplemented!()
}

pub fn remove_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}

pub fn start_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}

pub fn stop_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}

pub fn exit_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}

pub fn withdraw_validator<T: SlotClock + 'static, E: EthSpec>(
    req: Request<Body>,
    validator_store: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}
