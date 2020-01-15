use super::errors::{ApiError, ApiResult, BoxFut};
use super::response_builder::ResponseBuilder;
use hyper::{Body, Request};
use std::sync::Arc;
use types::EthSpec;
use validator_store::ValidatorStore;

pub fn get_validators<T, E: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
    // let service = validator_client.duties_service.clone();
    // let validators = service.validators();
    // ResponseBuilder::new(&req)?.body(&validators)
}

pub fn create_validator<T, E: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}

pub fn add_new_validator<T, E: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}

pub fn remove_validator<T, E: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}

pub fn start_validator<T, E: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}

pub fn stop_validator<T, E: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}

pub fn exit_validator<T, E: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}

pub fn withdraw_validator<T, E: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ValidatorStore<T, E>>,
) -> ApiResult {
    unimplemented!()
}
