use super::errors::{ApiError, ApiResult, BoxFut};
use super::response_builder::ResponseBuilder;
use crate::ProductionValidatorClient;
use hyper::{Body, Request};
use std::sync::Arc;
use types::EthSpec;

pub fn get_validators<T: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ProductionValidatorClient<T>>,
) -> ApiResult {
    unimplemented!()
    // let service = validator_client.duties_service.clone();
    // let validators = service.validators();
    // ResponseBuilder::new(&req)?.body(&validators)
}

pub fn create_validator<T: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ProductionValidatorClient<T>>,
) -> ApiResult {
    unimplemented!()
}

pub fn add_new_validator<T: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ProductionValidatorClient<T>>,
) -> ApiResult {
    unimplemented!()
}

pub fn remove_validator<T: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ProductionValidatorClient<T>>,
) -> ApiResult {
    unimplemented!()
}

pub fn start_validator<T: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ProductionValidatorClient<T>>,
) -> ApiResult {
    unimplemented!()
}

pub fn stop_validator<T: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ProductionValidatorClient<T>>,
) -> ApiResult {
    unimplemented!()
}

pub fn exit_validator<T: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ProductionValidatorClient<T>>,
) -> ApiResult {
    unimplemented!()
}

pub fn withdraw_validator<T: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ProductionValidatorClient<T>>,
) -> ApiResult {
    unimplemented!()
}
