use super::response_builder::ResponseBuilder;
use crate::ProductionValidatorClient;
use hyper::{Body, Request};
use std::sync::Arc;
use types::EthSpec;
use super::errors::{ApiError, ApiResult, BoxFut};

pub fn beacon_node_status<T: EthSpec>(
    req: Request<Body>,
    validator_client: Arc<ProductionValidatorClient<T>>,
) -> ApiResult {
    unimplemented!()
}
