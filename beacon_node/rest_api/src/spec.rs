use super::ApiResult;
use crate::helpers::get_beacon_chain_from_request;
use crate::response_builder::ResponseBuilder;
use crate::ApiError;
use beacon_chain::BeaconChainTypes;
use eth2_config::Eth2Config;
use hyper::{Body, Request};
use std::sync::Arc;
use types::EthSpec;

/// HTTP handler to return the full spec object.
pub fn get_spec<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let beacon_chain = get_beacon_chain_from_request::<T>(&req)?;
    ResponseBuilder::new(&req)?.body_no_ssz(&beacon_chain.spec)
}

/// HTTP handler to return the full Eth2Config object.
pub fn get_eth2_config<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let eth2_config = req
        .extensions()
        .get::<Arc<Eth2Config>>()
        .ok_or_else(|| ApiError::ServerError("Eth2Config extension missing".to_string()))?;

    ResponseBuilder::new(&req)?.body_no_ssz(eth2_config.as_ref())
}

/// HTTP handler to return the full spec object.
pub fn get_slots_per_epoch<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    ResponseBuilder::new(&req)?.body(&T::EthSpec::slots_per_epoch())
}
