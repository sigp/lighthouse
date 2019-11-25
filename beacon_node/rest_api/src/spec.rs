use super::ApiResult;
use crate::response_builder::ResponseBuilder;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2_config::Eth2Config;
use hyper::{Body, Request};
use std::sync::Arc;
use types::EthSpec;

/// HTTP handler to return the full spec object.
pub fn get_spec<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    ResponseBuilder::new(&req)?.body_no_ssz(&beacon_chain.spec)
}

/// HTTP handler to return the full Eth2Config object.
pub fn get_eth2_config<T: BeaconChainTypes>(
    req: Request<Body>,
    eth2_config: Arc<Eth2Config>,
) -> ApiResult {
    ResponseBuilder::new(&req)?.body_no_ssz(eth2_config.as_ref())
}

/// HTTP handler to return the full spec object.
pub fn get_slots_per_epoch<T: BeaconChainTypes>(req: Request<Body>) -> ApiResult {
    ResponseBuilder::new(&req)?.body(&T::EthSpec::slots_per_epoch())
}
