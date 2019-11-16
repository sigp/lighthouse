use crate::response_builder::ResponseBuilder;
use crate::ApiResult;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use hyper::{Body, Request};
use std::sync::Arc;
use version;

/// Read the version string from the current Lighthouse build.
pub fn get_version(req: Request<Body>) -> ApiResult {
    ResponseBuilder::new(&req)?.body_no_ssz(&version::version())
}

/// Read the genesis time from the current beacon chain state.
pub fn get_genesis_time<T: BeaconChainTypes + 'static>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    ResponseBuilder::new(&req)?.body(&beacon_chain.head().beacon_state.genesis_time)
}
