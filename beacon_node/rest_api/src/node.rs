use crate::helpers::*;
use crate::{ApiResult, BoxFut};
use beacon_chain::BeaconChainTypes;
use hyper::{Body, Request};
use version;

/// Read the version string from the current Lighthouse build.
pub fn get_version(req: Request<Body>) -> ApiResult {
    success_response_2_json(req, &version::version())
}

/// Read the genesis time from the current beacon chain state.
pub fn get_genesis_time<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let (_beacon_chain, head_state) = get_beacon_chain_from_request::<T>(&req)?;
    let gen_time: u64 = head_state.genesis_time;
    success_response_2(req, &gen_time)
}
