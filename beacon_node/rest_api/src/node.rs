use crate::helpers::get_beacon_chain_from_request;
use crate::{success_response, ApiResult};
use beacon_chain::BeaconChainTypes;
use hyper::{Body, Request};
use version;

/// Read the version string from the current Lighthouse build.
pub fn get_version(_req: Request<Body>) -> ApiResult {
    let body = Body::from(
        serde_json::to_string(&version::version())
            .expect("Version should always be serialializable as JSON."),
    );
    Ok(success_response(body))
}

/// Read the genesis time from the current beacon chain state.
pub fn get_genesis_time<T: BeaconChainTypes + 'static>(req: Request<Body>) -> ApiResult {
    let (_beacon_chain, head_state) = get_beacon_chain_from_request::<T>(&req)?;
    let gen_time: u64 = head_state.genesis_time;
    let body = Body::from(
        serde_json::to_string(&gen_time)
            .expect("Genesis should time always have a valid JSON serialization."),
    );
    Ok(success_response(body))
}
