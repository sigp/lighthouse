use crate::helpers::*;
use crate::response_builder::ResponseBuilder;
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
    let beacon_chain = get_beacon_chain_from_request::<T>(&req)?;
    ResponseBuilder::new(&req).body(&beacon_chain.head().beacon_state.genesis_time)
}
