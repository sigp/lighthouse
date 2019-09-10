use crate::helpers::*;
use crate::{ApiResult, BoxFut};
use beacon_chain::BeaconChainTypes;
use hyper::{Body, Request};
use version;

/// Read the version string from the current Lighthouse build.
pub fn get_version(req: Request<Body>) -> BoxFut {
    success_response_json(req, &version::version())
}

/// Read the genesis time from the current beacon chain state.
pub fn get_genesis_time<T: BeaconChainTypes + 'static>(req: Request<Body>) -> BoxFut {
    let bc = get_beacon_chain_from_request::<T>(&req);
    let (_beacon_chain, head_state) = match bc {
        Ok((bc, hs)) => (bc, hs),
        Err(e) => {
            return e.into();
        }
    };
    let gen_time: u64 = head_state.genesis_time;
    success_response(req, &gen_time)
}
