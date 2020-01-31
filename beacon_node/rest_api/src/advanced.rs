use crate::response_builder::ResponseBuilder;
use crate::ApiResult;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use hyper::{Body, Request};
use std::sync::Arc;

/// Returns the `proto_array` fork choice struct, encoded as JSON.
///
/// Useful for debugging or advanced inspection of the chain.
pub fn get_fork_choice<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    ResponseBuilder::new(&req)?.body_no_ssz(&*beacon_chain.fork_choice.core_proto_array())
}
