use crate::response_builder::ResponseBuilder;
use crate::ApiResult;
use hyper::{Body, Request};
use version;

/// Read the version string from the current Lighthouse build.
pub fn get_version(req: Request<Body>) -> ApiResult {
    ResponseBuilder::new(&req)?.body_no_ssz(&version::version())
}

pub fn syncing(req: Request<Body>, network: Arc<NetworkGlobals<T::EthSpec>>) -> ApiResult {
    ResponseBuilder::new(&req)?.body_no_ssz(&version::version())
}
