//! This contains a collection of lighthouse specific HTTP endpoints.

use crate::response_builder::ResponseBuilder;
use crate::ApiResult;
use eth2_libp2p::NetworkGlobals;
use hyper::{Body, Request};
use std::sync::Arc;
use types::EthSpec;

/// The syncing state of the beacon node.
pub fn syncing<T: EthSpec>(req: Request<Body>, network: Arc<NetworkGlobals<T>>) -> ApiResult {
    ResponseBuilder::new(&req)?.body_no_ssz(&network.sync_state())
}
