use super::errors::{ApiError, ApiResult, BoxFut};
use super::response_builder::ResponseBuilder;
use hyper::{Body, Request};
use remote_beacon_node::RemoteBeaconNode;
use std::sync::Arc;
use types::EthSpec;

pub fn beacon_node_status<T: EthSpec>(
    req: Request<Body>,
    beacon_node: Arc<RemoteBeaconNode<T>>,
) -> ApiResult {
    unimplemented!()
}
