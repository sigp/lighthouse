use super::errors::ApiResult;
use hyper::{Body, Request};
use remote_beacon_node::RemoteBeaconNode;
use std::sync::Arc;
use types::EthSpec;

/// Gets beacon node sync status or returns.
/// Returns an error if cannot connect to beacon node.
pub fn beacon_node_status<T: EthSpec>(
    _req: Request<Body>,
    _beacon_node: Arc<RemoteBeaconNode<T>>,
) -> ApiResult {
    unimplemented!()
}
