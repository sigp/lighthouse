use crate::response_builder::ResponseBuilder;
use crate::ApiResult;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use hyper::{Body, Request};
use operation_pool::PersistedOperationPool;
use std::sync::Arc;

/// Returns the `proto_array` fork choice struct, encoded as JSON.
///
/// Useful for debugging or advanced inspection of the chain.
pub fn get_fork_choice<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    ResponseBuilder::new(&req)?.body_no_ssz(
        &*beacon_chain
            .fork_choice
            .read()
            .proto_array()
            .core_proto_array(),
    )
}

/// Returns the `PersistedOperationPool` struct.
///
/// Useful for debugging or advanced inspection of the stored operations.
pub fn get_operation_pool<T: BeaconChainTypes>(
    req: Request<Body>,
    beacon_chain: Arc<BeaconChain<T>>,
) -> ApiResult {
    ResponseBuilder::new(&req)?.body(&PersistedOperationPool::from_operation_pool(
        &beacon_chain.op_pool,
    ))
}
