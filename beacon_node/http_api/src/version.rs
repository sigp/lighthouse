use crate::api_types::EndpointVersion;
use eth2::{
    CONSENSUS_BLOCK_VALUE_HEADER, CONSENSUS_VERSION_HEADER, EXECUTION_PAYLOAD_BLINDED_HEADER,
    EXECUTION_PAYLOAD_VALUE_HEADER,
};
use serde::Serialize;
use types::{
    fork_versioned_response::{
        ExecutionOptimisticFinalizedForkVersionedResponse, ExecutionOptimisticFinalizedMetadata,
    },
    ForkName, ForkVersionedResponse, InconsistentFork, Uint256,
};
use warp::reply::{self, Reply, Response};

pub const V1: EndpointVersion = EndpointVersion(1);
pub const V2: EndpointVersion = EndpointVersion(2);
pub const V3: EndpointVersion = EndpointVersion(3);

pub fn fork_versioned_response<T: Serialize>(
    endpoint_version: EndpointVersion,
    fork_name: ForkName,
    data: T,
) -> Result<ForkVersionedResponse<T>, warp::reject::Rejection> {
    let fork_name = if endpoint_version == V1 {
        None
    } else if endpoint_version == V2 || endpoint_version == V3 {
        Some(fork_name)
    } else {
        return Err(unsupported_version_rejection(endpoint_version));
    };
    Ok(ForkVersionedResponse {
        version: fork_name,
        metadata: Default::default(),
        data,
    })
}

pub fn execution_optimistic_finalized_fork_versioned_response<T: Serialize>(
    endpoint_version: EndpointVersion,
    fork_name: ForkName,
    execution_optimistic: bool,
    finalized: bool,
    data: T,
) -> Result<ExecutionOptimisticFinalizedForkVersionedResponse<T>, warp::reject::Rejection> {
    let fork_name = if endpoint_version == V1 {
        None
    } else if endpoint_version == V2 {
        Some(fork_name)
    } else {
        return Err(unsupported_version_rejection(endpoint_version));
    };
    Ok(ExecutionOptimisticFinalizedForkVersionedResponse {
        version: fork_name,
        metadata: ExecutionOptimisticFinalizedMetadata {
            execution_optimistic: Some(execution_optimistic),
            finalized: Some(finalized),
        },
        data,
    })
}

/// Add the `Eth-Consensus-Version` header to a response.
pub fn add_consensus_version_header<T: Reply>(reply: T, fork_name: ForkName) -> Response {
    reply::with_header(reply, CONSENSUS_VERSION_HEADER, fork_name.to_string()).into_response()
}

/// Add the `Eth-Execution-Payload-Blinded` header to a response.
pub fn add_execution_payload_blinded_header<T: Reply>(
    reply: T,
    execution_payload_blinded: bool,
) -> Response {
    reply::with_header(
        reply,
        EXECUTION_PAYLOAD_BLINDED_HEADER,
        execution_payload_blinded.to_string(),
    )
    .into_response()
}

/// Add the `Eth-Execution-Payload-Value` header to a response.
pub fn add_execution_payload_value_header<T: Reply>(
    reply: T,
    execution_payload_value: Uint256,
) -> Response {
    reply::with_header(
        reply,
        EXECUTION_PAYLOAD_VALUE_HEADER,
        execution_payload_value.to_string(),
    )
    .into_response()
}

/// Add the `Eth-Consensus-Block-Value` header to a response.
pub fn add_consensus_block_value_header<T: Reply>(
    reply: T,
    consensus_payload_value: Uint256,
) -> Response {
    reply::with_header(
        reply,
        CONSENSUS_BLOCK_VALUE_HEADER,
        consensus_payload_value.to_string(),
    )
    .into_response()
}

pub fn inconsistent_fork_rejection(error: InconsistentFork) -> warp::reject::Rejection {
    warp_utils::reject::custom_server_error(format!("wrong fork: {:?}", error))
}

pub fn unsupported_version_rejection(version: EndpointVersion) -> warp::reject::Rejection {
    warp_utils::reject::custom_bad_request(format!("Unsupported endpoint version: {}", version))
}
