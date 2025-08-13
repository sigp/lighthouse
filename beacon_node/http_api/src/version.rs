use crate::api_types::EndpointVersion;
use eth2::{
    CONSENSUS_BLOCK_VALUE_HEADER, CONSENSUS_VERSION_HEADER, CONTENT_TYPE_HEADER,
    EXECUTION_PAYLOAD_BLINDED_HEADER, EXECUTION_PAYLOAD_VALUE_HEADER, SSZ_CONTENT_TYPE_HEADER,
};
use serde::Serialize;
use types::{
    BeaconResponse, ForkName, ForkVersionedResponse, InconsistentFork, Uint256,
    UnversionedResponse,
    beacon_response::{
        ExecutionOptimisticFinalizedBeaconResponse, ExecutionOptimisticFinalizedMetadata,
    },
};
use warp::reply::{self, Reply, Response};

pub const V1: EndpointVersion = EndpointVersion(1);
pub const V2: EndpointVersion = EndpointVersion(2);
pub const V3: EndpointVersion = EndpointVersion(3);

#[derive(Debug, PartialEq, Clone, Serialize)]
pub enum ResponseIncludesVersion {
    Yes(ForkName),
    No,
}

pub fn beacon_response<T: Serialize>(
    require_version: ResponseIncludesVersion,
    data: T,
) -> BeaconResponse<T> {
    match require_version {
        ResponseIncludesVersion::Yes(fork_name) => {
            BeaconResponse::ForkVersioned(ForkVersionedResponse {
                version: fork_name,
                metadata: Default::default(),
                data,
            })
        }
        ResponseIncludesVersion::No => BeaconResponse::Unversioned(UnversionedResponse {
            metadata: Default::default(),
            data,
        }),
    }
}

pub fn execution_optimistic_finalized_beacon_response<T: Serialize>(
    require_version: ResponseIncludesVersion,
    execution_optimistic: bool,
    finalized: bool,
    data: T,
) -> Result<ExecutionOptimisticFinalizedBeaconResponse<T>, warp::reject::Rejection> {
    let metadata = ExecutionOptimisticFinalizedMetadata {
        execution_optimistic: Some(execution_optimistic),
        finalized: Some(finalized),
    };
    match require_version {
        ResponseIncludesVersion::Yes(fork_name) => {
            Ok(BeaconResponse::ForkVersioned(ForkVersionedResponse {
                version: fork_name,
                metadata,
                data,
            }))
        }
        ResponseIncludesVersion::No => Ok(BeaconResponse::Unversioned(UnversionedResponse {
            metadata,
            data,
        })),
    }
}

/// Add the 'Content-Type application/octet-stream` header to a response.
pub fn add_ssz_content_type_header<T: Reply>(reply: T) -> Response {
    reply::with_header(reply, CONTENT_TYPE_HEADER, SSZ_CONTENT_TYPE_HEADER).into_response()
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
