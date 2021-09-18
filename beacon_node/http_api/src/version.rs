use crate::api_types::{EndpointVersion, ForkVersionedResponse};
use serde::Serialize;
use types::ForkName;

pub const V1: EndpointVersion = EndpointVersion(1);
pub const V2: EndpointVersion = EndpointVersion(2);

pub fn fork_versioned_response<T: Serialize>(
    endpoint_version: EndpointVersion,
    fork_name: Option<ForkName>,
    data: T,
) -> Result<ForkVersionedResponse<T>, warp::reject::Rejection> {
    let fork_name = if endpoint_version == V1 {
        None
    } else if endpoint_version == V2 {
        fork_name
    } else {
        return Err(unsupported_version_rejection(endpoint_version));
    };
    Ok(ForkVersionedResponse {
        version: fork_name,
        data,
    })
}

pub fn unsupported_version_rejection(version: EndpointVersion) -> warp::reject::Rejection {
    warp_utils::reject::custom_bad_request(format!("Unsupported endpoint version: {}", version))
}
