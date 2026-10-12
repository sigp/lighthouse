use crate::api_types::GenericResponse;
use crate::unsupported_version_rejection;
use crate::version::{V1, V2, add_consensus_version_header, add_ssz_content_type_header};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::{self, Accept, EndpointVersion, Hash256, Slot};
use ssz::Encode;
use std::sync::Arc;
use types::beacon_response::EmptyMetadata;
use types::{CommitteeIndex, ForkVersionedResponse};
use warp::{Reply, http::response::Builder, reply::Response};

pub fn get_aggregate_attestation<T: BeaconChainTypes>(
    slot: Slot,
    attestation_data_root: &Hash256,
    committee_index: Option<CommitteeIndex>,
    endpoint_version: EndpointVersion,
    chain: Arc<BeaconChain<T>>,
    accept_header: Option<Accept>,
) -> Result<Response, warp::reject::Rejection> {
    let fork_name = chain.spec.fork_name_at_slot::<T::EthSpec>(slot);
    let aggregate_attestation = if fork_name.electra_enabled() {
        let Some(committee_index) = committee_index else {
            return Err(warp_utils::reject::custom_bad_request(
                "missing committee index".to_string(),
            ));
        };
        chain
            .get_aggregated_attestation_electra(slot, attestation_data_root, committee_index)
            .map_err(|e| {
                warp_utils::reject::custom_bad_request(format!(
                    "unable to fetch aggregate: {:?}",
                    e
                ))
            })?
            .ok_or_else(|| {
                warp_utils::reject::custom_not_found("no matching aggregate found".to_string())
            })?
    } else {
        chain
            .get_pre_electra_aggregated_attestation_by_slot_and_root(slot, attestation_data_root)
            .map_err(|e| {
                warp_utils::reject::custom_bad_request(format!(
                    "unable to fetch aggregate: {:?}",
                    e
                ))
            })?
            .ok_or_else(|| {
                warp_utils::reject::custom_not_found("no matching aggregate found".to_string())
            })?
    };

    match accept_header {
        Some(Accept::Ssz) => Builder::new()
            .status(200)
            .body(aggregate_attestation.as_ssz_bytes())
            .map(add_ssz_content_type_header)
            .map(|res| add_consensus_version_header(res, fork_name))
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!("failed to create response: {}", e))
            }),
        _ => {
            if endpoint_version == V2 {
                let fork_versioned_response = ForkVersionedResponse {
                    version: fork_name,
                    metadata: EmptyMetadata {},
                    data: aggregate_attestation,
                };
                Ok(add_consensus_version_header(
                    warp::reply::json(&fork_versioned_response).into_response(),
                    fork_name,
                ))
            } else if endpoint_version == V1 {
                Ok(
                    warp::reply::json(&GenericResponse::from(aggregate_attestation))
                        .into_response(),
                )
            } else {
                Err(unsupported_version_rejection(endpoint_version))
            }
        }
    }
}
