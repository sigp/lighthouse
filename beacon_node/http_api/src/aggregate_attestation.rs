use crate::api_types::GenericResponse;
use crate::unsupported_version_rejection;
use crate::version::{add_consensus_version_header, V1, V2};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::{self, EndpointVersion, Hash256, Slot};
use std::sync::Arc;
use types::fork_versioned_response::EmptyMetadata;
use types::{CommitteeIndex, ForkVersionedResponse};
use warp::{
    hyper::{Body, Response},
    reply::Reply,
};

pub fn get_aggregate_attestation<T: BeaconChainTypes>(
    slot: Slot,
    attestation_data_root: &Hash256,
    committee_index: Option<CommitteeIndex>,
    endpoint_version: EndpointVersion,
    chain: Arc<BeaconChain<T>>,
) -> Result<Response<Body>, warp::reject::Rejection> {
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

    if endpoint_version == V2 {
        let fork_versioned_response = ForkVersionedResponse {
            version: Some(fork_name),
            metadata: EmptyMetadata {},
            data: aggregate_attestation,
        };
        Ok(add_consensus_version_header(
            warp::reply::json(&fork_versioned_response).into_response(),
            fork_name,
        ))
    } else if endpoint_version == V1 {
        Ok(warp::reply::json(&GenericResponse::from(aggregate_attestation)).into_response())
    } else {
        return Err(unsupported_version_rejection(endpoint_version));
    }
}
