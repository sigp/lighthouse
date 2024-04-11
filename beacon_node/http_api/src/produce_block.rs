use crate::{
    build_block_contents,
    version::{
        add_consensus_block_value_header, add_consensus_version_header,
        add_execution_payload_blinded_header, add_execution_payload_value_header,
        add_ssz_content_type_header, fork_versioned_response, inconsistent_fork_rejection,
    },
};
use beacon_chain::{
    BeaconBlockResponseWrapper, BeaconChain, BeaconChainTypes, ProduceBlockVerification,
};
use eth2::types::{
    self as api_types, EndpointVersion, ProduceBlockV3Metadata, SkipRandaoVerification,
};
use ssz::Encode;
use std::sync::Arc;
use types::{payload::BlockProductionVersion, *};
use warp::{
    hyper::{Body, Response},
    Reply,
};

/// If default boost factor is provided in validator/blocks v3 request, we will skip the calculation
/// to keep the precision.
const DEFAULT_BOOST_FACTOR: u64 = 100;

pub fn get_randao_verification(
    query: &api_types::ValidatorBlocksQuery,
    randao_reveal_infinity: bool,
) -> Result<ProduceBlockVerification, warp::Rejection> {
    let randao_verification = if query.skip_randao_verification == SkipRandaoVerification::Yes {
        if !randao_reveal_infinity {
            return Err(warp_utils::reject::custom_bad_request(
                "randao_reveal must be point-at-infinity if verification is skipped".into(),
            ));
        }
        ProduceBlockVerification::NoVerification
    } else {
        ProduceBlockVerification::VerifyRandao
    };

    Ok(randao_verification)
}

pub async fn produce_block_v3<T: BeaconChainTypes>(
    accept_header: Option<api_types::Accept>,
    chain: Arc<BeaconChain<T>>,
    slot: Slot,
    query: api_types::ValidatorBlocksQuery,
) -> Result<Response<Body>, warp::Rejection> {
    let randao_reveal = query.randao_reveal.decompress().map_err(|e| {
        warp_utils::reject::custom_bad_request(format!(
            "randao reveal is not a valid BLS signature: {:?}",
            e
        ))
    })?;

    let randao_verification = get_randao_verification(&query, randao_reveal.is_infinity())?;
    let builder_boost_factor = if query.builder_boost_factor == Some(DEFAULT_BOOST_FACTOR) {
        None
    } else {
        query.builder_boost_factor
    };

    let block_response_type = chain
        .produce_block_with_verification(
            randao_reveal,
            slot,
            query.graffiti,
            randao_verification,
            builder_boost_factor,
            BlockProductionVersion::V3,
        )
        .await
        .map_err(|e| {
            warp_utils::reject::custom_bad_request(format!("failed to fetch a block: {:?}", e))
        })?;

    build_response_v3(chain, block_response_type, accept_header)
}

pub fn build_response_v3<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_response: BeaconBlockResponseWrapper<T::EthSpec>,
    accept_header: Option<api_types::Accept>,
) -> Result<Response<Body>, warp::Rejection> {
    let fork_name = block_response
        .fork_name(&chain.spec)
        .map_err(inconsistent_fork_rejection)?;
    let execution_payload_value = block_response.execution_payload_value();
    let consensus_block_value = block_response.consensus_block_value_wei();
    let execution_payload_blinded = block_response.is_blinded();

    let metadata = ProduceBlockV3Metadata {
        consensus_version: fork_name,
        execution_payload_blinded,
        execution_payload_value,
        consensus_block_value,
    };

    let block_contents = build_block_contents::build_block_contents(fork_name, block_response)?;

    match accept_header {
        Some(api_types::Accept::Ssz) => Response::builder()
            .status(200)
            .body(block_contents.as_ssz_bytes().into())
            .map(|res: Response<Body>| add_ssz_content_type_header(res))
            .map(|res: Response<Body>| add_consensus_version_header(res, fork_name))
            .map(|res| add_execution_payload_blinded_header(res, execution_payload_blinded))
            .map(|res: Response<Body>| {
                add_execution_payload_value_header(res, execution_payload_value)
            })
            .map(|res| add_consensus_block_value_header(res, consensus_block_value))
            .map_err(|e| -> warp::Rejection {
                warp_utils::reject::custom_server_error(format!("failed to create response: {}", e))
            }),
        _ => Ok(warp::reply::json(&ForkVersionedResponse {
            version: Some(fork_name),
            metadata,
            data: block_contents,
        })
        .into_response())
        .map(|res| res.into_response())
        .map(|res| add_consensus_version_header(res, fork_name))
        .map(|res| add_execution_payload_blinded_header(res, execution_payload_blinded))
        .map(|res| add_execution_payload_value_header(res, execution_payload_value))
        .map(|res| add_consensus_block_value_header(res, consensus_block_value)),
    }
}

pub async fn produce_blinded_block_v2<T: BeaconChainTypes>(
    endpoint_version: EndpointVersion,
    accept_header: Option<api_types::Accept>,
    chain: Arc<BeaconChain<T>>,
    slot: Slot,
    query: api_types::ValidatorBlocksQuery,
) -> Result<Response<Body>, warp::Rejection> {
    let randao_reveal = query.randao_reveal.decompress().map_err(|e| {
        warp_utils::reject::custom_bad_request(format!(
            "randao reveal is not a valid BLS signature: {:?}",
            e
        ))
    })?;

    let randao_verification = get_randao_verification(&query, randao_reveal.is_infinity())?;
    let block_response_type = chain
        .produce_block_with_verification(
            randao_reveal,
            slot,
            query.graffiti.map(Into::into),
            randao_verification,
            None,
            BlockProductionVersion::BlindedV2,
        )
        .await
        .map_err(warp_utils::reject::block_production_error)?;

    build_response_v2(chain, block_response_type, endpoint_version, accept_header)
}

pub async fn produce_block_v2<T: BeaconChainTypes>(
    endpoint_version: EndpointVersion,
    accept_header: Option<api_types::Accept>,
    chain: Arc<BeaconChain<T>>,
    slot: Slot,
    query: api_types::ValidatorBlocksQuery,
) -> Result<Response<Body>, warp::Rejection> {
    let randao_reveal = query.randao_reveal.decompress().map_err(|e| {
        warp_utils::reject::custom_bad_request(format!(
            "randao reveal is not a valid BLS signature: {:?}",
            e
        ))
    })?;

    let randao_verification = get_randao_verification(&query, randao_reveal.is_infinity())?;

    let block_response_type = chain
        .produce_block_with_verification(
            randao_reveal,
            slot,
            query.graffiti.map(Into::into),
            randao_verification,
            None,
            BlockProductionVersion::FullV2,
        )
        .await
        .map_err(warp_utils::reject::block_production_error)?;

    build_response_v2(chain, block_response_type, endpoint_version, accept_header)
}

pub fn build_response_v2<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_response: BeaconBlockResponseWrapper<T::EthSpec>,
    endpoint_version: EndpointVersion,
    accept_header: Option<api_types::Accept>,
) -> Result<Response<Body>, warp::Rejection> {
    let fork_name = block_response
        .fork_name(&chain.spec)
        .map_err(inconsistent_fork_rejection)?;

    let block_contents = build_block_contents::build_block_contents(fork_name, block_response)?;

    match accept_header {
        Some(api_types::Accept::Ssz) => Response::builder()
            .status(200)
            .body(block_contents.as_ssz_bytes().into())
            .map(|res: Response<Body>| add_ssz_content_type_header(res))
            .map(|res: Response<Body>| add_consensus_version_header(res, fork_name))
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!("failed to create response: {}", e))
            }),
        _ => fork_versioned_response(endpoint_version, fork_name, block_contents)
            .map(|response| warp::reply::json(&response).into_response())
            .map(|res| add_consensus_version_header(res, fork_name)),
    }
}
