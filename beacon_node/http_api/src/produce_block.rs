use bytes::Bytes;
use std::sync::Arc;
use types::{payload::BlockProductionVersion, *};

use beacon_chain::{
    BeaconBlockResponse, BeaconBlockResponseType, BeaconChain, BeaconChainTypes,
    ProduceBlockVerification,
};
use eth2::types::{self as api_types, EndpointVersion, SkipRandaoVerification};
use ssz::Encode;
use warp::{
    hyper::{Body, Response},
    Reply,
};

use crate::{
    build_block_contents,
    version::{
        add_consensus_block_value_header, add_consensus_version_header,
        add_execution_payload_blinded_header, add_execution_payload_value_header,
        fork_versioned_response, inconsistent_fork_rejection,
    },
};

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
            BlockProductionVersion::V3,
        )
        .await
        .map_err(|e| {
            warp_utils::reject::custom_bad_request(format!("failed to fetch a block: {:?}", e))
        })?;

    match block_response_type {
        BeaconBlockResponseType::Full(block_response) => {
            build_response_v3(chain, block_response, endpoint_version, accept_header)
        }
        BeaconBlockResponseType::Blinded(block_response) => {
            build_response_v3(chain, block_response, endpoint_version, accept_header)
        }
    }
}

pub fn build_response_v3<T: BeaconChainTypes, E: EthSpec, Payload: AbstractExecPayload<E>>(
    chain: Arc<BeaconChain<T>>,
    block_response: BeaconBlockResponse<E, Payload>,
    endpoint_version: EndpointVersion,
    accept_header: Option<api_types::Accept>,
) -> Result<Response<Body>, warp::Rejection> {
    let fork_name = block_response
        .block
        .to_ref()
        .fork_name(&chain.spec)
        .map_err(inconsistent_fork_rejection)?;

    let block_contents = build_block_contents::build_block_contents(
        fork_name,
        block_response.block,
        block_response.maybe_side_car,
    )?;

    let execution_payload_blinded = Payload::block_type() == BlockType::Blinded;

    match accept_header {
        Some(api_types::Accept::Ssz) => Response::builder()
            .status(200)
            .header("Content-Type", "application/ssz")
            .body(block_contents.as_ssz_bytes().into())
            .map(|res: Response<Body>| add_consensus_version_header(res, fork_name))
            .map(|res| add_execution_payload_blinded_header(res, execution_payload_blinded))
            .map(|res: Response<Body>| {
                add_execution_payload_value_header(res, block_response.execution_payload_value)
            })
            .map(|res| add_consensus_block_value_header(res, block_response.consensus_block_value))
            .map_err(|e| -> warp::Rejection {
                warp_utils::reject::custom_server_error(format!("failed to create response: {}", e))
            }),
        _ => fork_versioned_response(endpoint_version, fork_name, block_contents)
            .map(|response| warp::reply::json(&response).into_response())
            .map(|res| add_consensus_version_header(res, fork_name))
            .map(|res| add_execution_payload_blinded_header(res, execution_payload_blinded))
            .map(|res| {
                add_execution_payload_value_header(res, block_response.execution_payload_value)
            })
            .map(|res| add_consensus_block_value_header(res, block_response.consensus_block_value)),
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
            BlockProductionVersion::BlindedV2,
        )
        .await
        .map_err(warp_utils::reject::block_production_error)?;

    match block_response_type {
        BeaconBlockResponseType::Full(block_response) => {
            build_response_v2(chain, block_response, endpoint_version, accept_header)
        }
        BeaconBlockResponseType::Blinded(block_response) => {
            build_response_v2(chain, block_response, endpoint_version, accept_header)
        }
    }
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
            BlockProductionVersion::FullV2,
        )
        .await
        .map_err(warp_utils::reject::block_production_error)?;

    match block_response_type {
        BeaconBlockResponseType::Full(block_response) => {
            build_response_v2(chain, block_response, endpoint_version, accept_header)
        }
        BeaconBlockResponseType::Blinded(block_response) => {
            build_response_v2(chain, block_response, endpoint_version, accept_header)
        }
    }
}

pub fn build_response_v2<T: BeaconChainTypes, E: EthSpec, Payload: AbstractExecPayload<E>>(
    chain: Arc<BeaconChain<T>>,
    block_response: BeaconBlockResponse<E, Payload>,
    endpoint_version: EndpointVersion,
    accept_header: Option<api_types::Accept>,
) -> Result<Response<Body>, warp::Rejection> {
    let fork_name = block_response
        .block
        .to_ref()
        .fork_name(&chain.spec)
        .map_err(inconsistent_fork_rejection)?;

    let block_contents = build_block_contents::build_block_contents(
        fork_name,
        block_response.block,
        block_response.maybe_side_car,
    )?;

    match accept_header {
        Some(api_types::Accept::Ssz) => Response::builder()
            .status(200)
            .header("Content-Type", "application/octet-stream")
            .body(block_contents.as_ssz_bytes().into())
            .map(|res: Response<Bytes>| add_consensus_version_header(res, fork_name))
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!("failed to create response: {}", e))
            }),
        _ => fork_versioned_response(endpoint_version, fork_name, block_contents)
            .map(|response| warp::reply::json(&response).into_response())
            .map(|res| add_consensus_version_header(res, fork_name)),
    }
}
