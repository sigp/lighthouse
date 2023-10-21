use bytes::Bytes;
use std::sync::Arc;
use types::{payload::BlockProductionVersion, *};

use beacon_chain::{
    BeaconBlockResponseType, BeaconChain, BeaconChainError, BeaconChainTypes,
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
/// Uses the `chain.validator_pubkey_cache` to resolve a pubkey to a validator
/// index and then ensures that the validator exists in the given `state`.
pub fn pubkey_to_validator_index<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    state: &BeaconState<T::EthSpec>,
    pubkey: &PublicKeyBytes,
) -> Result<Option<usize>, BeaconChainError> {
    chain
        .validator_index(pubkey)?
        .filter(|&index| {
            state
                .validators()
                .get(index)
                .map_or(false, |v| v.pubkey == *pubkey)
        })
        .map(Result::Ok)
        .transpose()
}

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

    build_response_v2(chain, block_response_type, endpoint_version, accept_header)
}

pub async fn produce_block_v3<T: BeaconChainTypes>(
    endpoint_version: EndpointVersion,
    accept_header: Option<api_types::Accept>,
    chain: Arc<BeaconChain<T>>,
    slot: Slot,
    query: api_types::ValidatorBlocksQuery,
) -> Result<Response<Body>, warp::Rejection> {
    if let Some(accept_header_type) = accept_header {
        match accept_header_type {
            api_types::Accept::Json | api_types::Accept::Any => {
                determine_and_produce_block_json(endpoint_version, chain, slot, query).await
            }
            api_types::Accept::Ssz => determine_and_produce_block_ssz(chain, slot, query).await,
        }
    } else {
        determine_and_produce_block_json(endpoint_version, chain, slot, query).await
    }
}

pub async fn determine_and_produce_block_json<T: BeaconChainTypes>(
    endpoint_version: EndpointVersion,
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

    generate_json_response_v3(chain, block_response_type, endpoint_version)
}

pub async fn determine_and_produce_block_ssz<T: BeaconChainTypes>(
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

    let (block_ssz, fork_name, block_value, blinded) = match chain
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
        })? {
        BeaconBlockResponseType::Full(block_response) => {
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

            (
                block_contents.as_ssz_bytes(),
                fork_name,
                block_response.execution_payload_value,
                false,
            )
        }
        BeaconBlockResponseType::Blinded(block_response) => {
            let fork_name = block_response
                .block
                .to_ref()
                .fork_name(&chain.spec)
                .map_err(inconsistent_fork_rejection)?;

            let block_contents = build_block_contents::build_blinded_block_contents(
                fork_name,
                block_response.block,
                block_response.maybe_side_car,
            )?;

            (
                block_contents.as_ssz_bytes(),
                fork_name,
                block_response.execution_payload_value,
                true,
            )
        }
    };

    Response::builder()
        .status(200)
        .header("Content-Type", "application/ssz")
        .body(block_ssz.into())
        .map(|res: Response<Body>| add_consensus_version_header(res, fork_name))
        .map(|res| add_execution_payload_blinded_header(res, blinded))
        .map(|res: Response<Body>| add_execution_payload_value_header(res, block_value))
        .map_err(|e| -> warp::Rejection {
            warp_utils::reject::custom_server_error(format!("failed to create response: {}", e))
        })
}

pub fn generate_json_response_v3<T: BeaconChainTypes, E: EthSpec>(
    chain: Arc<BeaconChain<T>>,
    beacon_block_response_type: BeaconBlockResponseType<E>,
    endpoint_version: EndpointVersion,
) -> Result<Response<Body>, warp::Rejection> {
    match beacon_block_response_type {
        BeaconBlockResponseType::Full(beacon_block_response) => {
            let fork_name = beacon_block_response
                .block
                .to_ref()
                .fork_name(&chain.spec)
                .map_err(inconsistent_fork_rejection)?;

            let block_contents = build_block_contents::build_block_contents(
                fork_name,
                beacon_block_response.block,
                beacon_block_response.maybe_side_car,
            )?;

            fork_versioned_response(endpoint_version, fork_name, block_contents)
                .map(|response| warp::reply::json(&response).into_response())
                .map(|res| add_consensus_version_header(res, fork_name))
                .map(|res| add_execution_payload_blinded_header(res, false))
                .map(|res| {
                    add_execution_payload_value_header(
                        res,
                        beacon_block_response.execution_payload_value,
                    )
                })
                .map(|res| {
                    add_consensus_block_value_header(
                        res,
                        beacon_block_response.consensus_block_value,
                    )
                })
        }
        BeaconBlockResponseType::Blinded(beacon_block_response) => {
            let fork_name = beacon_block_response
                .block
                .to_ref()
                .fork_name(&chain.spec)
                .map_err(inconsistent_fork_rejection)?;

            let block_contents = build_block_contents::build_blinded_block_contents(
                fork_name,
                beacon_block_response.block,
                beacon_block_response.maybe_side_car,
            )?;

            fork_versioned_response(endpoint_version, fork_name, block_contents)
                .map(|response| warp::reply::json(&response).into_response())
                .map(|res| add_consensus_version_header(res, fork_name))
                .map(|res| add_execution_payload_blinded_header(res, true))
                .map(|res| {
                    add_execution_payload_value_header(
                        res,
                        beacon_block_response.execution_payload_value,
                    )
                })
                .map(|res| {
                    add_consensus_block_value_header(
                        res,
                        beacon_block_response.consensus_block_value,
                    )
                })
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

    build_response_v2(chain, block_response_type, endpoint_version, accept_header)
}

pub fn build_response_v2<T: BeaconChainTypes, E: EthSpec>(
    chain: Arc<BeaconChain<T>>,
    block_response_type: BeaconBlockResponseType<E>,
    endpoint_version: EndpointVersion,
    accept_header: Option<api_types::Accept>,
) -> Result<Response<Body>, warp::Rejection> {
    match block_response_type {
        BeaconBlockResponseType::Full(block_response) => {
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
                        warp_utils::reject::custom_server_error(format!(
                            "failed to create response: {}",
                            e
                        ))
                    }),
                _ => fork_versioned_response(endpoint_version, fork_name, block_contents)
                    .map(|response| warp::reply::json(&response).into_response())
                    .map(|res| add_consensus_version_header(res, fork_name)),
            }
        }
        BeaconBlockResponseType::Blinded(block_response) => {
            let fork_name = block_response
                .block
                .to_ref()
                .fork_name(&chain.spec)
                .map_err(inconsistent_fork_rejection)?;

            let block_contents = build_block_contents::build_blinded_block_contents(
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
                        warp_utils::reject::custom_server_error(format!(
                            "failed to create response: {}",
                            e
                        ))
                    }),
                _ => fork_versioned_response(endpoint_version, fork_name, block_contents)
                    .map(|response| warp::reply::json(&response).into_response())
                    .map(|res| add_consensus_version_header(res, fork_name)),
            }
        }
    }
}
