use std::sync::Arc;

use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes, ProduceBlockVerification};
use eth2::types::{self as api_types, EndpointVersion, SkipRandaoVerification};
use ssz::Encode;
use types::*;
use warp::{
    hyper::{Body, Response},
    Reply,
};

use crate::version::{
    add_consensus_version_header, add_execution_payload_blinded_header,
    add_execution_payload_value_header, fork_versioned_response, inconsistent_fork_rejection,
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

pub async fn produce_block_json<T: BeaconChainTypes>(
    endpoint_version: EndpointVersion,
    chain: Arc<BeaconChain<T>>,
    slot: Slot,
    query: api_types::ValidatorBlocksQuery,
    block_type: BlockType,
) -> Result<Response<Body>, warp::Rejection> {
    let randao_reveal = query.randao_reveal.decompress().map_err(|e| {
        warp_utils::reject::custom_bad_request(format!(
            "randao reveal is not a valid BLS signature: {:?}",
            e
        ))
    })?;

    let randao_verification = get_randao_verification(&query, randao_reveal.is_infinity())?;

    match block_type {
        BlockType::Blinded => {
            let (block, _, block_value) = chain
                .produce_block_with_verification::<BlindedPayload<T::EthSpec>>(
                    randao_reveal,
                    slot,
                    query.graffiti.map(Into::into),
                    randao_verification,
                )
                .await
                .map_err(warp_utils::reject::block_production_error)?;

            let fork_name = block
                .to_ref()
                .fork_name(&chain.spec)
                .map_err(inconsistent_fork_rejection)?;

            fork_versioned_response(endpoint_version, fork_name, block)
                .map(|response| warp::reply::json(&response).into_response())
                .map(|res| add_consensus_version_header(res, fork_name))
                .map(|res| add_execution_payload_blinded_header(res, true))
                .map(|res: Response<Body>| add_execution_payload_value_header(res, block_value))
        }
        BlockType::Full => {
            let (block, _, block_value) = chain
                .produce_block_with_verification::<FullPayload<T::EthSpec>>(
                    randao_reveal,
                    slot,
                    query.graffiti.map(Into::into),
                    randao_verification,
                )
                .await
                .map_err(warp_utils::reject::block_production_error)?;

            let fork_name = block
                .to_ref()
                .fork_name(&chain.spec)
                .map_err(inconsistent_fork_rejection)?;

            fork_versioned_response(endpoint_version, fork_name, block)
                .map(|response| warp::reply::json(&response).into_response())
                .map(|res| add_consensus_version_header(res, fork_name))
                .map(|res| add_execution_payload_blinded_header(res, true))
                .map(|res: Response<Body>| add_execution_payload_value_header(res, block_value))
        }
    }
}

pub async fn produce_block_ssz<T: BeaconChainTypes>(
    endpoint_version: EndpointVersion,
    chain: Arc<BeaconChain<T>>,
    slot: Slot,
    query: api_types::ValidatorBlocksQuery,
    block_type: BlockType,
) -> Result<Response<Body>, warp::Rejection> {
    let randao_reveal = query.randao_reveal.decompress().map_err(|e| {
        warp_utils::reject::custom_bad_request(format!(
            "randao reveal is not a valid BLS signature: {:?}",
            e
        ))
    })?;

    let randao_verification = get_randao_verification(&query, randao_reveal.is_infinity())?;

    let (block_ssz, fork_name, block_value, blinded) = match block_type {
        BlockType::Blinded => {
            let (block, _, block_value) = chain
                .produce_block_with_verification::<BlindedPayload<T::EthSpec>>(
                    randao_reveal,
                    slot,
                    query.graffiti.map(Into::into),
                    randao_verification,
                )
                .await
                .map_err(warp_utils::reject::block_production_error)?;

            let fork_name = block
                .to_ref()
                .fork_name(&chain.spec)
                .map_err(inconsistent_fork_rejection)?;

            (block.as_ssz_bytes(), fork_name, block_value, true)
        }
        BlockType::Full => {
            let (block, _, block_value) = chain
                .produce_block_with_verification::<FullPayload<T::EthSpec>>(
                    randao_reveal,
                    slot,
                    query.graffiti.map(Into::into),
                    randao_verification,
                )
                .await
                .map_err(warp_utils::reject::block_production_error)?;

            let fork_name = block
                .to_ref()
                .fork_name(&chain.spec)
                .map_err(inconsistent_fork_rejection)?;

            (block.as_ssz_bytes(), fork_name, block_value, false)
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

/*
pub fn produce_block_json<T: BeaconChainTypes>(block: BeaconBlock<T::EthSpec>) -> Result<Response<Body>,warp::Rejection> {
    return Response::builder()
        .status(200)
        .header("Content-Type", "application/ssz")
        .body(block.as_ssz_bytes())
        .map_err(|e| -> warp::Rejection {
            warp_utils::reject::custom_server_error(format!(
                "failed to create response: {}",
                e
            ))
        })
}

pub async fn produce_block<T: BeaconChainTypes>(
    endpoint_version: EndpointVersion,
    chain: Arc<BeaconChain<T>>,
    accept_header: Option<api_types::Accept>,
    slot: Slot,
    query: api_types::ValidatorBlocksQuery,
    is_ssz_response: bool
) -> Result<Response<Body>, warp::Rejection> {
    let randao_reveal = query.randao_reveal.decompress().map_err(|e| {
        warp_utils::reject::custom_bad_request(format!(
            "randao reveal is not a valid BLS signature: {:?}",
            e
        ))
    })?;

    let randao_verification = if query.skip_randao_verification == SkipRandaoVerification::Yes {
        if !randao_reveal.is_infinity() {
            return Err(warp_utils::reject::custom_bad_request(
                "randao_reveal must be point-at-infinity if verification is skipped".into(),
            ));
        }
        ProduceBlockVerification::NoVerification
    } else {
        ProduceBlockVerification::VerifyRandao
    };

    // some logic here to decide full payload vs blinded

    // need to apply header Eth-Execution-Payload-Blinded if blinded or not


    // Eth-Execution-Payload-Value: need this header to detrermine relative value of exec payload in wei...

    let (block, _) = chain
        .produce_block_with_verification::<FullPayload<T::EthSpec>>(
            randao_reveal,
            slot,
            query.graffiti.map(Into::into),
            randao_verification,
        )
        .await
        .map_err(warp_utils::reject::block_production_error)?;

    let fork_name = block
        .to_ref()
        .fork_name(&chain.spec)
        .map_err(inconsistent_fork_rejection)?;

    if is_ssz_response {
        return Response::builder()
            .status(200)
            .header("Content-Type", "application/ssz")
            .body(block.as_ssz_bytes())
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!(
                    "failed to create response: {}",
                    e
                ))
            })
    } else {

    }

    fork_versioned_response(endpoint_version, fork_name, block)
        .map(|response| warp::reply::json(&response).into_response())
        .map(|res| add_consensus_version_header(res, fork_name))
}
*/
