use crate::version::{
    add_consensus_version_header, add_ssz_content_type_header, fork_versioned_response, V1,
};
use beacon_chain::{BeaconChain, BeaconChainError, BeaconChainTypes};
use eth2::types::{
    self as api_types, ChainSpec, ForkVersionedResponse, LightClientUpdate,
    LightClientUpdateResponseChunk, LightClientUpdateSszResponse, LightClientUpdatesQuery,
};
use ssz::Encode;
use std::sync::Arc;
use types::{ForkName, Hash256, LightClientBootstrap};
use warp::{
    hyper::{Body, Response},
    reply::Reply,
    Rejection,
};

const MAX_REQUEST_LIGHT_CLIENT_UPDATES: u64 = 128;

pub fn get_light_client_updates<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    query: LightClientUpdatesQuery,
    accept_header: Option<api_types::Accept>,
) -> Result<Response<Body>, Rejection> {
    validate_light_client_updates_request(&chain, &query)?;

    let light_client_updates = chain
        .get_light_client_updates(query.start_period, query.count)
        .map_err(|_| {
            warp_utils::reject::custom_not_found("No LightClientUpdates found".to_string())
        })?;

    match accept_header {
        Some(api_types::Accept::Ssz) => {
            let response_chunks = light_client_updates
                .iter()
                .map(|update| map_light_client_update_to_ssz_chunk::<T>(&chain, update))
                .collect::<Vec<LightClientUpdateResponseChunk>>();

            let ssz_response = LightClientUpdateSszResponse {
                response_chunk_len: (light_client_updates.len() as u64).to_le_bytes().to_vec(),
                response_chunk: response_chunks.as_ssz_bytes(),
            }
            .as_ssz_bytes();

            Response::builder()
                .status(200)
                .body(ssz_response)
                .map(|res: Response<Vec<u8>>| add_ssz_content_type_header(res))
                .map_err(|e| {
                    warp_utils::reject::custom_server_error(format!(
                        "failed to create response: {}",
                        e
                    ))
                })
        }
        _ => {
            let fork_versioned_response = light_client_updates
                .iter()
                .map(|update| map_light_client_update_to_json_response::<T>(&chain, update.clone()))
                .collect::<Result<Vec<ForkVersionedResponse<LightClientUpdate<T::EthSpec>>>, Rejection>>()?;
            Ok(warp::reply::json(&fork_versioned_response).into_response())
        }
    }
}

pub fn get_light_client_bootstrap<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    block_root: &Hash256,
    accept_header: Option<api_types::Accept>,
) -> Result<Response<Body>, Rejection> {
    let (light_client_bootstrap, fork_name) = chain
        .get_light_client_bootstrap(block_root)
        .map_err(|err| {
            let error_message = if let BeaconChainError::LightClientBootstrapError(err) = err {
                println!("{:?}", err);
                err
            } else {
                "No LightClientBootstrap found".to_string()
            };
            warp_utils::reject::custom_not_found(error_message)
        })?
        .ok_or(warp_utils::reject::custom_not_found(
            "No LightClientBootstrap found".to_string(),
        ))?;

    match accept_header {
        Some(api_types::Accept::Ssz) => Response::builder()
            .status(200)
            .body(light_client_bootstrap.as_ssz_bytes().into())
            .map(|res: Response<Body>| add_consensus_version_header(res, fork_name))
            .map(|res: Response<Body>| add_ssz_content_type_header(res))
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!("failed to create response: {}", e))
            }),
        _ => {
            let fork_versioned_response = map_light_client_bootstrap_to_json_response::<T>(
                fork_name,
                light_client_bootstrap,
            )?;
            Ok(warp::reply::json(&fork_versioned_response).into_response())
        }
    }
}

pub fn validate_light_client_updates_request<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    query: &LightClientUpdatesQuery,
) -> Result<(), Rejection> {
    if query.count > MAX_REQUEST_LIGHT_CLIENT_UPDATES {
        return Err(warp_utils::reject::custom_bad_request(
            "Invalid count requested".to_string(),
        ));
    }

    let current_sync_period = chain
        .epoch()
        .map_err(|_| {
            warp_utils::reject::custom_server_error("failed to get current epoch".to_string())
        })?
        .sync_committee_period(&chain.spec)
        .map_err(|_| {
            warp_utils::reject::custom_server_error(
                "failed to get current sync committee period".to_string(),
            )
        })?;

    if query.start_period > current_sync_period {
        return Err(warp_utils::reject::custom_bad_request(
            "Invalid sync committee period requested".to_string(),
        ));
    }

    let earliest_altair_sync_committee = chain
        .spec
        .altair_fork_epoch
        .ok_or(warp_utils::reject::custom_server_error(
            "failed to get altair fork epoch".to_string(),
        ))?
        .sync_committee_period(&chain.spec)
        .map_err(|_| {
            warp_utils::reject::custom_server_error(
                "failed to get earliest altair sync committee".to_string(),
            )
        })?;

    if query.start_period < earliest_altair_sync_committee {
        return Err(warp_utils::reject::custom_bad_request(
            "Invalid sync committee period requested".to_string(),
        ));
    }

    Ok(())
}

fn map_light_client_update_to_ssz_chunk<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    light_client_update: &LightClientUpdate<T::EthSpec>,
) -> LightClientUpdateResponseChunk {
    let fork_name = chain
        .spec
        .fork_name_at_slot::<T::EthSpec>(*light_client_update.signature_slot());

    let fork_digest = ChainSpec::compute_fork_digest(
        chain.spec.fork_version_for_name(fork_name),
        chain.genesis_validators_root,
    );

    LightClientUpdateResponseChunk {
        context: fork_digest,
        payload: light_client_update.as_ssz_bytes(),
    }
}

fn map_light_client_bootstrap_to_json_response<T: BeaconChainTypes>(
    fork_name: ForkName,
    light_client_bootstrap: LightClientBootstrap<T::EthSpec>,
) -> Result<ForkVersionedResponse<LightClientBootstrap<T::EthSpec>>, Rejection> {
    fork_versioned_response(V1, fork_name, light_client_bootstrap)
}

fn map_light_client_update_to_json_response<T: BeaconChainTypes>(
    chain: &BeaconChain<T>,
    light_client_update: LightClientUpdate<T::EthSpec>,
) -> Result<ForkVersionedResponse<LightClientUpdate<T::EthSpec>>, Rejection> {
    let fork_name = chain
        .spec
        .fork_name_at_slot::<T::EthSpec>(*light_client_update.signature_slot());

    fork_versioned_response(V1, fork_name, light_client_update)
}
