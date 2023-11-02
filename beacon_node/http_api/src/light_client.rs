use beacon_chain::{BeaconChain, BeaconChainTypes};
use bytes::Bytes;
use eth2::types;
use eth2::types::{self as api_types};
use slot_clock::SlotClock;
use ssz::Encode;
use std::sync::Arc;
use types::{light_client_bootstrap::LightClientBootstrap, EthSpec, Hash256};
use warp::{
    hyper::{Body, Response},
    Reply,
};

use crate::version::add_consensus_version_header;

pub async fn get_light_client_bootstrap<T: BeaconChainTypes, E: EthSpec>(
    chain: Arc<BeaconChain<T>>,
    block_root: Hash256,
    accept_header: Option<api_types::Accept>,
) -> Result<Response<Body>, warp::Rejection> {
    let is_altair_or_greater = chain
        .spec
        .altair_fork_epoch
        .and_then(|fork_epoch| {
            let current_epoch = chain.slot_clock.now()?.epoch(E::slots_per_epoch());
            Some(current_epoch >= fork_epoch)
        })
        .unwrap_or(false);

    if !is_altair_or_greater {
        return Err(warp_utils::reject::custom_bad_request(format!(
            "cannot fetch pre altair"
        )));
    }

    let block = chain
        .get_block(&block_root)
        .await
        .map_err(|e| {
            warp_utils::reject::custom_bad_request(format!("failed to fetch beacon block: {:?}", e))
        })?
        .ok_or_else(|| warp_utils::reject::custom_bad_request(format!("no beacon block found")))?;

    let mut state = chain
        .get_state(&block.state_root(), Some(block.slot()))
        .map_err(|e| {
            warp_utils::reject::custom_bad_request(format!("failed to fetch beacon state: {:?}", e))
        })?
        .ok_or_else(|| warp_utils::reject::custom_bad_request(format!("no beacon state found")))?;

    let fork_name = state.fork_name(&chain.spec).map_err(|e| {
        warp_utils::reject::custom_bad_request(format!("failed to fetch fork name: {:?}", e))
    })?;

    let light_client_bootstrap =
        LightClientBootstrap::create_light_client_bootstrap(&mut state, block).map_err(|e| {
            warp_utils::reject::custom_bad_request(format!(
                "failed to create light client bootstrap: {:?}",
                e
            ))
        })?;

    match accept_header {
        Some(_) => Response::builder()
            .status(200)
            .header("Content-Type", "application/octet-stream")
            .body(light_client_bootstrap.as_ssz_bytes().into())
            .map(|res: Response<Bytes>| add_consensus_version_header(res, fork_name))
            .map_err(|e| {
                warp_utils::reject::custom_server_error(format!("failed to create response: {}", e))
            }),
        None => Ok(add_consensus_version_header(
            warp::reply::json(&light_client_bootstrap).into_response(),
            fork_name,
        )),
    }
}
