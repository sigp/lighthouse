use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::ValidatorId;
use eth2::lighthouse::AttestationRewardsTBD;
use slog::Logger;
use types::{Epoch, EthSpec};

pub fn compute_attestation_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    epoch: Epoch,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<AttestationRewardsTBD, warp::Rejection> {    

    //Get state_slot from the end_slot of epoch + 1
    let state_slot = (epoch + 1).end_slot(T::EthSpec::slots_per_epoch());

    //Get state_root as H256 from state_slot
    let state_root = chain.state_root_at_slot(state_slot).or_else(|_| {
        Err(warp_utils::reject::custom_server_error("Unable to get state root".to_owned()))
    })?;

    //Unwrap state_root as H256
    let state_root = state_root.ok_or_else(|| {
        warp_utils::reject::custom_server_error("Unable to get state root".to_owned())
    })?;

    // Get state from state_root and state_slot
    let mut state = chain.get_state(&state_root, Some(state_slot)).or_else(|_| {
        Err(warp_utils::reject::custom_server_error("Unable to get state".to_owned()))
    })?;

    Ok(AttestationRewardsTBD{
        execution_optimistic: false,
        finalized: false,
        data: vec![],
    })

}