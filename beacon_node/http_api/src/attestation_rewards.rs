use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::ValidatorId;
use eth2::lighthouse::AttestationRewardsTBD;
use slog::Logger;
use participation_cache::ParticipationCache;
use state_processing::{per_epoch_processing::altair::{participation_cache, rewards_and_penalties::get_flag_weight}};
use types::{Epoch, EthSpec};

pub fn compute_attestation_rewards<T: BeaconChainTypes>(
    chain: Arc<BeaconChain<T>>,
    epoch: Epoch,
    validators: Vec<ValidatorId>,
    log: Logger
) -> Result<AttestationRewardsTBD, warp::Rejection> {    

    //--- Get state ---//

    //Get spec from chain
    let spec = &chain.spec;

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

    //Get state from state_root and state_slot
    let mut state = chain.get_state(&state_root, Some(state_slot)).or_else(|_| {
        Err(warp_utils::reject::custom_server_error("Unable to get state".to_owned()))
    })?;

    //--- Calculate ideal rewards for 33 (0...32) values ---//

    //Unwrap state as BeaconState
    let state = state.ok_or_else(|| {
        warp_utils::reject::custom_server_error("Unable to get state".to_owned())
    })?;

    //Create ParticipationCache
    let participation_cache = ParticipationCache::new(&state, spec);

    //TODO Define flag_index as usize
    let flag_index = 0;

    //Use get_flag_weight
    let weight = get_flag_weight(flag_index);

    //--- Calculate actual rewards ---//

    Ok(AttestationRewardsTBD{
        execution_optimistic: false,
        finalized: false,
        data: vec![],
    })

}