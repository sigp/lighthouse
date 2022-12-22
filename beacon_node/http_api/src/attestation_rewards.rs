use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::types::ValidatorId;
use eth2::lighthouse::AttestationRewardsTBD;
use safe_arith::SafeArith;
use slog::Logger;
use participation_cache::ParticipationCache;
use state_processing::{per_epoch_processing::altair::{participation_cache, rewards_and_penalties::get_flag_weight}, common::altair::{BaseRewardPerIncrement, get_base_reward}};
use types::{Epoch, EthSpec};
use types::consts::altair::WEIGHT_DENOMINATOR;

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
    let participation_cache = participation_cache.or_else(|_| {
        Err(warp_utils::reject::custom_server_error("Unable to get participation cache".to_owned()))
    })?;

    //TODO Define flag_index as usize
    let flag_index = 0;

    //Use get_flag_weight to get weight
    let weight = get_flag_weight(flag_index);

    //Get total_active_balance through current_epoch_total_active_balance
    let total_active_balance = participation_cache.current_epoch_total_active_balance();

    //Get active_increments through total_active_balance and spec.effective_balance_increment
    let active_increments = total_active_balance.safe_div(spec.effective_balance_increment);

    //Get base_reward_per_increment through BaseRewardPerIncrement::new
    let base_reward_per_increment = BaseRewardPerIncrement::new(total_active_balance, spec);

    //Use pattern matching to handle ok and error cases of base_reward_per_increment
    let base_reward_per_increment = match base_reward_per_increment {
        Ok(base_reward_per_increment) => base_reward_per_increment,
        Err(e) => return Err(warp_utils::reject::custom_server_error(format!("Unable to get base reward per increment: {:?}", e))),
    };

    //Get index from participation_cache.eligible_validator_indices
    let index = participation_cache.eligible_validator_indices();

    //TODO Loop through index
    let base_reward = get_base_reward(&state, index[0], base_reward_per_increment, spec);

    //Get previous_epoch through state.previous_epoch()
    let previous_epoch = state.previous_epoch();

    //Get unslashed_participating_indices
    let unslashed_participating_indices = participation_cache.get_unslashed_participating_indices(flag_index, previous_epoch);

    //Unwrap unslashed_participating_indices
    let unslashed_participating_indices = unslashed_participating_indices.or_else(|_| {
        Err(warp_utils::reject::custom_server_error("Unable to get unslashed participating indices".to_owned()))
    })?;

    //Get unslashed_participating_balance
    let unslashed_participating_balance = unslashed_participating_indices.total_balance();

    //Unwrap unslashed_participating_balance
    let unslashed_participating_balance = unslashed_participating_balance.or_else(|_| {
        Err(warp_utils::reject::custom_server_error("Unable to get unslashed participating balance".to_owned()))
    })?;

    //Get unslashed_participating_increments
    let unslashed_participating_increments = unslashed_participating_balance.safe_div(spec.effective_balance_increment);

    //Unwrap unslashed_participating_increments
    let unslashed_participating_increments = unslashed_participating_increments.or_else(|_| {
        Err(warp_utils::reject::custom_server_error("Unable to get unslashed participating increments".to_owned()))
    })?;

    //Unwrap weight to u64
    let weight = weight.or_else(|_| {
        Err(warp_utils::reject::custom_server_error("Unable to get weight".to_owned()))
    })?;

    //Unwrap base_reward to u64
    let base_reward = base_reward.or_else(|_| {
        Err(warp_utils::reject::custom_server_error("Unable to get base reward".to_owned()))
    })?;
    
    //Calculate reward_numerator = base_reward * weight * unslashed_participating_increments with Error handling
    let reward_numerator = base_reward.safe_mul(weight).and_then(|reward_numerator| {
        reward_numerator.safe_mul(unslashed_participating_increments)
    }).or_else(|_| {
        Err(warp_utils::reject::custom_server_error("Unable to calculate reward numerator".to_owned()))
    })?;

    //Get active_increments
    let active_increments = total_active_balance.safe_div(spec.effective_balance_increment);

    //Unwrap active_increments to u64
    let active_increments = active_increments.or_else(|_| {
        Err(warp_utils::reject::custom_server_error("Unable to get active increments".to_owned()))
    })?;

    //Calculate reward = reward_numerator // (active_increments * WEIGHT_DENOMINATOR)
    let reward = reward_numerator.safe_div(active_increments).and_then(|reward| {
        reward.safe_div(WEIGHT_DENOMINATOR)
    }).or_else(|_| {
        Err(warp_utils::reject::custom_server_error("Unable to calculate reward".to_owned()))
    })?;

    //--- Calculate actual rewards ---//

    Ok(AttestationRewardsTBD{
        execution_optimistic: false,
        finalized: false,
        data: vec![],
    })

}