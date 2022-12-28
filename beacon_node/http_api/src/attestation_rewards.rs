use std::sync::Arc;
use beacon_chain::{BeaconChain, BeaconChainTypes};
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
    flag_index: usize,
    log: Logger
) -> Result<AttestationRewardsTBD, warp::Rejection> {    

    //--- Get state ---//

    //Get spec from chain
    let spec = &chain.spec;

    //Get state_slot from the end_slot of epoch + 1
    let state_slot = (epoch + 1).end_slot(T::EthSpec::slots_per_epoch());

    //Get state_root as H256 from state_slot
    let state_root = match chain.state_root_at_slot(state_slot) {
        Ok(Some(state_root)) => state_root,
        Ok(None) => return Err(warp_utils::reject::custom_server_error("Unable to get state root".to_owned())),
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get state root".to_owned())),
    };

    //Get state from state_root and state_slot
    let state = match chain.get_state(&state_root, Some(state_slot)) {
        Ok(Some(state)) => state,
        Ok(None) => return Err(warp_utils::reject::custom_server_error("State not found".to_owned())),
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get state".to_owned())),
    };

    //--- Calculate ideal rewards for 33 (0...32) values ---//

    //Create ParticipationCache
    let participation_cache = match ParticipationCache::new(&state, spec) {
        Ok(participation_cache) => participation_cache,
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get participation cache".to_owned())),
    };

    //Get weight as u64
    let weight = match get_flag_weight(flag_index) {
        Ok(weight) => weight,
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get weight".to_owned())),
    };
    
    //Get total_active_balance through current_epoch_total_active_balance
    let total_active_balance = participation_cache.current_epoch_total_active_balance();
    
    //TODO (flag, effective_balance) -> ideal_reward, while flag is head/target/source   

    //Get base_reward_per_increment through BaseRewardPerIncrement::new
    let base_reward_per_increment = match BaseRewardPerIncrement::new(total_active_balance, spec) {
        Ok(base_reward_per_increment) => base_reward_per_increment,
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get base reward per increment".to_owned())),
    };    

    //Get index from participation_cache.eligible_validator_indices
    let index = participation_cache.eligible_validator_indices();

    //TODO Loop through index
    let base_reward = get_base_reward(&state, index[0], base_reward_per_increment, spec);

    //Get previous_epoch through state.previous_epoch()
    let previous_epoch = state.previous_epoch();

    //Get unslashed_participating_indices
    let unslashed_participating_indices = match participation_cache.get_unslashed_participating_indices(flag_index, previous_epoch) {
        Ok(unslashed_participating_indices) => unslashed_participating_indices,
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get unslashed participating indices".to_owned())),
    };    

    //Get unslashed_participating_balance
    let unslashed_participating_balance = match unslashed_participating_indices.total_balance() {
        Ok(unslashed_participating_balance) => unslashed_participating_balance,
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get unslashed participating balance".to_owned())),
    };    

    //Get unslashed_participating_increments
    let unslashed_participating_increments = match unslashed_participating_balance.safe_div(spec.effective_balance_increment) {
        Ok(unslashed_participating_increments) => unslashed_participating_increments,
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get unslashed participating increments".to_owned())),
    };  

    //Unwrap base_reward to u64
    let base_reward = match base_reward {
        Ok(base_reward) => base_reward,
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get base reward".to_owned())),
    };
    
    //Calculate reward_numerator = base_reward * weight * unslashed_participating_increments with Error handling
    let reward_numerator = match base_reward.safe_mul(weight).and_then(|reward_numerator| {
        reward_numerator.safe_mul(unslashed_participating_increments)}) {
        Ok(reward_numerator) => reward_numerator,
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to calculate reward numerator".to_owned())),
    };

    //Get active_increments
    let active_increments = match total_active_balance.safe_div(spec.effective_balance_increment) {
        Ok(active_increments) => active_increments,
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get active increments".to_owned())),
    };    

    //Calculate reward = reward_numerator // (active_increments * WEIGHT_DENOMINATOR)
    let reward = match reward_numerator.safe_div(active_increments) {
        Ok(reward) => match reward.safe_div(WEIGHT_DENOMINATOR) {
            Ok(reward) => reward,
            Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to calculate reward: Division by WEIGHT_DENOMINATOR failed".to_owned())),
        },
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to calculate reward: Division by active_increments failed".to_owned())),
    };

    //TODO Put reward in Vec<IdealAttestationRewards>

    //--- Calculate actual rewards ---//

    //Check if the validator index is eligible for rewards using state.is_eligible_validator(epoch, validator_index)
    let eligible = match state.is_eligible_validator(previous_epoch, index[0]) {
        Ok(eligible) => eligible,
        Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get eligible".to_owned())),
    };

    //TODO add error handling to everything below

    //If eligible is false, change the reward to 0
    let reward = if eligible {
        reward
    } else {
        0
    };

    //Check if they voted correctly for the flag (head/target/source) by checking if their validator index appears in participation_cache.get_unslashed_participating_indices(flag, epoch)
    let voted_correctly = participation_cache.get_unslashed_participating_indices(flag_index, previous_epoch).is_ok();

    //If they voted correctly, they get paid the ideal_reward for (flag, validator.effective_balance), which can be looked up in the ideal rewards map.
    //If they voted incorrectly, then for the head vote their reward is 0, and for target/source it is -1 * base_reward * weight // WEIGHT_DENOMINATOR
    let actual_reward = if voted_correctly {
        reward
    } else {
        if flag_index == 0 {
            0
        } else {
            base_reward.safe_mul(weight).and_then(|reward| {
                reward.safe_div(WEIGHT_DENOMINATOR)
            }).and_then(|reward| {
                reward.safe_mul(1)
            }).or_else(|_| {
                Err(warp_utils::reject::custom_server_error("Unable to calculate actual reward".to_owned()))
            })?
        }
    };

    //TODO Put actual_reward in Vec<AttestationRewardsTBD>
    //TODO Code cleanup

    Ok(AttestationRewardsTBD{
        execution_optimistic: false,
        finalized: false,
        data: vec![],
    })

}