use std::{sync::Arc, collections::HashMap};
use beacon_chain::{BeaconChain, BeaconChainTypes};
use eth2::{lighthouse::AttestationRewardsTBD, types::ValidatorId};
use eth2::lighthouse::attestation_rewards::{IdealAttestationRewards, TotalAttestationRewards};
use safe_arith::SafeArith;
use slog::Logger;
use participation_cache::ParticipationCache;
use state_processing::{per_epoch_processing::altair::{participation_cache, rewards_and_penalties::get_flag_weight}, common::altair::{BaseRewardPerIncrement, get_base_reward}};
use types::{Epoch, EthSpec};
use types::consts::altair::WEIGHT_DENOMINATOR;
use types::consts::altair::{TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX, TIMELY_HEAD_FLAG_INDEX};

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
    
    //Get previous_epoch through state.previous_epoch()
    let previous_epoch = state.previous_epoch();

    //Initialize an empty HashMap to hold the rewards
    let mut ideal_rewards = HashMap::new();

    //Initialize base_reward and effective_balance_eth because they are being used in another loop
    let base_reward = 0;
    let effective_balance_eth = 0;
    let weight = 0;
    let flag_index = 0;

    for flag_index in [TIMELY_SOURCE_FLAG_INDEX, TIMELY_TARGET_FLAG_INDEX, TIMELY_HEAD_FLAG_INDEX].iter() {

        //Get weight as u64
        let weight = match get_flag_weight(*flag_index) {
            Ok(weight) => weight,
            Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get weight".to_owned())),
        };

        //Get unslashed_participating_indices
        let unslashed_participating_indices = match participation_cache.get_unslashed_participating_indices(*flag_index, previous_epoch) {
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

        //Get total_active_balance through current_epoch_total_active_balance
        let total_active_balance = participation_cache.current_epoch_total_active_balance();
        
        //Get active_increments
        let active_increments = match total_active_balance.safe_div(spec.effective_balance_increment) {
            Ok(active_increments) => active_increments,
            Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get active increments".to_owned())),
        };    
        
        //Get base_reward_per_increment through BaseRewardPerIncrement::new
        let base_reward_per_increment = match BaseRewardPerIncrement::new(total_active_balance, spec) {
            Ok(base_reward_per_increment) => base_reward_per_increment,
            Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get base reward per increment".to_owned())),
        };
        
        for effective_balance_eth in 0..=32 {
            //TODO Use safe_mul here
            let base_reward = get_base_reward(&state, effective_balance_eth, base_reward_per_increment, spec);

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
        
            //Calculate reward = reward_numerator // (active_increments * WEIGHT_DENOMINATOR)
            let reward = match reward_numerator.safe_div(active_increments) {
                Ok(reward) => match reward.safe_div(WEIGHT_DENOMINATOR) {
                    Ok(reward) => reward,
                    Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to calculate reward: Division by WEIGHT_DENOMINATOR failed".to_owned())),
                },
                Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to calculate reward: Division by active_increments failed".to_owned())),
            };
            
            if !state.is_in_inactivity_leak(previous_epoch, &spec) {
                //Push the rewards onto the HashMap
                ideal_rewards.insert((flag_index, effective_balance_eth), reward);
            } else {
                //Push the rewards onto the HashMap
                ideal_rewards.insert((flag_index, effective_balance_eth), 0);
            }  
        }
    }

    //TODO Output the ideal_rewards HashMap

    //--- Calculate actual rewards ---//
    
    let mut rewards = Vec::new();
    let index = participation_cache.eligible_validator_indices();
    
    for validator_index in index {
        let eligible = match state.is_eligible_validator(previous_epoch, *validator_index) {
            Ok(eligible) => eligible,
            Err(_) => return Err(warp_utils::reject::custom_server_error("Unable to get eligible".to_owned())),
        };
        let total_reward = if !eligible {
            0u64
        } else {
            //validator_index is eligible for rewards, calculate actual rewards 
            let voted_correctly = participation_cache.get_unslashed_participating_indices(flag_index, previous_epoch).is_ok();
            if voted_correctly {
                //Voted correctly, get paid the ideal_reward for (flag, validator.effective_balance)
                *ideal_rewards.get(&(&flag_index, effective_balance_eth)).unwrap_or(&0)
            } else {
                //Voted incorrectly, the head vote reward is 0, target/source their reward is -1 * base_reward * weight // WEIGHT_DENOMINATOR
                (-(base_reward as i64 as i128) * weight as i128 / WEIGHT_DENOMINATOR as i128) as u64
            }
        };
        rewards.push((*validator_index, total_reward));
    }

    //TODO Put actual_reward in Vec<AttestationRewardsTBD>
    //TODO Code cleanup

    //Convert ideal_rewards HashMap to Vec<IdealAttestationRewards>
    //TODO Check target and source
    let ideal_rewards_vec: Vec<IdealAttestationRewards> = ideal_rewards.iter().map(|((flag_index, effective_balance_eth), reward)| {
        IdealAttestationRewards {
            effective_balance: *effective_balance_eth as u64,
            head: *reward,
            target: 0,
            source: 0,
        }
    }).collect();

    Ok(AttestationRewardsTBD{
        execution_optimistic: false,
        finalized: false,
        ideal_rewards: ideal_rewards_vec,
        total_rewards: todo!(),
    })
}