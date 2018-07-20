extern crate rlp;

use super::bytes;
use super::config;
use super::utils;
use super::blake2;
use super::active_state;
use super::aggregate_vote;
use super::crystallized_state;
use super::crosslink_record;
use super::partial_crosslink_record;
use super::recent_proposer_record;
use super::validator_record;
use super::block;

pub mod new_active_state;
pub mod crosslinks;
pub mod deposits;
pub mod epoch;
pub mod ffg;
pub mod proposers;
pub mod shuffling;
pub mod validators;
pub mod attestors;


use super::block::Block;
use super::config::Config;
use super::crystallized_state::CrystallizedState;
use super::active_state::ActiveState;
use super::transition::epoch::initialize_new_epoch;
use super::transition::new_active_state::compute_new_active_state;
use super::utils::logging::Logger;

pub fn compute_state_transition (
    parent_cry_state: &CrystallizedState,
    parent_act_state: &ActiveState,
    parent_block: &Block,
    block: &Block,
    config: &Config,
    log: &Logger) 
    -> (CrystallizedState, ActiveState)
{
    let is_new_epoch =  parent_act_state.height % 
        config.epoch_length == 0;
    
    let (cry_state, mut act_state) = match is_new_epoch {
        false => (parent_cry_state.clone(), parent_act_state.clone()),
        true => initialize_new_epoch(
            &parent_cry_state,
            &parent_act_state,
            &config,
            &log)
    };
    
    if is_new_epoch {
        info!(log, "initialized new epoch";
              "epoch" => cry_state.current_epoch);
    }


    act_state = compute_new_active_state(
        &cry_state,
        &act_state,
        &parent_block,
        &block,
        &config,
        &log);

    (cry_state, act_state)
}
