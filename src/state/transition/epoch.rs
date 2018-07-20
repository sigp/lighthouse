use super::active_state::ActiveState;
use super::crystallized_state::CrystallizedState;
use super::validator_record::ValidatorRecord;
use super::utils::types::{ Bitfield, U256, Sha256Digest };
use super::utils::logging::Logger;
use super::config::Config;

use super::deposits::process_ffg_deposits;
use super::crosslinks::process_crosslinks;
use super::attestors::process_recent_attesters;
use super::proposers::process_recent_proposers;
use super::validators::get_incremented_validator_sets;
use super::shuffling::get_shuffling;

pub fn initialize_new_epoch(
    cry_state: &CrystallizedState,
    act_state: &ActiveState,
    config: &Config,
    log: &Logger) 
    -> (CrystallizedState, ActiveState)
{
    let mut new_validator_records: Vec<ValidatorRecord> = 
        cry_state.active_validators.to_vec();
    let ffg_voter_bitfield: Bitfield = 
        act_state.ffg_voter_bitfield.clone();

    let (ffg_deltas, _, _,
         should_justify, should_finalize) = process_ffg_deposits (
             &cry_state,
             &ffg_voter_bitfield,
             &log);

    info!(log, "processed ffg deposits";
            "should_justify" => should_justify, 
            "should_finalize" => should_finalize);

    let (crosslink_notaries_deltas, new_crosslinks) = 
        process_crosslinks(
            &cry_state,
            &act_state.partial_crosslinks,
            &config);

    info!(log, "processed crosslinks";
            "new_crosslinks_count" => new_crosslinks.len());

    let recent_attesters_deltas = process_recent_attesters(
        &cry_state,
        &act_state.recent_attesters,
        &config);

    let recent_proposers_deltas = process_recent_proposers(
        &cry_state,
        &act_state.recent_proposers);

    for (i, validator) in new_validator_records.iter_mut().enumerate() {
        let balance: i64 = 
            validator.balance.low_u64() as i64 +
            ffg_deltas[i] + 
            crosslink_notaries_deltas[i] +
            recent_attesters_deltas[i] +
            recent_proposers_deltas[i];
        if balance > 0 {
            validator.balance = U256::from(balance as u64);
        } else {
            validator.balance = U256::zero();
        }
    }
   
    let deposit_sum: i64 = 
        ffg_deltas.iter().sum::<i64>() + 
        crosslink_notaries_deltas.iter().sum::<i64>() +
        recent_attesters_deltas.iter().sum::<i64>() +
        recent_proposers_deltas.iter().sum::<i64>();

    info!(log, "processed validator deltas";
            "new_total_deposits" => deposit_sum);

    let total_deposits: U256 = match deposit_sum > 0 {
        true => U256::from(deposit_sum as u64),
        false => U256::zero()
    };

    let last_justified_epoch = match should_justify {
        true => cry_state.current_epoch,
        false => cry_state.last_justified_epoch
    };

    let (last_finalized_epoch, dynasty) = match should_finalize {
        true => (cry_state.current_epoch - 1, cry_state.dynasty + 1),
        false => (cry_state.last_finalized_epoch, cry_state.dynasty)
    };

    let (new_queued_validators, new_active_validators, new_exited_validators) =
        match should_finalize 
    {
        true => get_incremented_validator_sets(
            &cry_state,
            &new_validator_records,
            &config,
            &log),
        false => (cry_state.queued_validators.to_vec(), 
                  cry_state.active_validators.to_vec(),
                  cry_state.exited_validators.to_vec())
    };

    let shuffling = get_shuffling(
        &act_state.randao,
        &new_active_validators.len(),
        &config);

    let new_cry_state = CrystallizedState {
        active_validators: new_active_validators,
        queued_validators: new_queued_validators,
        exited_validators: new_exited_validators,
        current_shuffling: shuffling,
        current_epoch: cry_state.current_epoch + 1,
        last_justified_epoch,
        last_finalized_epoch,
        dynasty,
        // TODO: why is this zero?
        next_shard: 0,
        // TODO: currenct checkpoint wasnt in reference implementation
        current_checkpoint: Sha256Digest::zero(),
        crosslink_records: new_crosslinks,
        total_deposits
    };

    info!(log, "created new crystallized state";
            "epoch" => new_cry_state.current_epoch,
            "last_justified_epoch" => new_cry_state.last_justified_epoch,
            "last_finalized_epoch" => new_cry_state.last_finalized_epoch);

    let new_act_state = ActiveState {
        height: act_state.height + 1,
        // TODO: update to new randao
        randao: act_state.randao,
        ffg_voter_bitfield: Bitfield::new(),
        recent_attesters: vec![],
        partial_crosslinks: vec![],
        total_skip_count: act_state.total_skip_count,
        recent_proposers: vec![]
    };

    info!(log, "created new active state";
            "height" => new_act_state.height);

    (new_cry_state, new_act_state)
}


