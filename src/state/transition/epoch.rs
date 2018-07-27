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
    /*
     * Clone the cry_state active validators and the 
     * act_state ffg bitfield for later modification.
     */
    let mut new_validator_records: Vec<ValidatorRecord> = 
        cry_state.active_validators.to_vec();
    // TODO: why isnt this mut?
    let ffg_voter_bitfield: Bitfield = 
        act_state.ffg_voter_bitfield.clone();

    /*
     * For each active_validator in the cry_state, reward/penalize
     * them according to their presence in the ffg voter bitfield
     * (also with consideration to the cry_state finality distance).
     * These rewards/penalties are represented in the ffg_deltas vec.
     *
     * Determines if justification should take place based upon
     * the ratio of total deposits to voting deposits. If justification
     * is possible, finalize if the previous epoch was also justified.
     */
    let (ffg_deltas, _, _, should_justify, should_finalize) =
        process_ffg_deposits (
             &cry_state,
             &ffg_voter_bitfield,
             &log);

    info!(log, "processed ffg deposits";
            "should_justify" => should_justify, 
            "should_finalize" => should_finalize);

    /*
     * For all the partial crosslinks in the active state, return a vec of
     * complete crosslink records representing the most popular partial
     * record for each shard_id.
     *
     * During this process, create a vec of deltas rewarding/penalizing each
     * validator for thier votes/non-votes on their allocated shard_ids.
     */
    let (crosslink_notaries_deltas, new_crosslinks) = 
        process_crosslinks(
            &cry_state,
            &act_state.partial_crosslinks,
            &config);

    info!(log, "processed crosslinks";
            "new_crosslinks_count" => new_crosslinks.len());

    /*
     * Create a vec of deltas rewarding/penalizing each validator
     * for their votes/non-votes on blocks during the last epoch.
     */
    let recent_attesters_deltas = process_recent_attesters(
        &cry_state,
        &act_state.recent_attesters,
        &config);

    /*
     * Create a vec of deltas rewarding/penalizing each validator
     * for their block proposals during the past epoch.
     */
    let recent_proposers_deltas = process_recent_proposers(
        &cry_state,
        &act_state.recent_proposers);

    /*
     * For each validator, update their balances as per the deltas calculated
     * previously in this function.
     */
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
    
    /*
     * Determine the new total deposit sum, determined by the individual
     * rewards/penalities accrued by validators during this epoch.
     */
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

    /*
     * If finalization should take place, "increment" the validator sets.
     * This involves exiting validators who's balance is too low (from
     * deltas) or who's dynasty has ended and inducting queued validators
     * (if possible).
     */
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

    /*
     * Get the validator shuffling for the new epoch, based upon
     * the rando of the supplied active state.
     */
    let shuffling = get_shuffling(
        &act_state.randao,
        &new_active_validators.len(),
        &config);

    /*
     * Generate a new CrystallizedState
     */
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
    /*
     * Replicate the supplied active state, but reset the fields which
     * accumulate things during the course of an epoch (e.g, recent_proposers,
     * partial_crosslinks, etc)
     */
    let new_act_state = ActiveState {
        height: act_state.height,
        randao: act_state.randao,
        ffg_voter_bitfield: Bitfield::new(),
        recent_attesters: vec![],
        partial_crosslinks: vec![],
        total_skip_count: act_state.total_skip_count,
        recent_proposers: vec![]
    };

    info!(log, "reset active state";
            "height" => new_act_state.height);

    (new_cry_state, new_act_state)
}


