use std::cmp::min;

use super::crystallized_state::CrystallizedState;
use super::validator_record::ValidatorRecord;
use super::config::Config;

pub fn get_incremented_validator_sets(
    cry_state: &CrystallizedState,
    active_validators: &Vec<ValidatorRecord>,
    config: &Config)
    -> (Vec<ValidatorRecord>, Vec<ValidatorRecord>, Vec<ValidatorRecord>)
{
    let mut new_active_validators: Vec<ValidatorRecord> = vec![];
    let mut new_exited_validators: Vec<ValidatorRecord> 
        = cry_state.exited_validators.clone();
    let next_dynasty = cry_state.dynasty + 1;

    for v in active_validators {
        if (v.balance <= config.eject_balance) | 
            (v.switch_dynasty == next_dynasty) {
            new_exited_validators.push(v.clone());
        } 
        else {
            new_active_validators.push(v.clone());
        }
    }

    let induction_count = min(
        cry_state.num_queued_validators(),
        cry_state.num_active_validators() / 30 + 1);
    let mut first_ineligable = induction_count;
    for i in 0..induction_count {
        if cry_state.queued_validators[i].switch_dynasty > next_dynasty {
            first_ineligable = i;
            break;
        }
        new_active_validators.push(cry_state.queued_validators[i].clone());
    }
    let new_queued_validators = cry_state.
        queued_validators[first_ineligable..cry_state.queued_validators.len()]
            .to_vec();
    (new_queued_validators, new_active_validators, new_exited_validators)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::utils::types::U256;
    // use super::super::shuffling::get_shuffling;
    
    fn test_setup() -> (CrystallizedState, Config) {
        let mut cry_state = CrystallizedState::zero();
        let mut config = Config::standard();
        
        config.shard_count = 5;
        config.notaries_per_crosslink = 2;
        config.default_balance = U256::from(32000);
        config.eject_balance = U256::from(16000);
        cry_state.current_epoch = 100;
        cry_state.dynasty = 100;
        (cry_state, config)
    }

    #[test]
    fn test_incrementing_validator_sets_scenario_1() {
        let (mut cry_state, config) = test_setup();
        let validator_count = 10;

        let mut a: Vec<ValidatorRecord> = vec![];
        let mut q: Vec<ValidatorRecord> = vec![];
        let mut x: Vec<ValidatorRecord> = vec![];

        (0..validator_count).for_each(|_| {
            let mut v = ValidatorRecord::zero_with_thread_rand_pub_key();
            v.switch_dynasty = cry_state.dynasty + 5;
            v.balance = config.default_balance.clone();
            a.push(v)
        });
        
        (0..validator_count).for_each(|_| {
            let mut v = ValidatorRecord::zero_with_thread_rand_pub_key();
            v.switch_dynasty = cry_state.dynasty + 1;
            v.balance = config.default_balance.clone();
            q.push(v)
        });
        
        (0..validator_count).for_each(|_| {
            let mut v = ValidatorRecord::zero_with_thread_rand_pub_key();
            v.switch_dynasty = cry_state.dynasty - 1;
            v.balance = config.default_balance.clone();
            x.push(v)
        });

        cry_state.active_validators = a.to_vec();
        cry_state.queued_validators = q.to_vec();
        cry_state.exited_validators = x.to_vec();

        let (nq, na, nx) = get_incremented_validator_sets(
            &cry_state,
            &a,
            &config);

        let inducted = validator_count / 30 + 1;
        assert!(inducted > 0);

        assert_eq!(na.len(), validator_count + inducted, "new active incorrect");
        assert_eq!(nq.len(), validator_count - inducted, "new queued incorrect");
        assert_eq!(nx.len(), validator_count, "new exited incorrect");
    }

    #[test]
    fn test_incrementing_validator_sets_scenario_2() {
        let (mut cry_state, config) = test_setup();
        let validator_count = 60;
        let expiring_active = 5;
        let eligable_queued = 1;

        let mut a: Vec<ValidatorRecord> = vec![];
        let mut q: Vec<ValidatorRecord> = vec![];
        let mut x: Vec<ValidatorRecord> = vec![];

        (0..validator_count).for_each(|i| {
            let mut v = ValidatorRecord::zero_with_thread_rand_pub_key();
            if i < expiring_active {
                v.switch_dynasty = cry_state.dynasty + 1;
            } else {
                v.switch_dynasty = cry_state.dynasty + 5;
            }
            v.balance = config.default_balance.clone();
            a.push(v)
        });
        
        (0..validator_count).for_each(|i| {
            let mut v = ValidatorRecord::zero_with_thread_rand_pub_key();
            if i < eligable_queued {
                v.switch_dynasty = cry_state.dynasty + 1;
            } else {
                v.switch_dynasty = cry_state.dynasty + 5;
            }
            v.balance = config.default_balance.clone();
            q.push(v)
        });
        
        (0..validator_count).for_each(|_| {
            let mut v = ValidatorRecord::zero_with_thread_rand_pub_key();
            v.switch_dynasty = cry_state.dynasty - 1;
            v.balance = config.default_balance.clone();
            x.push(v)
        });

        cry_state.active_validators = a.to_vec();
        cry_state.queued_validators = q.to_vec();
        cry_state.exited_validators = x.to_vec();

        let (nq, na, nx) = get_incremented_validator_sets(
            &cry_state,
            &a,
            &config);

        let inducted = validator_count / 30 + 1;
        assert!(inducted > eligable_queued, "this test requires more inductable \
        validators than there are eligable.");

        assert_eq!(na.len(), validator_count - expiring_active + eligable_queued, 
                   "new active incorrect");
        assert_eq!(nq.len(), validator_count - eligable_queued, 
                   "new queued incorrect");
        assert_eq!(nx.len(), validator_count + expiring_active, 
                   "new exited incorrect");
    }
}
