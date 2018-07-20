use super::crystallized_state::CrystallizedState;
use super::utils::types::{ Bitfield, U256 };
use super::utils::logging::Logger;

pub fn process_ffg_deposits(
    cry_state: &CrystallizedState,
    ffg_vote_bitfield: &Bitfield,
    log: &Logger)
    -> (Vec<i64>, u64, U256, bool, bool)
{
    let active_validators: usize = cry_state.num_active_validators();
    let finality_distance: u64 = cry_state.finality_distance();
    let online_reward: u64 = if finality_distance <= 2 { 6 } else { 0 };
    let offline_penalty: u64 = finality_distance.saturating_mul(3); 
    let mut total_vote_count: u64 = 0;
    let mut total_vote_deposits = U256::zero();
    
    let mut deltas = vec![0_i64; active_validators];
    for i in 0..active_validators {
        if ffg_vote_bitfield.get_bit(&i) {
            total_vote_deposits = total_vote_deposits
                .saturating_add(cry_state.active_validators[i].balance);
            deltas[i] += online_reward as i64;
            total_vote_count += 1;
        } else {
            deltas[i] -= offline_penalty as i64;
        }
    }
   
    // Justify if total voting deposits is greater than 2/3 the total deposits.
    let should_justify = total_vote_deposits.saturating_mul(U256::from(3)) 
        >= cry_state.total_deposits.saturating_mul(U256::from(2));
    let mut should_finalize = false;
    if should_justify {
        if cry_state.last_justified_epoch == cry_state.current_epoch - 1 {
            should_finalize = true;
        }
    }
    
    info!(log, "counted ffg votes";
            "total_vote_count" => total_vote_count, 
            "total_vote_deposits" => total_vote_deposits.low_u64());

    (deltas, total_vote_count, total_vote_deposits, should_justify, should_finalize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::utils::types::{ Address, Sha256Digest };
    use super::super::utils::logging::test_logger;
    use super::super::super::validator_record::ValidatorRecord;
    use super::super::
        utils::test_helpers::get_dangerous_test_keypair;

    #[test]
    fn test_deposit_processing_scenario_1() {
        let log = test_logger();
        let mut cry_state = CrystallizedState::zero();
        let mut bitfield = Bitfield::new();
        let mut total_deposits = U256::zero();
        let individual_deposit = U256::from(1);

        
        // load some validators into the cry state and flag
        // they have all voted
        for i in 0..10 {
            cry_state.active_validators.push(ValidatorRecord {
                pubkey: get_dangerous_test_keypair().public,
                withdrawal_shard: 0,
                withdrawal_address: Address::zero(),
                randao_commitment: Sha256Digest::zero(),
                balance: individual_deposit,
                switch_dynasty: 0
            });
            total_deposits = total_deposits + individual_deposit;
            bitfield.set_bit(&i, &true);
        }

        cry_state.current_epoch         = 100;
        cry_state.last_justified_epoch  = 99;
        cry_state.last_finalized_epoch  = 98;
        cry_state.total_deposits = total_deposits;

        let (deltas, total_vote_count, total_vote_deposits,
             should_justify, should_finalize) = process_ffg_deposits(
                 &cry_state, &bitfield, &log);

        assert_eq!(deltas, [6; 10]);
        assert_eq!(total_vote_count, 10);
        assert_eq!(total_vote_deposits, total_deposits);
        assert_eq!(should_justify, true);
        assert_eq!(should_finalize, true);
    }
    
    #[test]
    fn test_deposit_processing_scenario_2() {
        let log = test_logger();
        let mut cry_state = CrystallizedState::zero();
        let bitfield = Bitfield::new();
        let individual_deposit = U256::from(0);

        
        // load some validators into the cry state and flag
        // they have all voted
        for _ in 0..10 {
            cry_state.active_validators.push(ValidatorRecord {
                pubkey: get_dangerous_test_keypair().public,
                withdrawal_shard: 0,
                withdrawal_address: Address::zero(),
                randao_commitment: Sha256Digest::zero(),
                balance: individual_deposit,
                switch_dynasty: 0
            });
        }

        cry_state.current_epoch         = 100;
        cry_state.last_justified_epoch  = 99;
        cry_state.last_finalized_epoch  = 98;
        cry_state.total_deposits = U256::from(10);

        let (deltas, total_vote_count, total_vote_deposits,
             should_justify, should_finalize) = process_ffg_deposits(
                 &cry_state, &bitfield, &log);

        assert_eq!(deltas, [-6; 10]);
        assert_eq!(total_vote_count, 0);
        assert_eq!(total_vote_deposits, U256::zero());
        assert_eq!(should_justify, false);
        assert_eq!(should_finalize, false);
    }

    #[test]
    fn test_deposit_processing_scenario_3() {
        let log = test_logger();
        let mut cry_state = CrystallizedState::zero();
        let mut bitfield = Bitfield::new();
        let mut total_deposits = U256::zero();
        let individual_deposit = U256::from(50);

        
        // load some validators into the cry state and flag
        // some have voted
        for i in 0..10 {
            cry_state.active_validators.push(ValidatorRecord {
                pubkey: get_dangerous_test_keypair().public,
                withdrawal_shard: 0,
                withdrawal_address: Address::zero(),
                randao_commitment: Sha256Digest::zero(),
                balance: individual_deposit,
                switch_dynasty: 0,
            });

            if i < 5 { 
                bitfield.set_bit(&i, &true);
                total_deposits = total_deposits + individual_deposit;
            }
        }

        cry_state.current_epoch         = 100;
        cry_state.last_justified_epoch  = 99;
        cry_state.last_finalized_epoch  = 98;
        cry_state.total_deposits = U256::from(5);

        let (deltas, total_vote_count, total_vote_deposits,
             should_justify, should_finalize) = process_ffg_deposits(
                 &cry_state, &bitfield, &log);

        assert_eq!(deltas[0..5].to_vec(), [6;5]);
        assert_eq!(deltas[5..10].to_vec(), [-6;5]);
        assert_eq!(total_vote_count, 5);
        assert_eq!(total_vote_deposits, total_deposits);
        assert_eq!(should_justify, true);
        assert_eq!(should_finalize, true);
    }
}
