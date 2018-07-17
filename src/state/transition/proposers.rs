use super::crystallized_state::CrystallizedState;
use super::recent_proposer_record::RecentPropserRecord;


pub fn process_recent_proposers(
    cry_state: &CrystallizedState,
    recent_proposers: &Vec<RecentPropserRecord>)
    -> Vec<i64>
{
    let mut deltas: Vec<i64> = vec![0; cry_state.num_active_validators()];
    for p in recent_proposers {
        deltas[p.index] += p.balance_delta;
    }
    deltas
}
    
#[cfg(test)]
mod tests {
    use super::*;
    use super::super::utils::types::Sha256Digest;
    use super::super::validator_record::ValidatorRecord;
    
    #[test]
    fn test_process_recent_proposers() {
        let mut cry_state = CrystallizedState::zero();
        let validator_count = 20;

        let mut recent_proposers: Vec<RecentPropserRecord> = vec![];

        for i in 0..validator_count {
            cry_state.active_validators
                .push(ValidatorRecord::zero_with_thread_rand_pub_key());
            if i % 2 == 0 {
                recent_proposers.push(RecentPropserRecord {
                    index: i,
                    randao_commitment: Sha256Digest::zero(),
                    balance_delta: 10
                });
            }
        }

        let d = process_recent_proposers(
            &cry_state,
            &recent_proposers);

        for i in 0..validator_count {
            if i % 2 == 0 {
                assert_eq!(d[i], 10);
            } else {
                assert_eq!(d[i], 0);
            }
        }
    }
}
