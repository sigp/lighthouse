use super::bytes::{ BytesMut, BufMut };
use super::crystallized_state::CrystallizedState;
use super::active_state::ActiveState;
use super::aggregate_vote::AggregateVote;

use super::transition::shuffling::get_shuffling;
use super::config::Config;

const AGG_VOTE_MSG_SIZE: i32 = 2 + 32 + 32 + 8 + 8;

// Given an aggregate_vote and a crystallized_state,
// return a byte array for signing or verification.
pub fn get_crosslink_aggvote_msg(
    agg_vote: &AggregateVote,
    cry_state: &CrystallizedState)
    ->  Vec<u8>
{
    let mut buf = BytesMut::with_capacity(AGG_VOTE_MSG_SIZE as usize);
    buf.put_u16_be(agg_vote.shard_id);
    buf.extend_from_slice(&agg_vote.shard_block_hash.to_vec());
    buf.extend_from_slice(&cry_state.current_checkpoint.to_vec());
    buf.put_u64_be(cry_state.current_epoch);
    buf.put_u64_be(cry_state.last_justified_epoch);
    buf.to_vec()
}

// For a given state set and skip_count, return a proposer and set
// of attestors.
pub fn get_attesters_and_proposer(
    cry_state: &CrystallizedState,
    act_state: &ActiveState,
    skip_count: &u64,
    config: &Config)
    -> (Vec<usize>, usize)
{
    let active_validator_count = cry_state.num_active_validators(); 
    assert!(active_validator_count >= 2, "must be >=2 active validators");
    let shuffled_validator_indicies = get_shuffling(
        &act_state.randao,
        &active_validator_count,
        config);
    let proposer_count: usize = 1;
    let ideal_validator_count: usize = (config.attester_count as usize)
        + (*skip_count as usize) + proposer_count;
    if ideal_validator_count > active_validator_count {
        return (
            shuffled_validator_indicies[0..active_validator_count - 1].to_vec(),
            shuffled_validator_indicies[active_validator_count - 1]);
    } else {
        return (
            shuffled_validator_indicies[0..ideal_validator_count - 1].to_vec(),
            shuffled_validator_indicies[ideal_validator_count - 1]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::validator_record::ValidatorRecord;
    use super::super::utils::types::{ Address, Sha256Digest, U256 };
    use super::super::
        utils::test_helpers::get_dangerous_test_keypair;

    #[test]
    fn test_crosslink_aggvote_msg() {
        let mut cs_state = CrystallizedState::zero();
        let mut agg_vote = AggregateVote::zero();
        // All zeros
        let m1 = get_crosslink_aggvote_msg(&agg_vote, &cs_state);
        assert_eq!(m1,
                   vec![0_u8; AGG_VOTE_MSG_SIZE as usize],
                   "failed all zeros test");
        // With some values
        agg_vote.shard_id = 42;
        cs_state.current_epoch = 99;
        cs_state.last_justified_epoch = 123;
        let m2 = get_crosslink_aggvote_msg(&agg_vote, &cs_state);
        assert_eq!(m2[0..2], [0, 42]);
        assert_eq!(m2[2..34], [0; 32]);     // TODO: test with non-zero hash
        assert_eq!(m2[34..66], [0; 32]);    // TODO: test with non-zero hash
        assert_eq!(m2[66..74], [0, 0, 0, 0, 0, 0, 0, 99]);
        assert_eq!(m2[74..82], [0, 0, 0, 0, 0, 0, 0, 123]);
    }

    #[test]
    fn test_attester_and_proposer_selection() {
        let mut cry_state = CrystallizedState::zero();
        for _ in 0..10 {
            cry_state.active_validators.push(ValidatorRecord {
                pubkey: get_dangerous_test_keypair().public,
                withdrawal_shard: 0,
                withdrawal_address: Address::zero(),
                randao_commitment: Sha256Digest::zero(),
                balance: U256::zero(),
                switch_dynasty: 0
            });
        }
        let act_state = ActiveState::zero();
        let (attestors, proposer) = get_attesters_and_proposer(
            &cry_state,
            &act_state,
            &0,
            &Config::standard());
        assert_eq!(attestors, [0, 9, 7, 6, 4, 1, 8, 5, 2]);
        assert_eq!(proposer, 3);
    }

    #[test]
    #[should_panic(expected = "must be >=2 active validators")]
    fn test_attester_and_proposer_selection_with_zero_active_validators() {
        let mut cry_state = CrystallizedState::zero();
        cry_state.active_validators = Vec::new();
        let act_state = ActiveState::zero();
        let (_attestors, _proposer) = get_attesters_and_proposer(
            &cry_state,
            &act_state,
            &0,
            &Config::standard());
    }
}
