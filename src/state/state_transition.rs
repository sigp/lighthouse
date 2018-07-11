use super::utils::types::{ Sha256Digest };
use super::blake2::{ Blake2s, Digest };
use super::bytes::{ BytesMut, BufMut };
use super::crystallized_state::CrystallizedState;
use super::aggregate_vote::AggregateVote;
use super::config::Config;

const AGG_VOTE_MSG_SIZE: i32 = 2 + 32 + 32 + 8 + 8;

// Interprets a 3-byte slice from a [u8] as an integer.
fn get_shift_from_source(source: &[u8], offset: usize) -> u32 {
    (source[offset + 2] as u32) |
        ((source[offset + 1] as u32) << 8) |
        ((source[offset    ] as u32) << 16)
}

// Given entropy in the form of `seed`, return a shuffled list of validators
// of size `validator_count` or `sample`.
pub fn get_shuffling(
    seed: &Sha256Digest,
    validator_count: &u32,
    sample: &Option<u32>,
    config: &Config) 
    -> Vec<u32>
{
    let max_validators = config.max_validators;
    assert!(*validator_count <= max_validators);
    
    // TODO: figure out why the Python implementation uses
    // this `rand_max` var.
    // let rand_max = max_validators - (max_validators % validator_count);
    let validator_range = match sample {
        Some(x) => x,
        None => validator_count
    };
    let mut output: Vec<u32> = (0..*validator_range).collect();
    let mut source = Blake2s::new();
    source.input(&seed);
    
    let mut v = 0;
    while v < *validator_range {
        let current_source = source.result();
        let mut source_offset = 0;
        while source_offset < 30 {
            let m = get_shift_from_source(&current_source, source_offset);
            let shuffled_position = (m % (validator_count - v)) + v;
            output.swap(v as usize, shuffled_position as usize);
            v += 1;
            if v >= *validator_count { break; }
            source_offset += 3;
        }
        // Re-hash the source
        source = Blake2s::new();
        source.input(&current_source);
    }
    output
}

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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shuffling_shift_fn() {
        let mut x = get_shift_from_source(
            &vec![0_u8, 0, 1],
            0);
        assert_eq!((x as u32), 1);

        x = get_shift_from_source(
            &vec![0_u8, 1, 1],
            0);
        assert_eq!(x, 257);
        
        x = get_shift_from_source(
            &vec![1_u8, 1, 1],
            0);
        assert_eq!(x, 65793);
        
        x = get_shift_from_source(
            &vec![255_u8, 1, 1],
            0);
        assert_eq!(x, 16711937);
    }


    #[test]
    fn test_shuffling() {
        let s = get_shuffling(
            &Sha256Digest::zero(),
            &10,
            &None,
            &Config::standard());
        assert_eq!(s,
                   vec!(0, 9, 7, 6, 4, 1, 8, 5, 2, 3),
                   "10 validator shuffle was not as expected");
    }

    #[test]
    fn test_shuffling_with_gt_half_max_validators() {
        let mut config = Config::standard();
        config.max_validators = 19;
        let s = get_shuffling(
            &Sha256Digest::zero(),
            &10,
            &None,
            &Config::standard());
        assert_eq!(s,
                   vec!(0, 9, 7, 6, 4, 1, 8, 5, 2, 3),
                   "10 validator shuffle was not as expected");
    }

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

}
