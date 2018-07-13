use std::collections::HashMap;
use std::cmp::min;

use super::crystallized_state::CrystallizedState;
use super::partial_crosslink_record::PartialCrosslinkRecord;
use super::config::Config;

// Returns the maximum possible shards for a given validator_count
// and configuration. 
pub fn get_crosslink_shards_count(
    active_validator_count: &usize, 
    config: &Config) 
    -> u16
{
    let system_shard_count: u16 = config.shard_count;
    let notaries_per_crosslink: u16 = config.notaries_per_crosslink;

    assert!(notaries_per_crosslink > 0, "Shards must require > 0 notaries.");

    let notarisable_shard_count = 
        *active_validator_count as u64 / notaries_per_crosslink as u64;

    min(notarisable_shard_count, system_shard_count as u64) as u16
}

pub fn get_crosslink_shards(
    cry_state: &CrystallizedState, 
    config: &Config) 
    -> Vec<u16>
{
    let max_shard_count: u16 = config.shard_count;
    let first_shard: u16 = cry_state.next_shard;
    assert!(first_shard < max_shard_count, "CrystallizedState.next_shard \
    must be less than Config.shard_count.");

    let shard_count = get_crosslink_shards_count(
        &cry_state.num_active_validators(),
        &config);

    let unwrapped_shards: u16 = min(first_shard + shard_count, max_shard_count);
    let wrapped_shards: u16 = (first_shard + shard_count) % max_shard_count;
    let mut crosslink_shards: Vec<u16> = (first_shard..unwrapped_shards).collect();
    crosslink_shards.append(&mut (0_u16..wrapped_shards).collect());
    crosslink_shards
}

/* Work in progres...
pub fn process_crosslinks(
    cry_state: &CrystallizedState,
    partial_crosslinks: &Vec<PartialCrosslinkRecord>,
    config: &Config)
    -> (Vec<i64>, Vec<PartialCrosslinkRecord>)
{
    assert!(partial_crosslinks.len() > 0, "No crosslinks present.");
   
    let mut map: HashMap<u16, (&PartialCrosslinkRecord, u64)> = HashMap::new();

    for pc in partial_crosslinks {
        let vote_count = pc.voter_bitfield.num_true_bits();
        let mut competiting_vote_count = 0;
        match map.get(&pc.shard_id) {
            Some(&competitor) => competiting_vote_count = competitor.1,
            None => {}
        }
        // Here we implicitly avoid adding crosslinks with 0 votes
        // to our map.
        if vote_count > competiting_vote_count {
            map.insert(pc.shard_id, (pc, vote_count));
        }
    }

    let mut new_partial_crosslinks: Vec<&PartialCrosslinkRecord> = Vec::new();
    map.iter_mut()
        .for_each(|(_, v)| new_partial_crosslinks.push(v.0));

    // To be completed...

    (Vec::new(), Vec::new())
}
*/


#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::validator_record::ValidatorRecord;

    #[test]
    fn test_crosslink_shard_count_with_varying_active_vals() {
        let mut config = Config::standard();

        config.shard_count = 10;
        config.notaries_per_crosslink = 10;

        let mut c = get_crosslink_shards_count(
            &100,
            &config);
        assert_eq!(c, 10);
        
        c = get_crosslink_shards_count(
            &101,
            &config);
        assert_eq!(c, 10);
        
        c = get_crosslink_shards_count(
            &99,
            &config);
        assert_eq!(c, 9);
        
        c = get_crosslink_shards_count(
            &0,
            &config);
        assert_eq!(c, 0);
    }
    
    #[test]
    #[should_panic(expected = "must require > 0 notaries.")]
    fn test_crosslink_shard_count_with_zero_notaries_per_crosslink() {
        let mut config = Config::standard();

        config.shard_count = 10;
        config.notaries_per_crosslink = 0;

        let validators: u16 = 10;

        let c = get_crosslink_shards_count(
            &(validators as usize),
            &config);
    }

    #[test]
    fn test_crosslink_shard_getter_with_5_shards() {
        let mut cry_state = CrystallizedState::zero();
        let mut config = Config::standard();

        config.shard_count = 5;
        config.notaries_per_crosslink = 2;

        (0..10).for_each(
            |_| cry_state.active_validators.push(
                ValidatorRecord::zero_with_thread_rand_pub_key()));

        cry_state.next_shard = 0;
        let c = get_crosslink_shards(
            &cry_state,
            &config);
        assert_eq!(c, [0, 1, 2, 3, 4]);
        
        cry_state.next_shard = 4;
        let c = get_crosslink_shards(
            &cry_state,
            &config);
        assert_eq!(c, [4, 0, 1, 2, 3]);
        
        cry_state.next_shard = 1;
        let c = get_crosslink_shards(
            &cry_state,
            &config);
        assert_eq!(c, [1, 2, 3, 4, 0]);
        
        cry_state.next_shard = 3;
        let c = get_crosslink_shards(
            &cry_state,
            &config);
        assert_eq!(c, [3, 4, 0, 1, 2]);
    }
    
    #[test]
    #[should_panic(expected = "next_shard must be less than Config.shard_count")]
    fn test_crosslink_shard_getter_with_too_large_next_shard() {
        let mut cry_state = CrystallizedState::zero();
        let mut config = Config::standard();

        config.shard_count = 1;
        config.notaries_per_crosslink = 2;

        (0..2).for_each(
            |_| cry_state.active_validators.push(
                ValidatorRecord::zero_with_thread_rand_pub_key()));

        cry_state.next_shard = 6;
        let c = get_crosslink_shards(
            &cry_state,
            &config);
    }
}
