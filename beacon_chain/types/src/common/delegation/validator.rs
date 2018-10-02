use super::active_validator_indicies;

type DelegatedSlot = Vec<ShardAndCommittee>;
type DelegatedCycle = Vec<DelegatedSlot>;

/*
 * Delegates active validators into slots for a given cycle, given a random seed.
 * Returns a vector or ShardAndComitte vectors representing the shards and committiees for
 * each slot.
 * References get_new_shuffling (ethereum 2.1 specification)
 */
pub fn delegate_validators(
    seed: &[u8],
    validators: &Vec<ValidatorRecord>,
    dynasty: &u64,
    crosslinking_shard_start: &u16,
    config: &ChainConfig)
    -> Result<DelegatedCycle, TransitionError>
{
    let shuffled_validator_indices = {
        let mut validator_indices = active_validator_indicies(dynasty, validators);
        match shuffle(seed, validator_indices) {
            Ok(shuffled) => shuffled,
            _ => return Err(TransitionError::InvalidInput(
                    String::from("Shuffle list length exceed.")))
        }
    };
    let shard_indices = (0_usize..config.shard_count as usize).into_iter().collect();
    let crosslinking_shard_start = *crosslinking_shard_start as usize;
    let cycle_length = config.cycle_length as usize;
    let min_committee_size = config.min_committee_size as usize;
    generate_cycle(
        &shuffled_validator_indices,
        &shard_indices,
        &crosslinking_shard_start,
        &cycle_length,
        &min_committee_size)
}

/*
 * Given the validator list, delegates the validators into slots and comittees for a given cycle.
 */
fn generate_cycle(
    validator_indices: &Vec<usize>,
    shard_indices: &Vec<usize>,
    crosslinking_shard_start: &usize,
    cycle_length: &usize,
    min_committee_size: &usize)
    -> Result<DelegatedCycle, TransitionError>
{
    let validator_count = validator_indices.len();
    let shard_count = shard_indices.len();

    let (committees_per_slot, slots_per_committee) = {
        if validator_count >= cycle_length * min_committee_size {
            let committees_per_slot = validator_count / cycle_length / (min_committee_size * 2) + 1;
            let slots_per_committee = 1;
            (committees_per_slot, slots_per_committee)
        } else {
            let committees_per_slot = 1;
            let mut slots_per_committee = 1;
            while (validator_count * slots_per_committee < cycle_length * min_committee_size) &
                (slots_per_committee < *cycle_length) {
                slots_per_committee = slots_per_committee * 2;
            }
            (committees_per_slot, slots_per_committee)
        }
    };

    let cycle = validator_indices
        .chunks(validator_indices.len() / *cycle_length)
        .enumerate()
        .map(|(i, slot_indices)| {
            let shard_id_start = crosslinking_shard_start + i * committees_per_slot / slots_per_committee;
            return slot_indices
                .chunks(slot_indices.len() / committees_per_slot)
                .enumerate()
                .map(|(j, shard_indices)| {
                    return ShardAndCommittee{
                        shard_id: ((shard_id_start + j) % shard_count) as u16,
                        committee: shard_indices.to_vec(),
                    }
                })
                .collect()
        })
        .collect();
    Ok(cycle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_cycle_helper(
        validator_count: &usize,
        shard_count: &usize,
        crosslinking_shard_start: &usize,
        cycle_length: &usize,
        min_committee_size: &usize)
        -> (Vec<usize>, Vec<usize>, Result<DelegatedCycle, TransitionError>)
    {
        let validator_indices = (0_usize..*validator_count).into_iter().collect();
        let shard_indices = (0_usize..*shard_count).into_iter().collect();
        let result = generate_cycle(
            &validator_indices,
            &shard_indices,
            &crosslinking_shard_start,
            &cycle_length,
            &min_committee_size);
        (validator_indices, shard_indices, result)
    }

    #[allow(dead_code)]
    fn print_cycle(cycle: &DelegatedCycle) {
        cycle.iter()
            .enumerate()
            .for_each(|(i, slot)| {
                println!("slot {:?}", &i);
                slot.iter()
                    .enumerate()
                    .for_each(|(i, sac)| {
                        println!("#{:?}\tshard_id={}\tcommittee.len()={}",
                            &i, &sac.shard_id, &sac.committee.len())
                    })
            });
    }

    fn flatten_validators(cycle: &DelegatedCycle)
        -> Vec<usize>
    {
        let mut flattened = vec![];
        for slot in cycle.iter() {
            for sac in slot.iter() {
                for validator in sac.committee.iter() {
                    flattened.push(*validator);
                }
            }
        }
        flattened
    }

    fn flatten_and_dedup_shards(cycle: &DelegatedCycle)
        -> Vec<usize>
    {
        let mut flattened = vec![];
        for slot in cycle.iter() {
            for sac in slot.iter() {
                flattened.push(sac.shard_id as usize);
            }
        }
        flattened.dedup();
        flattened
    }

    fn flatten_shards_in_slots(cycle: &DelegatedCycle)
        -> Vec<Vec<usize>>
    {
        let mut shards_in_slots: Vec<Vec<usize>> = vec![];
        for slot in cycle.iter() {
            let mut shards: Vec<usize> = vec![];
            for sac in slot.iter() {
                shards.push(sac.shard_id as usize);
            }
            shards_in_slots.push(shards);
        }
        shards_in_slots
    }


    #[test]
    fn test_generate_cycle() {
        let validator_count: usize = 100;
        let shard_count: usize = 10;
        let crosslinking_shard_start: usize = 0;
        let cycle_length: usize = 20;
        let min_committee_size: usize = 10;
        let (validators, shards, result) = generate_cycle_helper(
            &validator_count,
            &shard_count,
            &crosslinking_shard_start,
            &cycle_length,
            &min_committee_size);
        let cycle = result.unwrap();

        let assigned_validators = flatten_validators(&cycle);
        let assigned_shards = flatten_and_dedup_shards(&cycle);
        let shards_in_slots = flatten_shards_in_slots(&cycle);
        assert_eq!(assigned_validators, validators, "Validator assignment incorrect");
        assert_eq!(assigned_shards, shards, "Shard assignment incorrect");

        let expected_shards_in_slots: Vec<Vec<usize>> = vec![
            vec![0], vec![0],   // Each line is 2 slots..
            vec![1], vec![1],
            vec![2], vec![2],
            vec![3], vec![3],
            vec![4], vec![4],
            vec![5], vec![5],
            vec![6], vec![6],
            vec![7], vec![7],
            vec![8], vec![8],
            vec![9], vec![9],
        ];
        // assert!(compare_shards_in_slots(&cycle, &expected_shards_in_slots));
        assert_eq!(expected_shards_in_slots, shards_in_slots, "Shard assignment incorrect.")
    }
}
