use super::shuffle;
use super::ChainConfig;
use super::TransitionError;
use super::ValidatorRecord;
use super::ShardAndCommittee;

pub fn get_new_shuffling(
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

/// Produce a vector of validators indicies where those
/// validators start and end dynasties are within the supplied
/// `dynasty`.
fn active_validator_indicies(
    dynasty: &u64,
    validators: &Vec<ValidatorRecord>)
    -> Vec<usize>
{
    validators.iter()
        .enumerate()
        .filter_map(|(i, validator)| {
            if (validator.start_dynasty >= *dynasty) &
                (validator.end_dynasty < *dynasty)
            {
                Some(i)
            } else {
                None
            }
        })
        .collect()
}

type DelegatedSlot = Vec<ShardAndCommittee>;
type DelegatedCycle = Vec<DelegatedSlot>;

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
            let committees_per_slot = validator_count / cycle_length / (min_committee_size * 2);
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

    let mut cycle: DelegatedCycle = vec![];
    let split_iter = validator_indices.split(|i| i % cycle_length == 0);
    for (i, slot_indices) in split_iter.enumerate() {
        let shard_id_start = crosslinking_shard_start * i * committees_per_slot / slots_per_committee;

        let shard_iter = slot_indices.split(|i| i % committees_per_slot == 0);
        let slot: DelegatedSlot = shard_iter
            .enumerate()
            .map(|(j, shard_indices)| {
                ShardAndCommittee{
                    shard_id: ((shard_id_start + j) % shard_count) as u16,
                    committee: shard_indices.to_vec(),
                }
            })
            .collect();
        cycle.push(slot);
    };
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
        -> Result<DelegatedCycle, TransitionError>
    {
        let validator_indices = (0_usize..*validator_count).into_iter().collect();
        let shard_indices = (0_usize..*shard_count).into_iter().collect();
        generate_cycle(
            &validator_indices,
            &shard_indices,
            &crosslinking_shard_start,
            &cycle_length,
            &min_committee_size)
    }

    #[test]
    fn test_generate_cycle() {
        let validator_count: usize = 100;
        let shard_count: usize = 10;
        let crosslinking_shard_start: usize = 0;
        let cycle_length: usize = 20;
        let min_committee_size: usize = 10;
        let result = generate_cycle_helper(
            &validator_count,
            &shard_count,
            &crosslinking_shard_start,
            &cycle_length,
            &min_committee_size);
        println!("{:?}", result);
    }

}
