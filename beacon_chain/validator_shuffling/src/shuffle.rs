use std::cmp::min;

use honey_badger_split::SplitExt;
use spec::ChainSpec;
use types::{ShardCommittee, ValidatorRecord, ValidatorStatus};
use vec_shuffle::{shuffle, ShuffleErr};

type DelegatedCycle = Vec<Vec<ShardCommittee>>;

#[derive(Debug, PartialEq)]
pub enum ValidatorAssignmentError {
    TooManyValidators,
    TooFewShards,
}

/// Delegates active validators into slots for a given cycle, given a random seed.
/// Returns a vector or ShardAndComitte vectors representing the shards and committiees for
/// each slot.
/// References get_new_shuffling (ethereum 2.1 specification)
pub fn shard_and_committees_for_cycle(
    seed: &[u8],
    validators: &[ValidatorRecord],
    crosslinking_shard_start: u16,
    spec: &ChainSpec,
) -> Result<DelegatedCycle, ValidatorAssignmentError> {
    let shuffled_validator_indices = {
        let validator_indices = validators
            .iter()
            .enumerate()
            .filter_map(|(i, validator)| {
                if validator.status_is(ValidatorStatus::Active) {
                    Some(i)
                } else {
                    None
                }
            })
            .collect();
        shuffle(seed, validator_indices)?
    };
    let shard_indices: Vec<usize> = (0_usize..spec.shard_count as usize).into_iter().collect();
    let crosslinking_shard_start = crosslinking_shard_start as usize;
    let epoch_length = spec.epoch_length as usize;
    let min_committee_size = spec.target_committee_size as usize;
    generate_cycle(
        &shuffled_validator_indices,
        &shard_indices,
        crosslinking_shard_start,
        epoch_length,
        min_committee_size,
    )
}

/// Given the validator list, delegates the validators into slots and comittees for a given cycle.
fn generate_cycle(
    validator_indices: &[usize],
    shard_indices: &[usize],
    crosslinking_shard_start: usize,
    epoch_length: usize,
    min_committee_size: usize,
) -> Result<DelegatedCycle, ValidatorAssignmentError> {
    let validator_count = validator_indices.len();
    let shard_count = shard_indices.len();

    if shard_count / epoch_length == 0 {
        return Err(ValidatorAssignmentError::TooFewShards);
    }

    let (committees_per_slot, slots_per_committee) = {
        if validator_count >= epoch_length * min_committee_size {
            let committees_per_slot = min(
                validator_count / epoch_length / (min_committee_size * 2) + 1,
                shard_count / epoch_length,
            );
            let slots_per_committee = 1;
            (committees_per_slot, slots_per_committee)
        } else {
            let committees_per_slot = 1;
            let mut slots_per_committee = 1;
            while (validator_count * slots_per_committee < epoch_length * min_committee_size)
                & (slots_per_committee < epoch_length)
            {
                slots_per_committee *= 2;
            }
            (committees_per_slot, slots_per_committee)
        }
    };

    let cycle = validator_indices
        .honey_badger_split(epoch_length)
        .enumerate()
        .map(|(i, slot_indices)| {
            let shard_start =
                crosslinking_shard_start + i * committees_per_slot / slots_per_committee;
            slot_indices
                .honey_badger_split(committees_per_slot)
                .enumerate()
                .map(|(j, shard_indices)| ShardCommittee {
                    shard: ((shard_start + j) % shard_count) as u64,
                    committee: shard_indices.to_vec(),
                })
                .collect()
        })
        .collect();
    Ok(cycle)
}

impl From<ShuffleErr> for ValidatorAssignmentError {
    fn from(e: ShuffleErr) -> ValidatorAssignmentError {
        match e {
            ShuffleErr::ExceedsListLength => ValidatorAssignmentError::TooManyValidators,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_cycle_helper(
        validator_count: &usize,
        shard_count: &usize,
        crosslinking_shard_start: usize,
        epoch_length: usize,
        min_committee_size: usize,
    ) -> (
        Vec<usize>,
        Vec<usize>,
        Result<DelegatedCycle, ValidatorAssignmentError>,
    ) {
        let validator_indices: Vec<usize> = (0_usize..*validator_count).into_iter().collect();
        let shard_indices: Vec<usize> = (0_usize..*shard_count).into_iter().collect();
        let result = generate_cycle(
            &validator_indices,
            &shard_indices,
            crosslinking_shard_start,
            epoch_length,
            min_committee_size,
        );
        (validator_indices, shard_indices, result)
    }

    #[allow(dead_code)]
    fn print_cycle(cycle: &DelegatedCycle) {
        cycle.iter().enumerate().for_each(|(i, slot)| {
            println!("slot {:?}", &i);
            slot.iter().enumerate().for_each(|(i, sac)| {
                println!(
                    "#{:?}\tshard={}\tcommittee.len()={}",
                    &i,
                    &sac.shard,
                    &sac.committee.len()
                )
            })
        });
    }

    fn flatten_validators(cycle: &DelegatedCycle) -> Vec<usize> {
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

    fn flatten_and_dedup_shards(cycle: &DelegatedCycle) -> Vec<usize> {
        let mut flattened = vec![];
        for slot in cycle.iter() {
            for sac in slot.iter() {
                flattened.push(sac.shard as usize);
            }
        }
        flattened.dedup();
        flattened
    }

    fn flatten_shards_in_slots(cycle: &DelegatedCycle) -> Vec<Vec<usize>> {
        let mut shards_in_slots: Vec<Vec<usize>> = vec![];
        for slot in cycle.iter() {
            let mut shards: Vec<usize> = vec![];
            for sac in slot.iter() {
                shards.push(sac.shard as usize);
            }
            shards_in_slots.push(shards);
        }
        shards_in_slots
    }

    // TODO: Improve these tests to check committee lengths
    #[test]
    fn test_generate_cycle() {
        let validator_count: usize = 100;
        let shard_count: usize = 20;
        let crosslinking_shard_start: usize = 0;
        let epoch_length: usize = 20;
        let min_committee_size: usize = 10;
        let (validators, shards, result) = generate_cycle_helper(
            &validator_count,
            &shard_count,
            crosslinking_shard_start,
            epoch_length,
            min_committee_size,
        );
        let cycle = result.unwrap();

        let assigned_validators = flatten_validators(&cycle);
        let assigned_shards = flatten_and_dedup_shards(&cycle);
        let shards_in_slots = flatten_shards_in_slots(&cycle);
        let expected_shards = shards.get(0..10).unwrap();
        assert_eq!(
            assigned_validators, validators,
            "Validator assignment incorrect"
        );
        assert_eq!(
            assigned_shards, expected_shards,
            "Shard assignment incorrect"
        );

        let expected_shards_in_slots: Vec<Vec<usize>> = vec![
            vec![0],
            vec![0], // Each line is 2 slots..
            vec![1],
            vec![1],
            vec![2],
            vec![2],
            vec![3],
            vec![3],
            vec![4],
            vec![4],
            vec![5],
            vec![5],
            vec![6],
            vec![6],
            vec![7],
            vec![7],
            vec![8],
            vec![8],
            vec![9],
            vec![9],
        ];
        // assert!(compare_shards_in_slots(&cycle, &expected_shards_in_slots));
        assert_eq!(
            expected_shards_in_slots, shards_in_slots,
            "Shard assignment incorrect."
        )
    }

    #[test]
    // Check that the committees per slot is upper bounded by shard count
    fn test_generate_cycle_committees_bounded() {
        let validator_count: usize = 523;
        let shard_count: usize = 31;
        let crosslinking_shard_start: usize = 0;
        let epoch_length: usize = 11;
        let min_committee_size: usize = 5;
        let (validators, shards, result) = generate_cycle_helper(
            &validator_count,
            &shard_count,
            crosslinking_shard_start,
            epoch_length,
            min_committee_size,
        );
        let cycle = result.unwrap();
        let assigned_validators = flatten_validators(&cycle);
        let assigned_shards = flatten_and_dedup_shards(&cycle);
        let shards_in_slots = flatten_shards_in_slots(&cycle);
        let expected_shards = shards.get(0..22).unwrap();
        let expected_shards_in_slots: Vec<Vec<usize>> = (0_usize..11_usize)
            .map(|x| vec![2 * x, 2 * x + 1])
            .collect();
        assert_eq!(
            assigned_validators, validators,
            "Validator assignment incorrect"
        );
        assert_eq!(
            assigned_shards, expected_shards,
            "Shard assignment incorrect"
        );
        // assert!(compare_shards_in_slots(&cycle, &expected_shards_in_slots));
        assert_eq!(
            expected_shards_in_slots, shards_in_slots,
            "Shard assignment incorrect."
        )
    }
}
