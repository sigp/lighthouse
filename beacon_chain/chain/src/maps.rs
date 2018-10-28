use types::{
    AttesterMap,
    ProposerMap,
    ShardAndCommittee,
};

#[derive(Debug, PartialEq)]
pub enum AttesterAndProposerMapError {
    NoShardAndCommitteeForSlot,
    NoAvailableProposer,
}

/// Generate a map of `(slot, shard) |--> committee`.
///
/// The attester map is used to optimise the lookup of a committee.
pub fn generate_attester_and_proposer_maps(
    shard_and_committee_for_slots: &Vec<Vec<ShardAndCommittee>>,
    start_slot: u64)
    -> Result<(AttesterMap, ProposerMap), AttesterAndProposerMapError>
{
    let mut attester_map = AttesterMap::new();
    let mut proposer_map = ProposerMap::new();
    for (i, slot) in shard_and_committee_for_slots.iter().enumerate() {
        /*
         * Store the proposer for the block.
         */
        let slot_number = (i as u64).saturating_add(start_slot);
        let first_committee = &slot.get(0)
            .ok_or(AttesterAndProposerMapError::NoShardAndCommitteeForSlot)?
            .committee;
        let proposer_index = (slot_number as usize).checked_rem(first_committee.len())
            .ok_or(AttesterAndProposerMapError::NoAvailableProposer)?;
        proposer_map.insert(slot_number, first_committee[proposer_index]);

        /*
         * Loop through the shards and extend the attester map.
         */
        for shard_and_committee in slot {
            let committee = shard_and_committee.committee.clone();
            attester_map.insert((slot_number, shard_and_committee.shard), committee);
        }
    };
    Ok((attester_map, proposer_map))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sac_generator(shard_count: u16,
                     slot_count: usize,
                     sac_per_slot: usize,
                     committee_size: usize)
        -> Vec<Vec<ShardAndCommittee>>
    {
        let mut shard = 0;
        let mut validator = 0;
        let mut cycle = vec![];

        for _ in 0..slot_count {
            let mut slot: Vec<ShardAndCommittee> = vec![];
            for _ in 0..sac_per_slot {
                let mut sac = ShardAndCommittee {
                    shard: shard % shard_count,
                    committee: vec![],
                };
                for _ in 0..committee_size {
                    sac.committee.push(validator);
                    validator += 1;
                }
                slot.push(sac);
                shard += 1;
            }
            cycle.push(slot);
        }
        cycle
    }

    #[test]
    fn test_attester_proposer_maps_empty_slots() {
        let sac = sac_generator(4, 4, 0, 1);
        let result = generate_attester_and_proposer_maps(&sac, 0);
        assert_eq!(result, Err(AttesterAndProposerMapError::NoShardAndCommitteeForSlot));
    }

    #[test]
    fn test_attester_proposer_maps_empty_committees() {
        let sac = sac_generator(4, 4, 1, 0);
        let result = generate_attester_and_proposer_maps(&sac, 0);
        assert_eq!(result, Err(AttesterAndProposerMapError::NoAvailableProposer));
    }

    #[test]
    fn test_attester_proposer_maps_scenario_a() {
        let sac = sac_generator(4, 4, 1, 1);
        let (a, p) = generate_attester_and_proposer_maps(&sac, 0).unwrap();

        assert_eq!(*p.get(&0).unwrap(), 0);
        assert_eq!(*p.get(&1).unwrap(), 1);
        assert_eq!(*p.get(&2).unwrap(), 2);
        assert_eq!(*p.get(&3).unwrap(), 3);

        assert_eq!(*a.get(&(0, 0)).unwrap(), vec![0]);
        assert_eq!(*a.get(&(1, 1)).unwrap(), vec![1]);
        assert_eq!(*a.get(&(2, 2)).unwrap(), vec![2]);
        assert_eq!(*a.get(&(3, 3)).unwrap(), vec![3]);
    }

    #[test]
    fn test_attester_proposer_maps_scenario_b() {
        let sac = sac_generator(4, 4, 1, 4);
        let (a, p) = generate_attester_and_proposer_maps(&sac, 0).unwrap();

        assert_eq!(*p.get(&0).unwrap(), 0);
        assert_eq!(*p.get(&1).unwrap(), 5);
        assert_eq!(*p.get(&2).unwrap(), 10);
        assert_eq!(*p.get(&3).unwrap(), 15);

        assert_eq!(*a.get(&(0, 0)).unwrap(), vec![0, 1, 2, 3]);
        assert_eq!(*a.get(&(1, 1)).unwrap(), vec![4, 5, 6, 7]);
        assert_eq!(*a.get(&(2, 2)).unwrap(), vec![8, 9, 10, 11]);
        assert_eq!(*a.get(&(3, 3)).unwrap(), vec![12, 13, 14, 15]);
    }
}
