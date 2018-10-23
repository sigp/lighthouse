use types::{
    AttesterMap,
    CrystallizedState,
    ProposerMap,
};

#[derive(Debug, PartialEq)]
pub enum AttesterAndProposerMapError {
    NoShardAndCommitteeForSlot,
    NoAvailableProposer,
}

/// Generate a map of `(slot, shard) |--> committee`.
///
/// The attester map is used to optimise the lookup of a committee.
pub fn generate_attester_and_proposer_maps(cry_state: &CrystallizedState, start_slot: u64)
    -> Result<(AttesterMap, ProposerMap), AttesterAndProposerMapError>
{
    let mut attester_map = AttesterMap::new();
    let mut proposer_map = ProposerMap::new();
    for (i, slot) in cry_state.shard_and_committee_for_slots.iter().enumerate() {
        /*
         * Store the proposer for the block.
         */
        let slot_number = (i as u64).saturating_add(start_slot);
        let first_committee = {
            let first_shard_and_committee = slot.get(0)
                .ok_or(AttesterAndProposerMapError::NoShardAndCommitteeForSlot)?;
            first_shard_and_committee.committee.clone()
        };
        println!("{:?}", slot);
        let proposer_index = (slot_number as usize).checked_rem(first_committee.len())
            .ok_or(AttesterAndProposerMapError::NoAvailableProposer)?;
        proposer_map.insert(slot_number, proposer_index);

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
