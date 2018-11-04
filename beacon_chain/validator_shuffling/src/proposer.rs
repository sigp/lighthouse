use types::ShardAndCommittee;

#[derive(Debug, PartialEq)]
pub enum BlockProposerError {
    NoShardAndCommitteeForSlot,
    NoAvailableProposer,
}

pub fn shard_and_committee_for_slot(
    canonical_slot_number: u64,
    shard_and_committee_for_slots: &Vec<Vec<ShardAndCommittee>>,
) -> Option<&Vec<ShardAndCommittee>> {
    shard_and_committee_for_slots
        .get(canonical_slot_number as usize % shard_and_committee_for_slots.len())
}

/// Return the block proposer given the "canonical slot number" and the set of `ShardAndCommittee`
/// objects for that slot.
///
/// The "canonical slot number" means the height of the slot since chain genesis, instead of the
/// index of the slot inside some specific cycle.
pub fn block_proposer_for_slot(
    shard_and_committee_for_slot: &Vec<ShardAndCommittee>,
    canonical_slot_number: u64,
) -> Result<usize, BlockProposerError> {
    /*
     * Store the proposer for the block.
     */
    let first_committee = &shard_and_committee_for_slot
        .get(0)
        .ok_or(BlockProposerError::NoShardAndCommitteeForSlot)?
        .committee;
    let proposer_index = (canonical_slot_number as usize)
        .checked_rem(first_committee.len())
        .ok_or(BlockProposerError::NoAvailableProposer)?;
    Ok(first_committee[proposer_index])
}

// TODO: write tests for this. It is effectively tested in `chain/src/maps.rs`, however it should
// definitely have its own tests. #goodfirstissue
