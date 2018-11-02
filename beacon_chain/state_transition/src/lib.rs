extern crate types;

use types::{ActiveState, BeaconBlock, Hash256};

#[derive(Debug, PartialEq)]
pub enum StateTransitionError {
    BlockSlotBeforeRecalcSlot,
    InvalidParentHashes,
    DBError(String),
}

pub fn extend_active_state(
    act_state: &ActiveState,
    block: &BeaconBlock,
    block_hash: &Hash256,
) -> Result<ActiveState, StateTransitionError> {
    /*
     * Extend the pending attestations in the active state with the new attestations included
     * in the block.
     *
     * Using the concat method to avoid reallocations.
     */
    let pending_attestations =
        [&act_state.pending_attestations[..], &block.attestations[..]].concat();

    /*
     * Extend the pending specials in the active state with the new specials included in the
     * block.
     *
     * Using the concat method to avoid reallocations.
     */
    let pending_specials = [&act_state.pending_specials[..], &block.specials[..]].concat();

    /*
     * Update the active state recent_block_hashes:
     *
     * - Drop the hash from the earliest position.
     * - Push the block_hash into the latest position.
     *
     * Using the concat method to avoid reallocations.
     */
    let (_first_hash, last_hashes) = act_state
        .recent_block_hashes
        .split_first()
        .ok_or(StateTransitionError::InvalidParentHashes)?;
    let new_hash = &[block_hash.clone()];
    let recent_block_hashes = [&last_hashes, &new_hash[..]].concat();

    /*
     * The new `randao_mix` is set to the XOR of the previous active state randao mix and the
     * randao reveal in this block.
     */
    let randao_mix = act_state.randao_mix ^ block.randao_reveal;

    Ok(ActiveState {
        pending_attestations,
        pending_specials,
        recent_block_hashes,
        randao_mix,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use types::SpecialRecord;

    fn empty_active_state() -> ActiveState {
        ActiveState {
            pending_attestations: vec![],
            pending_specials: vec![],
            recent_block_hashes: vec![],
            randao_mix: Hash256::zero(),
        }
    }

    #[test]
    fn test_extend_active_state_minimal() {
        let mut act_state = empty_active_state();

        let parent_hash = Hash256::from("parent_hash".as_bytes());
        act_state.recent_block_hashes = vec![parent_hash];

        let block = BeaconBlock::zero();
        let block_hash = Hash256::from("block_hash".as_bytes());

        let new_act_state = extend_active_state(&act_state, &block, &block_hash).unwrap();

        assert_eq!(new_act_state.pending_attestations, vec![]);
        assert_eq!(new_act_state.pending_specials, vec![]);
        assert_eq!(new_act_state.recent_block_hashes, vec![block_hash]);
        assert_eq!(new_act_state.randao_mix, Hash256::zero());
    }

    #[test]
    fn test_extend_active_state_specials() {
        let mut act_state = empty_active_state();

        let parent_hash = Hash256::from("parent_hash".as_bytes());
        act_state.recent_block_hashes = vec![parent_hash];

        let mut block = BeaconBlock::zero();
        let special = SpecialRecord {
            kind: 0,
            data: vec![42, 42],
        };

        block.specials.push(special.clone());

        let block_hash = Hash256::from("block_hash".as_bytes());

        let new_act_state = extend_active_state(&act_state, &block, &block_hash).unwrap();

        assert_eq!(new_act_state.pending_attestations, vec![]);
        assert_eq!(new_act_state.pending_specials, vec![special.clone()]);
        assert_eq!(new_act_state.recent_block_hashes, vec![block_hash]);
        assert_eq!(new_act_state.randao_mix, Hash256::zero());

        let new_new_act_state = extend_active_state(&new_act_state, &block, &block_hash).unwrap();

        assert_eq!(new_new_act_state.pending_attestations, vec![]);
        assert_eq!(
            new_new_act_state.pending_specials,
            vec![special.clone(), special.clone()]
        );
        assert_eq!(new_new_act_state.recent_block_hashes, vec![block_hash]);
        assert_eq!(new_new_act_state.randao_mix, Hash256::zero());
    }

    #[test]
    fn test_extend_active_state_empty_recent_block_hashes() {
        let act_state = empty_active_state();

        let block = BeaconBlock::zero();

        let block_hash = Hash256::from("block_hash".as_bytes());

        let result = extend_active_state(&act_state, &block, &block_hash);

        assert_eq!(result, Err(StateTransitionError::InvalidParentHashes));
    }

    #[test]
    fn test_extend_active_recent_block_hashes() {
        let mut act_state = empty_active_state();

        let parent_hashes = vec![
            Hash256::from("one".as_bytes()),
            Hash256::from("two".as_bytes()),
            Hash256::from("three".as_bytes()),
        ];
        act_state.recent_block_hashes = parent_hashes.clone();

        let block = BeaconBlock::zero();

        let block_hash = Hash256::from("four".as_bytes());

        let new_act_state = extend_active_state(&act_state, &block, &block_hash).unwrap();

        assert_eq!(new_act_state.pending_attestations, vec![]);
        assert_eq!(new_act_state.pending_specials, vec![]);
        assert_eq!(
            new_act_state.recent_block_hashes,
            vec![
                Hash256::from("two".as_bytes()),
                Hash256::from("three".as_bytes()),
                Hash256::from("four".as_bytes()),
            ]
        );
        assert_eq!(new_act_state.randao_mix, Hash256::zero());
    }

    #[test]
    fn test_extend_active_state_randao() {
        let mut act_state = empty_active_state();

        let parent_hash = Hash256::from("parent_hash".as_bytes());
        act_state.recent_block_hashes = vec![parent_hash];

        act_state.randao_mix = Hash256::from(0b00000000);

        let mut block = BeaconBlock::zero();
        block.randao_reveal = Hash256::from(0b00000001);

        let block_hash = Hash256::from("block_hash".as_bytes());

        let new_act_state = extend_active_state(&act_state, &block, &block_hash).unwrap();

        assert_eq!(new_act_state.pending_attestations, vec![]);
        assert_eq!(new_act_state.pending_specials, vec![]);
        assert_eq!(new_act_state.recent_block_hashes, vec![block_hash]);
        assert_eq!(new_act_state.randao_mix, Hash256::from(0b00000001));
    }
}
