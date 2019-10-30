use crate::enums::{NotSafe, Safe, ValidityReason};
use ssz_derive::{Decode, Encode};
use std::convert::From;
use types::{BeaconBlockHeader, Hash256, Slot};

#[derive(PartialEq, Debug)]
pub enum InvalidBlock {
    BlockSlotTooEarly,
    DoubleBlockProposal,
}

#[derive(Debug, Clone, Encode, Decode, PartialEq)]
pub struct SignedBlock {
    pub slot: Slot,
    pub signing_root: Hash256,
}

impl SignedBlock {
    pub fn new(slot: u64, signing_root: Hash256) -> Self {
        Self {
            slot: Slot::from(slot),
            signing_root,
        }
    }
}

impl From<&BeaconBlockHeader> for SignedBlock {
    fn from(header: &BeaconBlockHeader) -> Self {
        Self {
            slot: header.slot,
            signing_root: header.canonical_root(),
        }
    }
}

pub fn check_for_proposer_slashing(
    block_header: &BeaconBlockHeader,
    block_history: &[SignedBlock],
) -> Result<Safe, NotSafe> {
    if block_history.is_empty() {
        return Ok(Safe {
            insert_index: 0,
            reason: ValidityReason::EmptyHistory,
        });
    }

    let last_block = &block_history[block_history.len() - 1];
    if block_header.slot > last_block.slot {
        return Ok(Safe {
            insert_index: block_history.len(),
            reason: ValidityReason::Valid,
        });
    }
    let index = block_history
        .iter()
        .rev()
        .position(|historical_block| historical_block.slot <= block_header.slot);
    let index = match index {
        None => return Err(NotSafe::PruningError),
        Some(num) => block_history.len() - 1 - num,
    };
    if block_history[index].slot == block_header.slot {
        if block_history[index].signing_root == block_header.canonical_root() {
            Ok(Safe {
                insert_index: index,
                reason: ValidityReason::SameVote,
            })
        } else {
            Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal))
        }
    } else {
        Err(NotSafe::InvalidBlock(InvalidBlock::BlockSlotTooEarly))
    }
}

#[cfg(test)]
mod block_tests {
    use crate::enums::*; // SCOTT
    use crate::proposer_slashings::*; // SCOTT
    use types::{BeaconBlockHeader, Hash256, Signature, Slot};

    fn block_builder(slot: u64) -> BeaconBlockHeader {
        BeaconBlockHeader {
            slot: Slot::from(slot),
            parent_root: Hash256::random(),
            state_root: Hash256::random(),
            body_root: Hash256::random(),
            signature: Signature::empty_signature(),
        }
    }

    #[test]
    fn valid_empty_history() {
        let history = vec![];

        let new_block = block_builder(3);

        assert_eq!(
            check_for_proposer_slashing(&new_block, &history),
            Ok(Safe {
                insert_index: 0,
                reason: ValidityReason::EmptyHistory
            })
        );
    }

    #[test]
    fn valid_block() {
        let mut history = vec![];

        history.push(SignedBlock::new(1, Hash256::random()));
        history.push(SignedBlock::new(2, Hash256::random()));
        let new_block = block_builder(3);

        assert_eq!(
            check_for_proposer_slashing(&new_block, &history),
            Ok(Safe {
                insert_index: 2,
                reason: ValidityReason::Valid
            })
        );
    }

    #[test]
    fn valid_same_block() {
        let mut history = vec![];

        let new_block = block_builder(3);

        history.push(SignedBlock::new(1, Hash256::random()));
        history.push(SignedBlock::new(2, Hash256::random()));
        history.push(SignedBlock::new(3, new_block.canonical_root()));

        assert_eq!(
            check_for_proposer_slashing(&new_block, &history),
            Ok(Safe {
                insert_index: 2,
                reason: ValidityReason::SameVote
            })
        );
    }

    #[test]
    fn invalid_pruning_error() {
        let mut history = vec![];

        let new_block = block_builder(0);

        history.push(SignedBlock::new(2, Hash256::random()));
        history.push(SignedBlock::new(3, Hash256::random()));

        assert_eq!(
            check_for_proposer_slashing(&new_block, &history),
            Err(NotSafe::PruningError)
        );
    }

    #[test]
    fn invalid_double_block_proposal() {
        let mut history = vec![];

        history.push(SignedBlock::new(1, Hash256::random()));
        history.push(SignedBlock::new(2, Hash256::random()));
        history.push(SignedBlock::new(3, Hash256::random()));

        let new_block = block_builder(2);

        assert_eq!(
            check_for_proposer_slashing(&new_block, &history),
            Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal))
        );
    }
}