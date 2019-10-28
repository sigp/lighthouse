use crate::enums::{NotSafe, Safe, ValidData};
use ssz_derive::{Decode, Encode};
use types::{BeaconBlockHeader, Hash256, Slot};

#[derive(PartialEq, Debug)]
pub enum InvalidBlock {
    BlockSlotTooEarly,
    DoubleBlockProposal,
}

#[derive(Debug, Clone, Encode, Decode)]
pub struct SignedBlock {
    pub slot: Slot,
    pub signing_root: Hash256,
}

impl SignedBlock {
    pub fn new(slot: Slot, signing_root: Hash256) -> Self {
        Self { slot, signing_root }
    }

    pub fn from(header: &BeaconBlockHeader) -> Self {
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
            reason: ValidData::EmptyHistory,
        });
    }
    let index = block_history
        .iter()
        .rev()
        .position(|historical_block| historical_block.slot >= block_header.slot);
    let index = match index {
        None => return Err(NotSafe::PruningError),
        Some(num) => block_history.len() - 1 - num,
    };
    if block_history[index].slot == block_header.slot {
        if block_history[index].signing_root == block_header.canonical_root() {
            Ok(Safe {
                insert_index: index + 1,
                reason: ValidData::SameVote,
            })
        } else {
            Err(NotSafe::InvalidBlock(InvalidBlock::DoubleBlockProposal))
        }
    } else {
        Err(NotSafe::InvalidBlock(InvalidBlock::BlockSlotTooEarly))
    }
}
