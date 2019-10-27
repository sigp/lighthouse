use ssz_derive::{Decode, Encode};
use types::{BeaconBlockHeader, Hash256, Slot};

#[derive(Debug, Clone, Encode, Decode)]
pub struct ValidatorHistoricalBlock {
    pub slot: Slot,
    pub signing_root: Hash256,
}

impl ValidatorHistoricalBlock {
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

pub fn should_sign_block(
    block_header: &BeaconBlockHeader,
    block_history: &[ValidatorHistoricalBlock],
) -> Result<usize, &'static str> {
    let index = block_history
        .iter()
        .rev()
        .position(|historical_block| historical_block.slot >= block_header.slot);
    let index = match index {
        None => return Err("no pos found"), // check for pruning error?
        Some(num) => block_history.len() - 1 - num,
    };
    if block_history[index].slot == block_header.slot {
        if block_history[index].signing_root == block_header.canonical_root() {
            Ok(index + 1)
        } else {
            Err("Double vote")
        }
    } else {
        Err("small than some historical block")
    }
}