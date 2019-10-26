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
