use types::{BeaconBlockHeader, Hash256, Slot};

#[derive(PartialEq, Debug)]
pub enum InvalidBlock {
    DoubleBlockProposal(SignedBlock),
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignedBlock {
    pub slot: Slot,
    pub signing_root: Hash256,
}

impl SignedBlock {
    pub fn new(slot: Slot, signing_root: Hash256) -> Self {
        Self { slot, signing_root }
    }

    pub fn from(header: &BeaconBlockHeader) -> Self {
        // FIXME(slashing): use real signing_root
        Self {
            slot: header.slot,
            signing_root: header.canonical_root(),
        }
    }
}
