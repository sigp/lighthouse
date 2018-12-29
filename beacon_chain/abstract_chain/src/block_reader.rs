use types::{BeaconBlock, Hash256};

pub trait BlockReader {
    fn slot(&self) -> u64;
    fn parent_root(&self) -> Hash256;
}

impl BlockReader for BeaconBlock {
    fn slot(&self) -> u64 {
        self.slot
    }

    fn parent_root(&self) -> Hash256 {
        self.parent_root
    }
}
