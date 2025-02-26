use parking_lot::Mutex;
use std::collections::HashSet;
use types::SignedBeaconBlockHeader;

#[derive(Debug, Default)]
pub struct BlockQueue {
    blocks: Mutex<HashSet<SignedBeaconBlockHeader>>,
}

impl BlockQueue {
    pub fn queue(&self, block_header: SignedBeaconBlockHeader) {
        self.blocks.lock().insert(block_header);
    }

    pub fn dequeue(&self) -> HashSet<SignedBeaconBlockHeader> {
        let mut blocks = self.blocks.lock();
        std::mem::take(&mut *blocks)
    }

    pub fn len(&self) -> usize {
        self.blocks.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
