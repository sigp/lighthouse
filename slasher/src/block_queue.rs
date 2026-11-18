use parking_lot::Mutex;
use std::collections::HashSet;
use types::SignedBeaconBlockHeaderBase;

#[derive(Debug, Default)]
pub struct BlockQueue {
    blocks: Mutex<HashSet<SignedBeaconBlockHeaderBase>>,
}

impl BlockQueue {
    pub fn queue(&self, block_header: SignedBeaconBlockHeaderBase) {
        self.blocks.lock().insert(block_header);
    }

    pub fn dequeue(&self) -> HashSet<SignedBeaconBlockHeaderBase> {
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
