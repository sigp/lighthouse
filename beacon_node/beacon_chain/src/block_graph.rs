use crate::{BeaconChain, CheckPoint, ClientDB, SlotClock};
use std::collections::HashSet;
use std::sync::{RwLock, RwLockReadGuard};
use types::{BeaconBlock, BeaconState, Hash256};

pub struct BlockGraph {
    pub leaves: RwLock<HashSet<Hash256>>,
}

impl BlockGraph {
    pub fn new() -> Self {
        Self {
            leaves: RwLock::new(HashSet::new()),
        }
    }
    /// Add a new leaf to the block hash graph. Returns `true` if the leaf was built upon another
    /// leaf.
    pub fn add_leaf(&self, parent: &Hash256, leaf: Hash256) -> bool {
        let mut leaves = self
            .leaves
            .write()
            .expect("CRITICAL: BlockGraph poisioned.");

        if leaves.contains(parent) {
            leaves.remove(parent);
            leaves.insert(leaf);
            true
        } else {
            leaves.insert(leaf);
            false
        }
    }

    pub fn leaves(&self) -> RwLockReadGuard<HashSet<Hash256>> {
        self.leaves.read().expect("CRITICAL: BlockGraph poisioned.")
    }
}
