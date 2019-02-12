use parking_lot::{RwLock, RwLockReadGuard};
use std::collections::HashSet;
use types::Hash256;

/// Maintains a view of the block DAG, also known as the "blockchain" (except, it tracks multiple
/// chains eminating from a single root instead of just the head of some canonical chain).
///
/// The BlockGraph does not store the blocks, instead it tracks the block hashes of blocks at the
/// tip of the DAG. It is out of the scope of the object to retrieve blocks.
///
/// Presently, the DAG root (genesis block) is not tracked.
///
/// The BlogGraph is thread-safe due to internal RwLocks.
#[derive(Default)]
pub struct BlockGraph {
    pub leaves: RwLock<HashSet<Hash256>>,
}

impl BlockGraph {
    /// Create a new block graph without any leaves.
    pub fn new() -> Self {
        Self {
            leaves: RwLock::new(HashSet::new()),
        }
    }
    /// Add a new leaf to the block hash graph. Returns `true` if the leaf was built upon another
    /// leaf.
    pub fn add_leaf(&self, parent: &Hash256, leaf: Hash256) -> bool {
        let mut leaves = self.leaves.write();

        if leaves.contains(parent) {
            leaves.remove(parent);
            leaves.insert(leaf);
            true
        } else {
            leaves.insert(leaf);
            false
        }
    }

    /// Returns a read-guarded HashSet of all leaf blocks.
    pub fn leaves(&self) -> RwLockReadGuard<HashSet<Hash256>> {
        self.leaves.read()
    }
}
