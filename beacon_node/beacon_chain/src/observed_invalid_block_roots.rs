//! Cache of block roots observed to fail consensus validation.
//!
//! When a block fails consensus validation during import, we store it in this cache. 
//! This allows us to quickly reject messages that build on top of invalid blocks.
//!
//! Only failures attributable to the block root may be recorded here. The block root
//! root to the block *message* but not its signature, so a proposer-signature failure must
//! never mark the root as invalid. See [`crate::block_verification::BlockError::invalidates_block_root`].
//!
//! Pre-gloas payload-invalid blocks are deliberately excluded; they are tracked via fork choice's execution
//! status and have separate gossip conditions (e.g. `ParentExecutionPayloadInvalid`).

use hashlink::lru_cache::LruCache;
use parking_lot::Mutex;
use types::Hash256;

/// Bounds memory at ~32 KiB while comfortably outlasting the gossip propagation window of any
/// invalid block and its descendants.
const CACHE_SIZE: usize = 1024;

pub struct ObservedInvalidBlockRoots {
    roots: Mutex<LruCache<Hash256, ()>>,
}

impl Default for ObservedInvalidBlockRoots {
    fn default() -> Self {
        Self {
            roots: Mutex::new(LruCache::new(CACHE_SIZE)),
        }
    }
}

impl ObservedInvalidBlockRoots {
    pub fn insert(&self, block_root: Hash256) {
        self.roots.lock().insert(block_root, ());
    }

    pub fn contains(&self, block_root: &Hash256) -> bool {
        self.roots.lock().contains_key(block_root)
    }
}
