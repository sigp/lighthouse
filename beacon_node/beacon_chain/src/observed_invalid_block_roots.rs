//! A bounded cache of block roots observed to be consensus-invalid.
//!
//! When a block fails consensus validation during import (e.g. `per_block_processing` failure,
//! state root mismatch), fork choice retains no trace of it, making a later sighting of the same
//! root indistinguishable from a block we have never seen. The gossip specification distinguishes
//! these cases: messages referencing an *unseen* block are IGNOREd, while messages referencing a
//! block that was seen and *failed validation* are REJECTed ("... passes validation" conditions),
//! penalizing peers that propagate descendants of known-invalid blocks.
//!
//! Only failures attributable to the block's canonical root may be recorded here. The canonical
//! root commits to the block *message* but not its signature, so a proposer-signature failure must
//! never mark the root: an attacker could take an honest block, corrupt the signature bytes, and
//! poison the honest root. See [`crate::block_verification::BlockError::invalidates_block_root`].
//!
//! Payload-invalid blocks are deliberately excluded; they are tracked via fork choice's execution
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
