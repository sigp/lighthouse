use crate::types::HeaderSentSet;
use hashlink::lru_cache::LruCache;
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::Arc;
use types::core::Hash256;

const MAX_BLOCKS: usize = 4;

pub struct PartialColumnHeaderTracker {
    blocks: LruCache<Hash256, HeaderSentSet>,
}

impl PartialColumnHeaderTracker {
    pub fn new() -> Self {
        PartialColumnHeaderTracker {
            blocks: LruCache::new(MAX_BLOCKS),
        }
    }

    pub fn get_for_block(&mut self, hash: Hash256) -> HeaderSentSet {
        Arc::clone(
            self.blocks
                .entry(hash)
                .or_insert_with(|| Arc::new(Mutex::new(HashSet::new()))),
        )
    }
}
