use crate::{BeaconChain, BeaconChainError, BeaconChainTypes};
use itertools::process_results;
use lru::LruCache;
use parking_lot::Mutex;
use slog::warn;
use types::Hash256;

const BLOCK_ROOT_CACHE_LIMIT: usize = 512;
const LOOKUP_LIMIT: usize = 8;

#[derive(Default)]
pub struct PreFinalizationBlockCache {
    cache: Mutex<Cache>,
}

struct Cache {
    /// Set of block roots that are known to be pre-finalization.
    block_roots: LruCache<Hash256, ()>,
    /// Set of block roots that are the subject of single block lookups.
    in_progress_lookups: LruCache<Hash256, ()>,
}

impl Default for Cache {
    fn default() -> Self {
        Cache {
            block_roots: LruCache::new(BLOCK_ROOT_CACHE_LIMIT),
            in_progress_lookups: LruCache::new(LOOKUP_LIMIT),
        }
    }
}

impl<T: BeaconChainTypes> BeaconChain<T> {
    pub fn is_pre_finalization_block(&self, block_root: Hash256) -> Result<bool, BeaconChainError> {
        let mut cache = self.pre_finalization_block_cache.cache.lock();

        // Check the cache to see if we already know this pre-finalization block root.
        if cache.block_roots.contains(&block_root) {
            return Ok(true);
        }

        // Avoid repeating the disk lookup for blocks that are already subject to a network lookup.
        if cache.in_progress_lookups.contains(&block_root) {
            return Ok(false);
        }

        // 1. Check memory for a recent pre-finalization block.
        let is_recent_finalized_block = self.with_head(|head| {
            process_results(
                head.beacon_state.rev_iter_block_roots(&self.spec),
                |mut iter| iter.any(|(_, root)| root == block_root),
            )
            .map_err(BeaconChainError::BeaconStateError)
        })?;
        if is_recent_finalized_block {
            cache.block_roots.put(block_root, ());
            return Ok(true);
        }

        // 2. Check on disk.
        if self.store.get_block(&block_root)?.is_some() {
            cache.block_roots.put(block_root, ());
            return Ok(true);
        }

        // 3. Check the network with a single block lookup.
        if cache.in_progress_lookups.len() == LOOKUP_LIMIT {
            warn!(
                self.log,
                "Pre-finalization lookup cache is full";
            );
        }
        cache.in_progress_lookups.put(block_root, ());
        Ok(false)
    }

    pub fn pre_finalization_block_rejected(&self, block_root: Hash256) {
        // Future requests can know that this block is invalid without having to look it up again.
        let mut cache = self.pre_finalization_block_cache.cache.lock();
        cache.in_progress_lookups.pop(&block_root);
        cache.block_roots.put(block_root, ());
    }
}

impl PreFinalizationBlockCache {
    pub fn block_processed(&self, block_root: Hash256) {
        // Future requests will find this block in fork choice, so no need to cache it in the
        // ongoing lookup cache any longer.
        self.cache.lock().in_progress_lookups.pop(&block_root);
    }
}
